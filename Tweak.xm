// bs_unlock 注入层：卡槽写回 / 授权投放 / 心跳判定
// conf: /var/mobile/Media/bs_pull.conf   log: /var/mobile/Media/bs_bridge.log

#import <Foundation/Foundation.h>
#import <stdarg.h>
#import <stdint.h>
#import <time.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>
#import <sys/stat.h>
#import <dlfcn.h>

#define BS_PAGE 0x4000      // iOS arm64 页大小 16KB，不依赖 PAGE_SIZE 宏

#define CONF_PATH   "/var/mobile/Media/bs_pull.conf"
#define DATA_DIR    "/var/mobile/Media/BetaScreenTYMDESUJCX8T"
#define CARD_PATH   DATA_DIR "/bs_card.txt"
#define LOG_PATH    "/var/mobile/Media/bs_bridge.log"

// ---------------- 配置 ----------------
typedef struct {
    char  host[64];
    int   port;
    int   tick;
    char  prj[16];
    char  devid[80];
    char  card[64];
    long  vt_off;      // 0 = 不打
    long  st_off;      // 0 = 不打
} BSCfg;

static BSCfg g_cfg;
static int   g_autorized = 0;
static long long g_expire = 0;
static char  g_bindcard[64];

// ---------------- 小工具 ----------------
static void BSLog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt]
                                            arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%ld] %@\n",
                      (long)time(NULL), msg];
    FILE *f = fopen(LOG_PATH, "a");
    if (f) { fwrite([line UTF8String], 1, [line length], f); fclose(f); }
}

static void BSConfLoad(void) {
    g_cfg.port = 38471;
    g_cfg.tick = 60;
    strcpy(g_cfg.prj, "sjz");
    strcpy(g_cfg.host, "127.0.0.1");

    FILE *f = fopen(CONF_PATH, "r");
    if (!f) { BSLog("conf missing, defaults"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
        if      (!strcmp(k, "host"))    strncpy(g_cfg.host, v, sizeof(g_cfg.host)-1);
        else if (!strcmp(k, "port"))    g_cfg.port = atoi(v);
        else if (!strcmp(k, "tick"))    g_cfg.tick = atoi(v);
        else if (!strcmp(k, "prj"))     strncpy(g_cfg.prj, v, sizeof(g_cfg.prj)-1);
        else if (!strcmp(k, "devid"))   strncpy(g_cfg.devid, v, sizeof(g_cfg.devid)-1);
        else if (!strcmp(k, "cardval") || !strcmp(k, "cardkey"))
                                        strncpy(g_cfg.card, v, sizeof(g_cfg.card)-1);
        else if (!strcmp(k, "vt_off"))  g_cfg.vt_off = strtol(v, NULL, 16);
        else if (!strcmp(k, "st_off"))  g_cfg.st_off = strtol(v, NULL, 16);
    }
    fclose(f);
    BSLog("conf host=%s port=%d tick=%d prj=%s card=%.12s devid=%.12s",
          g_cfg.host, g_cfg.port, g_cfg.tick, g_cfg.prj, g_cfg.card, g_cfg.devid);
}

// 设备号：优先 conf，其次读 Agent 的卡槽（若里面有 device id 字段）
static const char *BSDevId(void) {
    if (g_cfg.devid[0]) return g_cfg.devid;
    static char buf[80];
    NSString *s = [NSString stringWithContentsOfFile:@CARD_PATH encoding:NSUTF8StringEncoding error:nil];
    for (NSString *ln in [s componentsSeparatedByString:@"\n"]) {
        if ([ln hasPrefix:@"devid="]) { strncpy(buf, [[ln substringFromIndex:6] UTF8String], 79); return buf; }
    }
    return "";
}

// ---------------- 卡槽写回 ----------------
static void BSCardWrite(const char *card, long long expire) {
    NSString *body = [NSString stringWithFormat:
        @"expire=%lld\nlastok=%lld\ncard=%s\nkicked=\nkickts=0\n",
        expire, (long long)time(NULL), card];
    [body writeToFile:@CARD_PATH atomically:YES encoding:NSUTF8StringEncoding error:nil];
    chmod(CARD_PATH, 0644);
}

// ---------------- 授权注入 ----------------
static void BSApplyAuth(int st, long long vt, const char *card) {
    void *p;

    // g_agent_auth_state : int32_t
    p = dlsym(RTLD_DEFAULT, "g_agent_auth_state");
    if (p) *(volatile int32_t *)p = st;

    // g_agent_auth_valid_time : int64_t
    p = dlsym(RTLD_DEFAULT, "g_agent_auth_valid_time");
    if (p) *(volatile int64_t *)p = vt;

    // g_agent_activate_card : char *
    if (card && card[0]) {
        p = dlsym(RTLD_DEFAULT, "g_agent_activate_card");
        if (p) {
            char *dup = strdup(card);
            *(volatile char **)p = dup;
        }
    }
    g_autorized = st;
    g_expire = vt;
    BSLog("apply auth st=%d vt=%lld card=%.12s (sym %s)",
          st, vt, card ? card : "", p ? "ok" : "missing");
}

// ---------------- 兜底：按偏移打 ret ----------------
static int BSPatchRet(long off) {
    if (off <= 0) return -1;
    uintptr_t base = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    uintptr_t addr = base + (uintptr_t)off;
    vm_address_t page = addr & ~(vm_address_t)(BS_PAGE - 1);
    if (vm_protect(mach_task_self(), page, BS_PAGE, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return -2;
    *(volatile uint32_t *)addr = 0xd65f03c0;   // ret
    vm_protect(mach_task_self(), page, BS_PAGE, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, 4);
    BSLog("patch ret @ +0x%lx", off);
    return 0;
}

// ---------------- HTTP ----------------
static NSData *BSHttpGet(NSString *url, NSTimeInterval timeout) {
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    c.timeoutIntervalForRequest = timeout;
    c.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:c];
    [[s dataTaskWithURL:[NSURL URLWithString:url]
       completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (!e) out = d;
            dispatch_semaphore_signal(sem);
       }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW,
                          (int64_t)((timeout + 2) * NSEC_PER_SEC)));
    [s finishTasksAndInvalidate];
    return out;
}

// ---------------- 心跳一轮 ----------------
static void BSHbOnce(void) {
    const char *dev = BSDevId();
    if (!dev || !dev[0]) { BSLog("no devid, skip hb"); return; }

    NSString *url = [NSString stringWithFormat:
        @"http://%s:%d/hb?key=%s&cc=%s&prj=%s&nm=A222&of=ok&ofn=0",
        g_cfg.host, g_cfg.port, dev, g_cfg.card, g_cfg.prj];

    NSData *d = BSHttpGet(url, 8.0);
    if (!d) { BSLog("hb network miss"); return; }

    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:[NSDictionary class]]) { BSLog("hb bad json"); return; }

    NSInteger code = [j[@"code"] integerValue];
    long long exp  = [[j objectForKey:@"expire"] longLongValue];
    NSString *bind = [j objectForKey:@"bindcard"];
    if ([bind isKindOfClass:[NSString class]] && bind.length > 4) {
        strncpy(g_bindcard, [bind UTF8String], sizeof(g_bindcard) - 1);
    }
    const char *card = g_bindcard[0] ? g_bindcard : g_cfg.card;

    BSLog("hb code=%ld expire=%lld bind=%.14s", (long)code, exp, card);

    if (code == 0 && exp > 0) {
        BSCardWrite(card, exp);
        BSApplyAuth(1, exp, card);
        // 首次成功后按偏移补一次（若配置了）
        static int patched = 0;
        if (!patched) {
            BSPatchRet(g_cfg.vt_off);
            BSPatchRet(g_cfg.st_off);
            patched = 1;
        }
    } else if (code == 3) {
        // 过期：时间保留给中控显示，但授权关闭
        if (exp > 0) BSCardWrite(card, exp);
        BSApplyAuth(0, exp > 0 ? exp : g_expire, card);
        BSLog("expired -> display only");
    } else {
        BSApplyAuth(0, g_expire, card);
        BSLog("rejected code=%ld", (long)code);
    }
}

// ---------------- 入口 ----------------
__attribute__((constructor))
static void BSInit(void) {
    @autoreleasepool {
        BSConfLoad();

        NSString *pn = [[NSProcessInfo processInfo] processName];
        BOOL isAgent = [pn containsString:@"Agent"];
        BSLog("loaded into %s (tick=%d)", [pn UTF8String], g_cfg.tick);

        // 先按当前卡槽里的值给一次授权，避免启动瞬间显示未授权
        NSString *cache = [NSString stringWithContentsOfFile:@CARD_PATH
                                                    encoding:NSUTF8StringEncoding error:nil];
        long long exp0 = 0; char card0[64] = {0};
        for (NSString *ln in [cache componentsSeparatedByString:@"\n"]) {
            if ([ln hasPrefix:@"expire="]) exp0 = atoll([[ln substringFromIndex:7] UTF8String]);
            if ([ln hasPrefix:@"card="])   strncpy(card0, [[ln substringFromIndex:5] UTF8String], 63);
        }
        if (exp0 > 0) BSApplyAuth((int)(exp0 > time(NULL)), exp0, card0[0] ? card0 : g_cfg.card);

        if (!isAgent) return;   // 监控端只注入显示，不发请求

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            while (1) {
                @autoreleasepool { BSHbOnce(); }
                int t = g_cfg.tick > 5 ? g_cfg.tick : 60;
                sleep(t);
            }
        });
    }
}
