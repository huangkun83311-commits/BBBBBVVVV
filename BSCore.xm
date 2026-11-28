// BSCore.xm —— 卡密登录 / token 自愈 / killswitch / watchdog（补齐 2.45 缺失的守护层）
// 与 Tweak.xm 的心跳分工：Tweak 负责 /hb 保活，本文件负责登录、踢卡、守护、自愈

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/stat.h>
#import <unistd.h>
#import <time.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>

#define CO_CONF "/var/mobile/Media/bs_pull.conf"
#define CO_CARD "/var/mobile/Media/BetaScreenTYMDESUJCX8T/bs_card.txt"
#define CO_FLAG "/var/mobile/Media/bs_reload.flag"

static char c_host[64];
static char c_cardhost[80];
static char c_token[96];
static char c_prj[20];
static char c_card[64];
static char c_devid[80];
static int  c_port = 38471;
static int  c_cardtick = 60;
static int  c_cardgrace = 1;
static int  c_hbmiss = 3;
static int  c_enable = 1;

static char c_logpath[256];

static void CLog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt] arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%ld] [core] %@\n", (long)time(NULL), body];

    NSLog(@"[bsc] %@", body);
    if (!c_logpath[0]) {
        NSString *home = NSHomeDirectory();
        const char *c[] = {
            [[home stringByAppendingPathComponent:@"Documents/bs_bridge.log"] UTF8String],
            [[home stringByAppendingPathComponent:@"tmp/bs_bridge.log"] UTF8String],
            [[NSTemporaryDirectory() stringByAppendingPathComponent:@"bs_bridge.log"] UTF8String],
            "/var/mobile/Media/BetaScreenTYMDESUJCX8T/log/bs_bridge.log",
            "/var/mobile/Media/bs_bridge.log", "/var/tmp/bs_bridge.log", NULL };
        for (int i = 0; c[i]; i++) { FILE *t = fopen(c[i], "a"); if (t) { fclose(t); strncpy(c_logpath, c[i], sizeof(c_logpath)-1); break; } }
    }
    if (!c_logpath[0]) return;
    FILE *f = fopen(c_logpath, "a");
    if (f) { fwrite([line UTF8String], 1, [line length], f); fclose(f); }
}

static void CConf(void) {
    strcpy(c_host, "106.52.43.129");
    strcpy(c_prj, "sjz");

    FILE *f = fopen(CO_CONF, "r");
    if (!f) { CLog("conf missing"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
        if      (!strcmp(k, "host"))      strncpy(c_host, v, sizeof(c_host)-1);
        else if (!strcmp(k, "port"))      c_port = atoi(v);
        else if (!strcmp(k, "cardhost"))  strncpy(c_cardhost, v, sizeof(c_cardhost)-1);
        else if (!strcmp(k, "token"))     strncpy(c_token, v, sizeof(c_token)-1);
        else if (!strcmp(k, "prj"))       strncpy(c_prj, v, sizeof(c_prj)-1);
        else if (!strcmp(k, "card") || !strcmp(k, "cardkey") || !strcmp(k, "cardval"))
                                          strncpy(c_card, v, sizeof(c_card)-1);
        else if (!strcmp(k, "devid"))     strncpy(c_devid, v, sizeof(c_devid)-1);
        else if (!strcmp(k, "cardtick"))  c_cardtick = atoi(v);
        else if (!strcmp(k, "cardgrace")) c_cardgrace = atoi(v);
        else if (!strcmp(k, "hbmiss"))    c_hbmiss = atoi(v);
        else if (!strcmp(k, "enable"))    c_enable = atoi(v);
    }
    fclose(f);
}

static NSString *CMd5(NSString *s) {
    const char *c = [s UTF8String];
    unsigned char d[16];
    CC_MD5(c, (CC_LONG)strlen(c), d);
    NSMutableString *o = [NSMutableString string];
    for (int i = 0; i < 16; i++) [o appendFormat:@"%02x", d[i]];
    return o;
}

// token 自愈：conf 里没 token 时，用 devid 派生，避免空 token 被服务端拒
static void CTokenSelfHeal(void) {
    if (c_token[0]) return;
    NSString *dev = c_devid[0] ? [NSString stringWithUTF8String:c_devid] : @"";
    if (dev.length == 0) {
        // devid 也没有 -> 从卡槽读
        NSString *body = [NSString stringWithContentsOfFile:@CO_CARD encoding:NSUTF8StringEncoding error:nil];
        for (NSString *ln in [body componentsSeparatedByString:@"\n"])
            if ([ln hasPrefix:@"devid="]) dev = [ln substringFromIndex:6];
    }
    if (dev.length == 0) { CLog("token selfheal skipped (no devid)"); return; }
    NSString *tok = CMd5(dev);
    strncpy(c_token, [tok UTF8String], sizeof(c_token)-1);
    CLog("token selfheal = %.8s (src=devid)", c_token);
}

static NSData *CGet(NSString *url, NSTimeInterval to) {
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionConfiguration *cf = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cf.timeoutIntervalForRequest = to;
    cf.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cf];
    [[s dataTaskWithURL:[NSURL URLWithString:url] completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (!e) out = d;
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((to + 2) * NSEC_PER_SEC)));
    [s finishTasksAndInvalidate];
    return out;
}

// ---------------- 授权写 ---------------- 
static void CApply(int st, long long vt) {
    void *p = dlsym(RTLD_DEFAULT, "g_agent_auth_state");
    if (p) *(volatile int32_t *)p = st;
    p = dlsym(RTLD_DEFAULT, "g_agent_auth_valid_time");
    if (p) *(volatile int64_t *)p = vt;
    CLog("apply st=%d vt=%lld sym_state=%d", st, vt, p ? 1 : 0);
}

// ---------------- killswitch：卡槽 kicked=1 立刻清授权 ----------------
static int CKillSwitch(void) {
    NSString *body = [NSString stringWithContentsOfFile:@CO_CARD encoding:NSUTF8StringEncoding error:nil];
    if (!body) return 0;
    int kicked = 0;
    for (NSString *ln in [body componentsSeparatedByString:@"\n"])
        if ([ln hasPrefix:@"kicked="]) kicked = atoi([[ln substringFromIndex:7] UTF8String]);
    if (kicked) {
        CApply(0, 0);
        CLog("killswitch armed (kicked=1) -> auth cleared");
        return 1;
    }
    return 0;
}

// ---------------- 卡密登录：/key ----------------
static long long CCardLogin(void) {
    if (!c_card[0] || !c_token[0]) return 0;
    NSString *hostport = c_cardhost[0] ? [NSString stringWithUTF8String:c_cardhost]
                                       : [NSString stringWithFormat:@"%s:%d", c_host, c_port];
    NSString *dev = c_devid[0] ? [NSString stringWithUTF8String:c_devid] : @"";
    NSString *u = [NSString stringWithFormat:@"http://%@/key?devid=%@&card=%s&prj=%s&token=%s",
                   hostport, dev, c_card, c_prj, c_token];
    NSData *d = CGet(u, 8.0);
    if (!d) { CLog("login network miss"); return 0; }
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:[NSDictionary class]]) { CLog("login bad json"); return 0; }

    NSInteger code = [j[@"code"] integerValue];
    long long exp = [[j objectForKey:@"expire"] longLongValue];
    NSString *bind = [j objectForKey:@"bindcard"];
    CLog("login code=%ld expire=%lld bind=%.14s", (long)code, exp, bind ? [bind UTF8String] : "-");

    if (code == 0 && exp > 0) {
        NSString *cardOut = (bind.length > 4) ? bind : [NSString stringWithUTF8String:c_card];
        NSString *slot = [NSString stringWithFormat:@"expire=%lld\nlastok=%lld\ncard=%@\nkicked=\nkickts=0\n",
                          exp, (long long)time(NULL), cardOut];
        [slot writeToFile:@CO_CARD atomically:YES encoding:NSUTF8StringEncoding error:nil];
        chmod(CO_CARD, 0644);
        CApply(1, exp);
        return exp;
    }
    return 0;
}

// ---------------- watchdog：心跳陈旧 -> 记录 + 重载标记 ----------------
static void CWatchdog(int *misses) {
    CConf();
    if (CKillSwitch()) { *misses = 0; return; }

    // 以卡槽 lastok 为心跳证据
    long long lastok = 0;
    NSString *body = [NSString stringWithContentsOfFile:@CO_CARD encoding:NSUTF8StringEncoding error:nil];
    for (NSString *ln in [body componentsSeparatedByString:@"\n"])
        if ([ln hasPrefix:@"lastok="]) lastok = atoll([[ln substringFromIndex:7] UTF8String]);

    long long age = (long long)time(NULL) - lastok;
    if (lastok > 0 && age > (long long)c_cardtick * 3) {
        (*misses)++;
        CLog("watchdog stale age=%llds miss=%d/%d", age, *misses, c_hbmiss);
        if (*misses >= c_hbmiss) {
            NSString *flag = [NSString stringWithFormat:@"wd %ld\n", (long)time(NULL)];
            [flag writeToFile:@CO_FLAG atomically:YES encoding:NSUTF8StringEncoding error:nil];
            CLog("watchdog -> reload flag (grace=%d)", c_cardgrace);
            *misses = 0;
        }
    } else {
        *misses = 0;
    }
}

static void CCoreThread(void) {
    static int misses = 0;
    int first = 1;
    while (1) {
        @autoreleasepool {
            CConf();
            if (!c_enable) { sleep(30); continue; }
            if (first) {
                CTokenSelfHeal();
                long long e = CCardLogin();
                if (e > 0) CLog("login ok expire=%lld", e);
                first = 0;
            }
            CWatchdog(&misses);
        }
        sleep(c_cardtick > 10 ? c_cardtick : 60);
    }
}

__attribute__((constructor))
static void BSCoreInit(void) {
    @autoreleasepool {
        NSString *pn = [[NSProcessInfo processInfo] processName];
        BOOL isAgent = [pn containsString:@"Agent"];
        CConf();
        CLog("init pn=%s isAgent=%d card=%.10s token=%.8s", [pn UTF8String], isAgent,
             c_card[0] ? c_card : "-", c_token[0] ? c_token : "-");
        if (!isAgent) return;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool { CCoreThread(); }
        });
    }
}
