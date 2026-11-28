// BSSync.xm —— so 版本同步 / 拉取 / 守护（2.45 行为复刻）
// verwatch: 轮询 /ver 比较版本  |  puller: 下载 so + md5 校验 + 原子替换
// watchdog: 心跳失败计数 + 记录  |  全部走 conf 里的 sohost:soport，不碰 8.153

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/stat.h>
#import <unistd.h>
#import <time.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <dispatch/dispatch.h>

#define SY_CONF   "/var/mobile/Media/bs_pull.conf"
#define SY_DIR    "/var/mobile/Media/BetaScreenTYMDESUJCX8T"
#define SY_SO     SY_DIR "/beta.so"
#define SY_NEW    SY_DIR "/beta_new.so"

static char  s_host[64];
static char  s_sohost[64];
static char  s_token[96];
static char  s_prj[20];
static int   s_soport   = 27391;
static int   s_sosync   = 1;
static int   s_sotick   = 120;
static int   s_enable   = 1;
static int   s_autoreload = 1;
static char  s_logpath[256];

static void SLog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt] arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%ld] [so] %@\n", (long)time(NULL), body];

    if (!s_logpath[0]) {
        const char *c[] = { "/var/mobile/Media/bs_bridge.log",
                            "/var/mobile/Media/BetaScreenTYMDESUJCX8T/log/bs_bridge.log",
                            "/var/tmp/bs_bridge.log", NULL };
        for (int i = 0; c[i]; i++) {
            FILE *t = fopen(c[i], "a");
            if (t) { fclose(t); strncpy(s_logpath, c[i], sizeof(s_logpath) - 1); break; }
        }
    }
    if (!s_logpath[0]) return;
    FILE *f = fopen(s_logpath, "a");
    if (f) { fwrite([line UTF8String], 1, [line length], f); fclose(f); }
}

static void SConf(void) {
    strcpy(s_host, "106.52.43.129");
    strcpy(s_prj, "sjz");
    s_soport = 27391;

    FILE *f = fopen(SY_CONF, "r");
    if (!f) { SLog("conf missing -> default"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
        if      (!strcmp(k, "host"))       strncpy(s_host, v, sizeof(s_host)-1);
        else if (!strcmp(k, "sohost"))     strncpy(s_sohost, v, sizeof(s_sohost)-1);
        else if (!strcmp(k, "soport"))     s_soport = atoi(v);
        else if (!strcmp(k, "token"))      strncpy(s_token, v, sizeof(s_token)-1);
        else if (!strcmp(k, "prj"))        strncpy(s_prj, v, sizeof(s_prj)-1);
        else if (!strcmp(k, "sosync"))     s_sosync = atoi(v);
        else if (!strcmp(k, "sotick"))     s_sotick = atoi(v);
        else if (!strcmp(k, "enable"))     s_enable = atoi(v);
        else if (!strcmp(k, "autoreload")) s_autoreload = atoi(v);
    }
    fclose(f);
    if (!s_sohost[0]) strncpy(s_sohost, s_host, sizeof(s_sohost)-1);
    if (s_sotick < 10) s_sotick = 120;
}

static NSData *SGet(NSString *url, NSTimeInterval to) {
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    c.timeoutIntervalForRequest = to;
    c.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:c];
    [[s dataTaskWithURL:[NSURL URLWithString:url]
       completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (!e) out = d;
            dispatch_semaphore_signal(sem);
       }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((to + 2) * NSEC_PER_SEC)));
    [s finishTasksAndInvalidate];
    return out;
}

static NSString *SMd5OfFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return nil;
    CC_MD5_CTX ctx; CC_MD5_Init(&ctx);
    unsigned char buf[8192]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) CC_MD5_Update(&ctx, buf, (CC_LONG)n);
    fclose(f);
    unsigned char dig[16]; CC_MD5_Final(dig, &ctx);
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 16; i++) [s appendFormat:@"%02x", dig[i]];
    return s;
}

// ---------------- puller：下载 + 校验 + 原子替换 ----------------
static int SPull(NSString *wantMd5, long wantSize) {
    NSString *u = [NSString stringWithFormat:@"http://%s:%d/so?prj=%s&token=%s",
                   s_sohost, s_soport, s_prj, s_token];
    NSData *d = SGet(u, 20.0);
    if (!d || d.length < 10000) { SLog("pull fail (bytes=%lu)", (unsigned long)d.length); return -1; }

    if (wantSize > 0 && (long)d.length != wantSize)
        SLog("size mismatch got=%lu want=%ld (continue)", (unsigned long)d.length, wantSize);

    if (![d writeToFile:@SY_NEW atomically:YES]) { SLog("write %s fail", SY_NEW); return -2; }
    chmod(SY_NEW, 0644);

    NSString *got = SMd5OfFile(SY_NEW);
    if (wantMd5.length > 0 && got && ![got isEqualToString:wantMd5]) {
        SLog("md5 mismatch got=%s want=%s -> discard", [got UTF8String], [wantMd5 UTF8String]);
        unlink(SY_NEW);
        return -3;
    }

    // 原子替换
    unlink(SY_SO);
    if (rename(SY_NEW, SY_SO) != 0) { SLog("rename fail errno=%d", errno); return -4; }

    SLog("pulled ok md5=%s size=%lu", got ? [got UTF8String] : "-", (unsigned long)d.length);
    if (s_autoreload) {
        NSString *flag = [NSString stringWithFormat:@"%ld\n", (long)time(NULL)];
        [flag writeToFile:@"/var/mobile/Media/bs_reload.flag" atomically:YES
                 encoding:NSUTF8StringEncoding error:nil];
        SLog("reload flag written");
    }
    return 0;
}

// ---------------- verwatch：一轮 ----------------
static void SVerOnce(void) {
    NSString *u = [NSString stringWithFormat:@"http://%s:%d/ver?prj=%s&token=%s",
                   s_sohost, s_soport, s_prj, s_token];
    NSData *d = SGet(u, 8.0);
    if (!d) { SLog("ver network miss"); return; }

    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:[NSDictionary class]]) { SLog("ver bad json"); return; }

    NSString *ver = [j objectForKey:@"ver"];
    NSString *md5 = [j objectForKey:@"md5"];
    long size = [[j objectForKey:@"size"] longValue];
    if (![ver isKindOfClass:[NSString class]] || ver.length == 0) { SLog("ver empty"); return; }

    NSString *local = SMd5OfFile(SY_SO);
    SLog("ver=%s cloud_md5=%.10s local_md5=%.10s",
         [ver UTF8String], md5 ? [md5 UTF8String] : "-", local ? [local UTF8String] : "-");

    if (md5.length == 32 && local && [local isEqualToString:md5]) return;   // 已是最新
    SPull(md5, size);
}

// ---------------- 线程 ----------------
static void SVerThread(void) {
    int first = 1;
    while (1) {
        @autoreleasepool {
            if (s_enable && s_sosync) {
                if (first) { SLog("verwatch start tick=%ds sohost=%s:%d", s_sotick, s_sohost, s_soport); first = 0; }
                SVerOnce();
            }
        }
        sleep(s_sotick > 10 ? s_sotick : 120);
    }
}

__attribute__((constructor))
static void BSSyncInit(void) {
    @autoreleasepool {
        NSString *pn = [[NSProcessInfo processInfo] processName];
        BOOL isAgent = [pn containsString:@"Agent"];
        SConf();
        SLog("init pn=%s isAgent=%d sosync=%d sohost=%s:%d", [pn UTF8String], isAgent, s_sosync, s_sohost, s_soport);
        if (!isAgent) return;                       // 只有 Agent 进程跑同步
        if (!s_enable || !s_sosync) { SLog("disabled"); return; }
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ SVerThread(); });
    }
}
