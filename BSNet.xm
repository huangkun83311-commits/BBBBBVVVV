// BSNet.xm —— 网络层（2.45 行为复刻：fishhook + interpose 双保险）
// 60.204.159.47 改道 / vps.beibeiplay.com + 43.154.19.236 阻断 / 8.153 放行

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <errno.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <time.h>
#import <stdarg.h>
#include "fishhook.h"

#define NET_CONF_PATH "/var/mobile/Media/bs_pull.conf"

static char  n_statip[64];
static int   n_statport   = 0;
static int   n_photoport  = 0;
static int   n_blockvps   = 0;
static int   n_egress     = 1;
static int   n_enable     = 1;
static int   n_hblock     = 1;

static uint32_t n_ip_orig = 0;
static uint32_t n_ip_bb   = 0;
static uint32_t n_ip_new  = 0;
static uint32_t n_stat_be = 0;

static int  n_ready = 0;
static long n_hits  = 0;

static char  n_logpath[256];

static void NLog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt] arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%ld] [net] %@\n", (long)time(NULL), body];

    NSLog(@"[bsn] %@", body);
    if (!n_logpath[0]) {
        NSString *home = NSHomeDirectory();
        const char *cands[] = {
            [[home stringByAppendingPathComponent:@"Documents/bs_bridge.log"] UTF8String],
            [[home stringByAppendingPathComponent:@"tmp/bs_bridge.log"] UTF8String],
            [[NSTemporaryDirectory() stringByAppendingPathComponent:@"bs_bridge.log"] UTF8String],
            "/var/mobile/Media/BetaScreenTYMDESUJCX8T/log/bs_bridge.log",
            "/var/mobile/Media/bs_bridge.log",
            "/var/tmp/bs_bridge.log",
            NULL
        };
        for (int i = 0; cands[i]; i++) {
            FILE *t = fopen(cands[i], "a");
            if (t) { fclose(t); strncpy(n_logpath, cands[i], sizeof(n_logpath) - 1); break; }
        }
    }
    if (!n_logpath[0]) { return; }
    FILE *f = fopen(n_logpath, "a");
    if (f) { fwrite([line UTF8String], 1, [line length], f); fclose(f); }
}

static uint32_t NIp4(const char *s) {
    struct in_addr a; a.s_addr = 0;
    if (s && s[0] && inet_pton(AF_INET, s, &a) == 1) return a.s_addr;
    return 0;
}

static const char *NIpStr(uint32_t be) {
    static char b[24];
    struct in_addr a; a.s_addr = be;
    inet_ntop(AF_INET, &a, b, sizeof(b));
    return b;
}

static int NIsBbHost(const char *h) {
    if (!h || !h[0]) return 0;
    const char *tag = "beibeiplay.com";
    size_t tl = strlen(tag), hl = strlen(h);
    if (hl < tl) return 0;
    return strcasecmp(h + (hl - tl), tag) == 0;
}

static void NConfLoad(void) {
    n_statport = 0; n_photoport = 0; n_blockvps = 0; n_egress = 1; n_enable = 1; n_hblock = 1;
    n_statip[0] = 0;

    FILE *f = fopen(NET_CONF_PATH, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = 0;
            char *k = line, *v = eq + 1;
            while (*k == ' ' || *k == '\t') k++;
            while (*v == ' ' || *v == '\t') v++;
            char *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
            if      (!strcmp(k, "statip"))    strncpy(n_statip, v, sizeof(n_statip) - 1);
            else if (!strcmp(k, "statport"))  n_statport  = atoi(v);
            else if (!strcmp(k, "photoport")) n_photoport = atoi(v);
            else if (!strcmp(k, "blockvps"))  n_blockvps  = atoi(v);
            else if (!strcmp(k, "egress"))    n_egress    = atoi(v);
            else if (!strcmp(k, "enable"))    n_enable    = atoi(v);
            else if (!strcmp(k, "hblock"))    n_hblock    = atoi(v);
        }
        fclose(f);
    }

    n_ip_orig = NIp4("60.204.159.47");
    n_ip_bb   = NIp4("43.154.19.236");
    n_ip_new  = NIp4("8.153.176.121");
    n_stat_be = NIp4(n_statip);
    n_ready = 1;

    NLog("armed orig=60.204.159.47 bb=43.154.19.236 new=8.153.176.121 statip=%s:%d/%d blockvps=%d hblock=%d enable=%d",
         n_statip[0] ? n_statip : "(empty)", n_statport, n_photoport, n_blockvps, n_hblock, n_enable);
}

// ---------------- 原始函数 ----------------
static int     (*o_connect)(int, const struct sockaddr *, int);
static int     (*o_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static ssize_t (*o_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*o_sendmsg)(int, const struct msghdr *, int);

static ssize_t h_sendmsg_(int, const struct msghdr *, int);

static int h_connect_(int, const struct sockaddr *, int);
static int h_getaddrinfo_(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static ssize_t h_sendto_(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

static void NInstallHooks(void) {
    static int logged = 0;
    struct rebinding rb[4];
    rb[0].name = "connect";     rb[0].replacement = (void *)h_connect_;    rb[0].replaced = (void **)&o_connect;
    rb[1].name = "getaddrinfo"; rb[1].replacement = (void *)h_getaddrinfo_; rb[1].replaced = (void **)&o_getaddrinfo;
    rb[2].name = "sendto";      rb[2].replacement = (void *)h_sendto_;     rb[2].replaced = (void **)&o_sendto;
    rb[3].name = "sendmsg";     rb[3].replacement = (void *)h_sendmsg_;    rb[3].replaced = (void **)&o_sendmsg;
    int rc = rebind_symbols(rb, 4);
    if (!logged) {
        logged = 1;
        NLog("fishhook rc=%d orig=%d/%d/%d/%d",
             rc, o_connect ? 1 : 0, o_getaddrinfo ? 1 : 0, o_sendto ? 1 : 0, o_sendmsg ? 1 : 0);
    }
}

// 每 3 秒重新 rebind 一次：beta.so 由 Agent 动态 dlopen，constructor 时它还不在镜像列表里
static void NRebindLoop(void) {
    while (1) {
        sleep(3);
        @autoreleasepool { NInstallHooks(); }
    }
}

// ---------------- 核心处理 ----------------
static int NHandleConnect(int fd, const struct sockaddr *sa, int len) {
    if (!n_ready) NConfLoad();
    if (!o_connect) o_connect = (int (*)(int, const struct sockaddr *, int))dlsym(RTLD_DEFAULT, "connect");
    if (!o_connect) { errno = EFAULT; return -1; }
    if (!sa || sa->sa_family != AF_INET || len < (int)sizeof(struct sockaddr_in))
        return o_connect(fd, sa, len);

    const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
    uint32_t ip = si->sin_addr.s_addr;
    int port = ntohs(si->sin_port);

    int isOrig = (n_ip_orig && ip == n_ip_orig);
    int isBb   = (n_ip_bb   && ip == n_ip_bb);
    if (!isOrig && !isBb) return o_connect(fd, sa, len);
    if (!n_enable) return o_connect(fd, sa, len);

    n_hits++;

    if (isBb && n_blockvps) {
        NLog("[blk] connect %s:%d blocked (#%ld)", NIpStr(ip), port, n_hits);
        errno = ECONNREFUSED;
        return -1;
    }

    if (!n_stat_be) {
        NLog("[off] connect %s:%d pass (statip empty) (#%ld)", NIpStr(ip), port, n_hits);
        return o_connect(fd, sa, len);
    }

    struct sockaddr_in n2 = *si;
    n2.sin_addr.s_addr = n_stat_be;
    int np = port;
    if (port == 7880 && n_photoport > 0) np = n_photoport;
    else if (n_statport > 0)             np = n_statport;
    n2.sin_port = htons((uint16_t)np);

    NLog("%s connect %s:%d -> %s:%d (#%ld)",
         isOrig ? "[off]" : "[s2]", NIpStr(ip), port, n_statip, np, n_hits);
    return o_connect(fd, (const struct sockaddr *)&n2, sizeof(n2));
}

static int h_connect_(int fd, const struct sockaddr *sa, int len) {
    return NHandleConnect(fd, sa, len);
}

static int h_getaddrinfo_(const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
    if (!n_ready) NConfLoad();
    if (n_enable && n_hblock && n_blockvps && NIsBbHost(node)) {
        n_hits++;
        NLog("[blk] getaddrinfo %s blocked (#%ld)", node, n_hits);
        return EAI_NONAME;
    }
    return o_getaddrinfo(node, service, hints, res);
}

static ssize_t h_sendto_(int fd, const void *buf, size_t n, int flags,
                         const struct sockaddr *sa, socklen_t len) {
    if (!n_ready) NConfLoad();
    if (!o_sendto) { errno = EFAULT; return -1; }
    if (!n_enable || !sa || sa->sa_family != AF_INET || len < sizeof(struct sockaddr_in))
        return o_sendto(fd, buf, n, flags, sa, len);

    const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
    uint32_t ip = si->sin_addr.s_addr;
    int port = ntohs(si->sin_port);
    if (!((n_ip_orig && ip == n_ip_orig) || (n_ip_bb && ip == n_ip_bb)))
        return o_sendto(fd, buf, n, flags, sa, len);

    if (n_ip_bb && ip == n_ip_bb && n_blockvps) {
        n_hits++;
        NLog("[blk] sendto %s:%d blocked (#%ld)", NIpStr(ip), port, n_hits);
        errno = ECONNREFUSED;
        return -1;
    }
    if (!n_stat_be) return o_sendto(fd, buf, n, flags, sa, len);

    struct sockaddr_in nn = *si;
    nn.sin_addr.s_addr = n_stat_be;
    int np = (port == 7880 && n_photoport > 0) ? n_photoport : (n_statport > 0 ? n_statport : port);
    nn.sin_port = htons((uint16_t)np);
    n_hits++;
    NLog("[off] sendto %s:%d -> %s:%d (#%ld)", NIpStr(ip), port, n_statip, np, n_hits);
    return o_sendto(fd, buf, n, flags, (const struct sockaddr *)&nn, sizeof(nn));
}

// ---------------- sendmsg：UDP / 带 msg_name 的发送 ----------------
static ssize_t h_sendmsg_(int fd, const struct msghdr *m, int flags) {
    if (!n_ready) NConfLoad();
    if (!o_sendmsg) o_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))dlsym(RTLD_DEFAULT, "sendmsg");
    if (!o_sendmsg) { errno = EFAULT; return -1; }
    if (!n_enable || !m || !m->msg_name) return o_sendmsg(fd, m, flags);

    struct sockaddr *sa = (struct sockaddr *)m->msg_name;
    if (sa->sa_family != AF_INET || m->msg_namelen < sizeof(struct sockaddr_in))
        return o_sendmsg(fd, m, flags);

    const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
    uint32_t ip = si->sin_addr.s_addr;
    int port = ntohs(si->sin_port);
    if (!((n_ip_orig && ip == n_ip_orig) || (n_ip_bb && ip == n_ip_bb)))
        return o_sendmsg(fd, m, flags);

    if (n_ip_bb && ip == n_ip_bb && n_blockvps) {
        n_hits++;
        NLog("[blk] sendmsg %s:%d blocked (#%ld)", NIpStr(ip), port, n_hits);
        errno = ECONNREFUSED;
        return -1;
    }
    if (!n_stat_be) return o_sendmsg(fd, m, flags);

    struct sockaddr_in nn = *si;
    nn.sin_addr.s_addr = n_stat_be;
    int np = (port == 7880 && n_photoport > 0) ? n_photoport : (n_statport > 0 ? n_statport : port);
    nn.sin_port = htons((uint16_t)np);
    struct msghdr m2 = *m;
    m2.msg_name = &nn;
    m2.msg_namelen = sizeof(nn);
    n_hits++;
    NLog("[off] sendmsg %s:%d -> %s:%d (#%ld)", NIpStr(ip), port, n_statip, np, n_hits);
    return o_sendmsg(fd, &m2, flags);
}

// ---------------- interpose 兜底（与 2.45 一致：fish + interpose 双开）----------------
struct bs_interpose_t { const void *replacement; const void *replacee; };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_connect =
    { (const void *)h_connect_, (const void *)connect };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_getaddrinfo =
    { (const void *)h_getaddrinfo_, (const void *)getaddrinfo };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_sendto =
    { (const void *)h_sendto_, (const void *)sendto };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_sendmsg =
    { (const void *)h_sendmsg_, (const void *)sendmsg };

__attribute__((constructor))
static void BSNetInit(void) {
    @autoreleasepool {
        // 探针：不依赖日志、不受沙箱影响，直接连回 PC 9999 证明 init 是否执行
        {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s >= 0) {
                struct sockaddr_in a; memset(&a, 0, sizeof(a));
                a.sin_family = AF_INET;
                a.sin_port = htons(9999);
                a.sin_addr.s_addr = inet_addr("192.168.1.18");
                int rc = connect(s, (struct sockaddr *)&a, sizeof(a));
                char b[96];
                snprintf(b, sizeof(b), "BEACON pid=%d rc=%d pn=%s", getpid(), rc,
                         [[[NSProcessInfo processInfo] processName] UTF8String]);
                send(s, b, strlen(b), 0);
                close(s);
            }
        }
        int su = setuid(0);
        int sg = setgid(0);
        NSLog(@"[bsn] BOOT pid=%d uid=%d su=%d sg=%d", getpid(), getuid(), su, sg);
        NConfLoad();
        NInstallHooks();
        NLog("net layer installed mode=fishhook+interpose enable=%d probe_uid=%d/%d", n_enable, su, sg);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool { NRebindLoop(); }
        });
    }
}
