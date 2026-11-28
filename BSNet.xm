// BSNet.xm —— 网络层（按 2.45 bs_unlock 行为复刻的第一版）
// 目标：60.204.159.47 改道 / vps.beibeiplay.com + 43.154.19.236 阻断 / 8.153 放行
// conf: /var/mobile/Media/bs_pull.conf   log: /var/mobile/Media/bs_bridge.log

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

#define NET_CONF_PATH "/var/mobile/Media/bs_pull.conf"
#define NET_LOG_PATH  "/var/mobile/Media/bs_bridge.log"

static char  n_statip[64];
static int   n_statport   = 0;
static int   n_photoport  = 0;
static int   n_blockvps   = 0;
static int   n_egress     = 1;
static int   n_enable     = 1;
static int   n_hblock     = 1;

static uint32_t n_ip_orig = 0;      // 60.204.159.47  原厂 IP 直连（改道）
static uint32_t n_ip_bb   = 0;      // 43.154.19.236  原厂域名入口（阻断）
static uint32_t n_ip_new  = 0;      // 8.153.176.121  放行（不拦）
static uint32_t n_stat_be = 0;      // statip 的 network order

static int n_ready = 0;
static long n_hits = 0;

static void NLog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt] arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%ld] [net] %@\n", (long)time(NULL), msg];
    FILE *f = fopen(NET_LOG_PATH, "a");
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
    // 域名精确匹配 + 后缀匹配（防止带端口的写法漏掉）
    const char *tag = "beibeiplay.com";
    size_t tl = strlen(tag);
    size_t hl = strlen(h);
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
            if      (!strcmp(k, "statip"))     strncpy(n_statip, v, sizeof(n_statip) - 1);
            else if (!strcmp(k, "statport"))   n_statport  = atoi(v);
            else if (!strcmp(k, "photoport"))  n_photoport = atoi(v);
            else if (!strcmp(k, "blockvps"))   n_blockvps  = atoi(v);
            else if (!strcmp(k, "egress"))     n_egress    = atoi(v);
            else if (!strcmp(k, "enable"))     n_enable    = atoi(v);
            else if (!strcmp(k, "hblock"))     n_hblock    = atoi(v);
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

static void NResolveOrig(void) {
    if (!o_connect)     o_connect     = (int (*)(int, const struct sockaddr *, int))dlsym(RTLD_NEXT, "connect");
    if (!o_getaddrinfo) o_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
    if (!o_sendto)      o_sendto      = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "sendto");
}

// ---------------- connect ----------------
static int NHandle(int fd, const struct sockaddr *sa, int len, const char *tag) {
    if (!n_ready) NConfLoad();
    NResolveOrig();
    if (!o_connect) { errno = EFAULT; return -1; }
    if (!sa || sa->sa_family != AF_INET || len < (int)sizeof(struct sockaddr_in))
        return o_connect(fd, sa, len);

    const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
    uint32_t ip = si->sin_addr.s_addr;
    int port = ntohs(si->sin_port);

    int isOrig = (n_ip_orig && ip == n_ip_orig);
    int isBb   = (n_ip_bb   && ip == n_ip_bb);
    if (!isOrig && !isBb) return o_connect(fd, sa, len);      // 8.153 及其他一律放行

    if (!n_enable) return o_connect(fd, sa, len);

    n_hits++;

    // 43.154 / beibeiplay：blockvps=1 才封
    if (isBb) {
        if (n_blockvps) {
            NLog("[blk] connect %s:%d blocked hblock=%d (#%ld)", NIpStr(ip), port, n_hblock, n_hits);
            errno = ECONNREFUSED;
            return -1;
        }
        // blockvps=0 时只做改道（与 2.45 一致：BLOCK DISABLED / s2 redirect still on）
    }

    // 改道目标
    if (!n_stat_be) {
        NLog("[off] connect %s:%d intercepted, statip empty -> pass (#%ld)", NIpStr(ip), port, n_hits);
        return o_connect(fd, sa, len);
    }

    struct sockaddr_in n = *si;
    n.sin_addr.s_addr = n_stat_be;
    int np = port;
    if (port == 7880 && n_photoport > 0) np = n_photoport;
    else if (n_statport > 0)             np = n_statport;
    n.sin_port = htons((uint16_t)np);

    NLog("[%s] connect %s:%d -> %s:%d (#%ld)",
         isOrig ? "off" : "s2", NIpStr(ip), port, n_statip, np, n_hits);
    return o_connect(fd, (const struct sockaddr *)&n, sizeof(n));
}

static int h_connect(int fd, const struct sockaddr *sa, int len) {
    return NHandle(fd, sa, len, "connect");
}

// ---------------- getaddrinfo：域名级拦截 ----------------
static int h_getaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res) {
    if (!n_ready) NConfLoad();
    NResolveOrig();
    if (!o_getaddrinfo) { return EAI_FAIL; }

    if (n_enable && n_hblock && n_blockvps && NIsBbHost(node)) {
        n_hits++;
        NLog("[blk] getaddrinfo %s blocked (#%ld)", node, n_hits);
        return EAI_NONAME;
    }
    return o_getaddrinfo(node, service, hints, res);
}

// ---------------- sendto：UDP 直接发 ----------------
static ssize_t h_sendto(int fd, const void *buf, size_t n, int flags,
                        const struct sockaddr *sa, socklen_t len) {
    if (!n_ready) NConfLoad();
    NResolveOrig();
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

// ---------------- interpose 注册 ----------------
struct bs_interpose_t { const void *replacement; const void *replacee; };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_connect =
    { (const void *)h_connect, (const void *)connect };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_getaddrinfo =
    { (const void *)h_getaddrinfo, (const void *)getaddrinfo };

__attribute__((used, section("__DATA,__interpose")))
static struct bs_interpose_t bs_int_sendto =
    { (const void *)h_sendto, (const void *)sendto };

__attribute__((constructor))
static void BSNetInit(void) {
    @autoreleasepool {
        NConfLoad();
        NResolveOrig();
        NLog("net layer installed (interpose=on orig=%d bb=%d stat=%d)",
             o_connect ? 1 : 0, o_getaddrinfo ? 1 : 0, o_sendto ? 1 : 0);
    }
}
