// krwtweak.c —— 注入 SpringBoard 的内核读写 RPC（v2）
// v2 修复：jbroot 路径动态发现、从 libjailbreak 解析 kread/kwrite、自动扫 kbase
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int (*fn_rw)(unsigned long long, void *, size_t);
typedef unsigned long long (*fn_base)(void);

static fn_rw g_read, g_write;
static fn_base g_base;
static char g_backend[256];

static int find_jbroot(char *out, size_t cap)
{
    DIR *d = opendir("/var/containers/Bundle/Application");
    struct dirent *de;
    if (!d) return -1;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, ".jbroot-", 8) == 0) {
            snprintf(out, cap, "/var/containers/Bundle/Application/%s", de->d_name);
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

static int krw_load(void)
{
    char jb[512], p[768];
    void *h = NULL;
    int i;
    static const char *REL[] = {
        "/usr/lib/libkrw/libkrw-relaxin.dylib",
        "/usr/lib/libkrw.0.dylib",
        "/usr/lib/libkrw.dylib",
        "/private/var/tmp/libkrwrelaxin.dylib",
        NULL
    };
    if (find_jbroot(jb, sizeof(jb)) == 0) {
        for (i = 0; REL[i]; i++) {
            snprintf(p, sizeof(p), "%s%s", jb, REL[i]);
            h = dlopen(p, RTLD_NOW | RTLD_GLOBAL);
            if (h) { snprintf(g_backend, sizeof(g_backend), "%s", p); break; }
        }
    }
    if (!h) {
        for (i = 0; REL[i]; i++) {
            h = dlopen(REL[i], RTLD_NOW | RTLD_GLOBAL);
            if (h) { snprintf(g_backend, sizeof(g_backend), "%s", REL[i]); break; }
        }
    }
    if (!h) return -1;

    /* 初始化 libkrw（它自己会连 libjailbreak 的原语） */
    {
        void (*init)(void) = (void (*)(void))dlsym(h, "kcall_initializer");
        if (init) init();
    }

    /* kread/kwrite 是 libjailbreak 的导入符号，用 RTLD_DEFAULT 解析 */
    g_read  = (fn_rw)dlsym(RTLD_DEFAULT, "kreadbuf");
    g_write = (fn_rw)dlsym(RTLD_DEFAULT, "kwritebuf");
    if (!g_read)  g_read  = (fn_rw)dlsym(h, "kread");
    if (!g_write) g_write = (fn_rw)dlsym(h, "kwrite");
    g_base = (fn_base)dlsym(RTLD_DEFAULT, "kbase");

    if (!g_read || !g_write) return -2;
    return 0;
}

static unsigned long long scan_kbase(void)
{
    unsigned long long slide;
    unsigned char buf[8];
    if (!g_read) return 0;
    for (slide = 0; slide <= 0x40000000ULL; slide += 0x200000ULL) {
        unsigned long long base = 0xfffffff007004000ULL + slide;
        if (g_read(base, buf, 4) == 0) {
            unsigned int magic = buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((unsigned)buf[3] << 24);
            if (magic == 0xfeedfacf || magic == 0xfeedface)
                return base;
        }
    }
    return 0;
}

static void hexenc(const unsigned char *b, size_t n, char *o)
{
    static const char *H = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { o[i*2] = H[b[i] >> 4]; o[i*2+1] = H[b[i] & 15]; }
    o[n*2] = 0;
}

static int jstr(const char *j, const char *k, char *o, size_t cap)
{
    char pat[64]; const char *p, *q; size_t n;
    snprintf(pat, sizeof(pat), "\"%s\"", k);
    p = strstr(j, pat); if (!p) return -1;
    p = strchr(p + strlen(pat), ':'); if (!p) return -1;
    p++; while (*p == ' ') p++;
    if (*p == '"') { p++; q = strchr(p, '"'); } else { q = p; while (*q && *q != ',' && *q != '}') q++; }
    if (!q) return -1;
    n = (size_t)(q - p); if (n >= cap) n = cap - 1;
    memcpy(o, p, n); o[n] = 0; return 0;
}

static unsigned long long parse_num(const char *s)
{
    if (!s) return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return strtoull(s + 2, NULL, 16);
    return strtoull(s, NULL, 0);
}

static void handle(const char *req, char *resp, size_t cap)
{
    char cmd[24] = {0}, addr[32] = {0}, lenstr[32] = {0};
    if (jstr(req, "cmd", cmd, sizeof(cmd))) { snprintf(resp, cap, "{\"ok\":false}\n"); return; }
    if (!strcmp(cmd, "ping")) {
        snprintf(resp, cap, "{\"ok\":true,\"backend\":\"%s\"}\n", g_backend);
    } else if (!strcmp(cmd, "kbase")) {
        unsigned long long b = g_base ? g_base() : 0;
        if (!b) b = scan_kbase();
        snprintf(resp, cap, "{\"ok\":%s,\"kbase\":\"0x%llx\"}\n", b ? "true" : "false", b);
    } else if (!strcmp(cmd, "kread")) {
        static unsigned char buf[1 << 16]; static char out[1 << 17];
        long long len = 32;
        if (jstr(req, "addr", addr, sizeof(addr))) { snprintf(resp, cap, "{\"ok\":false}\n"); return; }
        if (!jstr(req, "len", lenstr, sizeof(lenstr))) len = strtoll(lenstr, NULL, 0);
        if (len <= 0 || len > (long long)sizeof(buf)) len = 32;
        if (g_read(parse_num(addr), buf, (size_t)len) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"kread failed\"}\n"); return;
        }
        hexenc(buf, (size_t)len, out);
        snprintf(resp, cap, "{\"ok\":true,\"hex\":\"%s\"}\n", out);
    } else if (!strcmp(cmd, "kwrite")) {
        static unsigned char buf[1 << 16]; char hex[1 << 17] = {0};
        size_t i, n;
        if (jstr(req, "addr", addr, sizeof(addr)) || jstr(req, "hex", hex, sizeof(hex))) {
            snprintf(resp, cap, "{\"ok\":false}\n"); return;
        }
        n = strlen(hex) / 2;
        if (n > sizeof(buf)) n = sizeof(buf);
        for (i = 0; i < n; i++) {
            unsigned v;
            if (sscanf(hex + i*2, "%2x", &v) != 1) { snprintf(resp, cap, "{\"ok\":false}\n"); return; }
            buf[i] = (unsigned char)v;
        }
        if (g_write(parse_num(addr), buf, n) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"kwrite failed\"}\n"); return;
        }
        snprintf(resp, cap, "{\"ok\":true,\"len\":%zu}\n", n);
    } else {
        snprintf(resp, cap, "{\"ok\":false,\"err\":\"unknown\"}\n");
    }
}

static void *server(void *arg)
{
    int port = (int)(long)arg;
    int srv, cli;
    struct sockaddr_in sa;
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return NULL;
    {
        int one = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(srv); return NULL; }
    listen(srv, 4);
    for (;;) {
        char req[1 << 17], resp[1 << 18];
        ssize_t n;
        cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;
        while ((n = read(cli, req, sizeof(req) - 1)) > 0) {
            req[n] = 0;
            memset(resp, 0, sizeof(resp));
            handle(req, resp, sizeof(resp));
            write(cli, resp, strlen(resp));
        }
        close(cli);
    }
    return NULL;
}

__attribute__((constructor))
static void krwtweak_init(void)
{
    pthread_t th;
    if (krw_load() != 0) {
        /* 加载失败也起服务，ping 会返回 backend 为空，方便诊断 */
        memset(g_backend, 0, sizeof(g_backend));
    }
    pthread_create(&th, NULL, server, (void *)27060);
    pthread_detach(th);
}
