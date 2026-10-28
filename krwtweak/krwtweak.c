// krwtweak.c —— 注入 SpringBoard，加载 libkrw，暴露本机内核读写 RPC
// 为什么放这里：ellekit 注入的 tweak 天然带越狱上下文，能访问 /var/jb 并 dlopen 越狱库；
// 独立 launchd 守护进程会被沙盒挡掉 mmap。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int (*fn_rw)(unsigned long long, void *, size_t);
typedef unsigned long long (*fn_base)(void);

static fn_rw g_read, g_write;
static fn_base g_base;
static char g_backend[128];

static const char *PATHS[] = {
    "/var/jb/usr/lib/libkrw/libkrw-relaxin.dylib",
    "/var/jb/usr/lib/libkrw.0.dylib",
    "/var/jb/usr/lib/libkrw.dylib",
    "/private/var/tmp/libkrwrelaxin.dylib",
    NULL
};

static void *sym(void *h, const char *a, const char *b)
{
    void *p = dlsym(h, a);
    if (!p && b) p = dlsym(h, b);
    return p;
}

static int krw_load(void)
{
    int i;
    for (i = 0; PATHS[i]; i++) {
        void *h = dlopen(PATHS[i], RTLD_NOW | RTLD_GLOBAL);
        if (!h) continue;
        g_read  = (fn_rw)sym(h, "kread", "kreadbuf");
        g_write = (fn_rw)sym(h, "kwrite", "kwritebuf");
        g_base  = (fn_base)sym(h, "kbase", "kernel_base");
        if (g_read && g_write) {
            snprintf(g_backend, sizeof(g_backend), "%s", PATHS[i]);
            return 0;
        }
        dlclose(h);
    }
    return -1;
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

static void handle(const char *req, char *resp, size_t cap)
{
    char cmd[24] = {0}, addr[32] = {0};
    if (jstr(req, "cmd", cmd, sizeof(cmd))) { snprintf(resp, cap, "{\"ok\":false}\n"); return; }
    if (!strcmp(cmd, "ping")) {
        snprintf(resp, cap, "{\"ok\":true,\"backend\":\"%s\"}\n", g_backend);
    } else if (!strcmp(cmd, "kbase")) {
        unsigned long long b = g_base ? g_base() : 0;
        snprintf(resp, cap, "{\"ok\":%s,\"kbase\":\"0x%llx\"}\n", b ? "true" : "false", b);
    } else if (!strcmp(cmd, "kread")) {
        static unsigned char buf[1 << 16]; static char out[1 << 17];
        long long len = 32;
        char tmp[32];
        if (jstr(req, "addr", addr, sizeof(addr))) { snprintf(resp, cap, "{\"ok\":false}\n"); return; }
        if (!jstr(req, "len", tmp, sizeof(tmp))) len = strtoll(tmp, NULL, 0);
        if (len <= 0 || len > (long long)sizeof(buf)) len = 32;
        if (g_read(strtoull(addr, NULL, 0), buf, (size_t)len) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"kread failed\"}\n"); return;
        }
        hexenc(buf, (size_t)len, out);
        snprintf(resp, cap, "{\"ok\":true,\"hex\":\"%s\"}", out);
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
    if (krw_load() != 0) return;
    pthread_create(&th, NULL, server, (void *)27060);
    pthread_detach(th);
}
