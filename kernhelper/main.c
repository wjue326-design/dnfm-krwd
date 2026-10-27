// dnfm-krwd：内核读写守护进程
// 作用：由 launchd 以 root 身份拉起（jbroot 上下文），加载 libkrw，暴露本机 TCP RPC。
// 协议：一行一个 JSON 请求/应答
//   {"cmd":"kbase"}
//   {"cmd":"kread","addr":"0x...","len":64}
//   {"cmd":"kwrite","addr":"0x...","hex":"..."}
//   {"cmd":"kcall","addr":"0x...","args":["0x..","0x.."]}
// 仅监听 127.0.0.1，外部访问必须走 SSH 隧道（见 krw_client.py）。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int (*fn_rw)(unsigned long long, void *, size_t);
typedef unsigned long long (*fn_base)(void);
typedef int (*fn_kcall)(unsigned long long, unsigned long long, unsigned long long,
                        unsigned long long, unsigned long long, unsigned long long *);

/* libkrw 各版本符号名不一样，逐个试 */
struct krw {
    void *h;
    fn_rw read;
    fn_rw write;
    fn_base base;
    fn_kcall kcall;
    char backend[128];
};

static const char *PATHS[] = {
    "/usr/lib/libkrw.0.dylib",
    "/var/jb/usr/lib/libkrw.0.dylib",
    "/usr/lib/libkrw/libkrw-relaxin.dylib",
    "/var/jb/usr/lib/libkrw/libkrw-relaxin.dylib",
    "/usr/lib/libkrw.dylib",
    NULL
};

static void *sym_try(void *h, const char *a, const char *b, const char *c)
{
    void *p = NULL;
    if (a) p = dlsym(h, a);
    if (!p && b) p = dlsym(h, b);
    if (!p && c) p = dlsym(h, c);
    return p;
}

static int krw_open(struct krw *k)
{
    int i;
    memset(k, 0, sizeof(*k));
    for (i = 0; PATHS[i]; i++) {
        k->h = dlopen(PATHS[i], RTLD_NOW);
        if (k->h) {
            k->read  = (fn_rw)sym_try(k->h, "kread", "kreadbuf", "krw_read");
            k->write = (fn_rw)sym_try(k->h, "kwrite", "kwritebuf", "krw_write");
            k->base  = (fn_base)sym_try(k->h, "kbase", "kernel_base", NULL);
            k->kcall = (fn_kcall)sym_try(k->h, "kcall", NULL, NULL);
            if (k->read && k->write) {
                snprintf(k->backend, sizeof(k->backend), "%s", PATHS[i]);
                return 0;
            }
            dlclose(k->h);
            k->h = NULL;
        }
    }
    return -1;
}

/* ---------------- 极简 JSON 取值 ---------------- */
static int jget_str(const char *j, const char *key, char *out, size_t cap)
{
    char pat[64];
    const char *p, *q;
    size_t n;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(j, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') { p++; q = strchr(p, '"'); }
    else { q = p; while (*q && *q != ',' && *q != '}') q++; }
    if (!q) return -1;
    n = (size_t)(q - p);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n); out[n] = 0;
    return 0;
}

static long long jget_int(const char *j, const char *key, long long def)
{
    char buf[64];
    if (jget_str(j, key, buf, sizeof(buf))) return def;
    return strtoll(buf, NULL, 0);
}

static void hexdump_encode(const unsigned char *b, size_t n, char *out)
{
    static const char *h = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}

static int hex2bin(const char *hex, unsigned char *out, size_t cap)
{
    size_t n = strlen(hex), i;
    if (n % 2) return -1;
    if (n / 2 > cap) return -1;
    for (i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return (int)(n / 2);
}

/* ---------------- 处理一条请求 ---------------- */
static void handle(struct krw *k, const char *req, char *resp, size_t cap)
{
    char cmd[32] = {0};
    if (jget_str(req, "cmd", cmd, sizeof(cmd))) {
        snprintf(resp, cap, "{\"ok\":false,\"err\":\"no cmd\"}\n");
        return;
    }

    if (!strcmp(cmd, "ping")) {
        snprintf(resp, cap, "{\"ok\":true,\"backend\":\"%s\"}\n", k->backend);
    } else if (!strcmp(cmd, "kbase")) {
        unsigned long long b = k->base ? k->base() : 0;
        snprintf(resp, cap, "{\"ok\":%s,\"kbase\":\"0x%llx\"}\n",
                 b ? "true" : "false", b);
    } else if (!strcmp(cmd, "kread")) {
        char addr[32] = {0};
        long long len = jget_int(req, "len", 16);
        static unsigned char buf[1 << 16];
        static char hex[(1 << 17) + 2];
        unsigned long long a;
        if (jget_str(req, "addr", addr, sizeof(addr)) || len <= 0 || len > (long long)sizeof(buf)) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"bad args\"}\n"); return;
        }
        a = strtoull(addr, NULL, 0);
        if (k->read(a, buf, (size_t)len) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"kread failed\"}\n"); return;
        }
        hexdump_encode(buf, (size_t)len, hex);
        snprintf(resp, cap, "{\"ok\":true,\"hex\":\"%s\"}\n", hex);
    } else if (!strcmp(cmd, "kwrite")) {
        char addr[32] = {0}, hex[1 << 17] = {0};
        static unsigned char buf[1 << 16];
        unsigned long long a;
        int n;
        if (jget_str(req, "addr", addr, sizeof(addr)) || jget_str(req, "hex", hex, sizeof(hex))) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"bad args\"}\n"); return;
        }
        a = strtoull(addr, NULL, 0);
        n = hex2bin(hex, buf, sizeof(buf));
        if (n < 0) { snprintf(resp, cap, "{\"ok\":false,\"err\":\"bad hex\"}\n"); return; }
        if (k->write(a, buf, (size_t)n) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"err\":\"kwrite failed\"}\n"); return;
        }
        snprintf(resp, cap, "{\"ok\":true,\"len\":%d}\n", n);
    } else {
        snprintf(resp, cap, "{\"ok\":false,\"err\":\"unknown cmd\"}\n");
    }
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 27050;
    int srv, cli;
    struct sockaddr_in sa;
    struct krw k;

    if (krw_open(&k)) {
        fprintf(stderr, "dnfm-krwd: 没有可用的 libkrw（检查 /usr/lib/libkrw*）\n");
        return 1;
    }
    fprintf(stderr, "dnfm-krwd: backend=%s port=%d\n", k.backend, port);

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    {
        int one = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 只监听本机，外部走 SSH 隧道 */
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    listen(srv, 4);

    for (;;) {
        char req[1 << 17];
        static char resp[1 << 18];
        ssize_t n;
        cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;
        while ((n = read(cli, req, sizeof(req) - 1)) > 0) {
            req[n] = 0;
            handle(&k, req, resp, sizeof(resp));
            write(cli, resp, strlen(resp));
        }
        close(cli);
    }
    return 0;
}
