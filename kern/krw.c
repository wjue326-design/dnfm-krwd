/* krw.c — 把越狱给的内核 r/w 包成统一接口 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>

#include "krw.h"

struct backend_spec {
	const char *path;
	const char *read_sym;
	const char *write_sym;
	const char *base_sym;
	const char *sym_sym;
	const char *kcall_sym;
};

static const struct backend_spec g_specs[] = {
	{ "/var/jb/usr/lib/libkrw.dylib", "kread", "kwrite", "kbase", "ksym", "kcall" },
	{ "/var/jb/usr/lib/libkrwshim.dylib", "ios_kread", "ios_kwrite", "ios_kbase", "ios_ksym", "ios_kcall" },
	{ "libkrw.dylib", "kread", "kwrite", "kbase", "ksym", "kcall" },
	{ "libkrwshim.dylib", "ios_kread", "ios_kwrite", "ios_kbase", "ios_ksym", "ios_kcall" },
};

static int try_backend(krw_ctx *c, const struct backend_spec *s)
{
	void *h = dlopen(s->path, RTLD_NOW | RTLD_LOCAL);
	if (!h)
		return -1;

	c->read  = (int (*)(uint64_t, void *, size_t))dlsym(h, s->read_sym);
	c->write = (int (*)(uint64_t, const void *, size_t))dlsym(h, s->write_sym);
	if (!c->read || !c->write) {
		dlclose(h);
		return -1;
	}
	c->base   = (uint64_t (*)(void))dlsym(h, s->base_sym);
	c->sym    = (uint64_t (*)(const char *))dlsym(h, s->sym_sym);
	c->kcall  = (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t *))dlsym(h, s->kcall_sym);
	c->handle = h;
	c->has_kcall = c->kcall != NULL;
	c->has_ksym  = c->sym != NULL;
	strncpy(c->backend, s->path, sizeof(c->backend) - 1);
	return 0;
}

int krw_init(krw_ctx *c)
{
	size_t i;
	uint64_t probe = 0;

	memset(c, 0, sizeof(*c));
	for (i = 0; i < sizeof(g_specs) / sizeof(g_specs[0]); i++) {
		if (try_backend(c, &g_specs[i]) == 0)
			break;
	}
	if (!c->handle) {
		fprintf(stderr, "[krw] 没有可用后端：先越狱，确认 libkrw 存在\n");
		return -1;
	}

	if (c->base)
		c->kbase = c->base();

	/* 探一次内核内存，确认 r/w 真能用（读 kernel base 前 4 字节） */
	if (krw_read(c, c->kbase, &probe, 4) != 0 || probe == 0) {
		fprintf(stderr, "[krw] 后端 %s 读了 0x%llx 失败，判定不可用\n",
			c->backend, (unsigned long long)c->kbase);
		krw_close(c);
		return -1;
	}

	printf("[krw] 后端=%s kbase=0x%llx kcall=%d ksym=%d\n",
	       c->backend, (unsigned long long)c->kbase, c->has_kcall, c->has_ksym);
	return 0;
}

void krw_close(krw_ctx *c)
{
	if (c->handle)
		dlclose(c->handle);
	memset(c, 0, sizeof(*c));
}

uint64_t krw_sym(krw_ctx *c, const char *name)
{
	if (!c->has_ksym || !name)
		return 0;
	return c->sym(name);
}
