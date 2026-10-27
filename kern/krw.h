/* ios kernel r/w 抽象层
 *
 * 后端来源（按顺序尝试）：
 *   1) /var/jb/usr/lib/libkrw.dylib 或系统内 libkrw（越狱自带），导出 kread/kwrite/kbase
 *   2) /var/jb/usr/lib/libkrwshim.dylib（自备 shim，导出 ios_kread/ios_kwrite/ios_kbase/ios_ksym）
 *   3) 都不在 → 退出，绝不在没有 r/w 的情况下乱写内核
 */
#ifndef IOS_KRW_H
#define IOS_KRW_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	void    *handle;          /* dlopen 句柄 */
	char     backend[48];
	uint64_t kbase;
	uint64_t kslide;
	int      has_kcall;
	int      has_ksym;
	/* 后端函数指针 */
	int      (*read)(uint64_t addr, void *buf, size_t len);
	int      (*write)(uint64_t addr, const void *buf, size_t len);
	uint64_t (*base)(void);
	uint64_t (*sym)(const char *name);
	int      (*kcall)(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2,
			  uint64_t a3, uint64_t *ret);
} krw_ctx;

int  krw_init(krw_ctx *c);
void krw_close(krw_ctx *c);

static inline int krw_read(krw_ctx *c, uint64_t addr, void *buf, size_t len)
{
	return c->read ? c->read(addr, buf, len) : -1;
}

static inline int krw_write(krw_ctx *c, uint64_t addr, const void *buf, size_t len)
{
	return c->write ? c->write(addr, buf, len) : -1;
}

uint64_t krw_sym(krw_ctx *c, const char *name);

#endif
