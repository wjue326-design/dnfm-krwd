/* stealth.h — 内核补丁（dyld 摘链 / allproc 摘链 / task_for_pid 放行）
 *
 * 原则：每一处写入前先读原值比对，字节不符就放弃，绝不把内核写坏。
 */
#ifndef IOS_STEALTH_H
#define IOS_STEALTH_H

#include <stdint.h>
#include "krw.h"

struct kern_offsets {
	uint32_t proc_list_next;   /* offsetof(struct proc, p_list.le_next) */
	uint32_t proc_list_prev;   /* offsetof(struct proc, p_list.le_prev) */
	uint32_t proc_pid;         /* offsetof(struct proc, p_pid)        */
	uint32_t proc_comm;        /* offsetof(struct proc, p_comm)       */
	uint32_t task_proc;        /* offsetof(struct task, bsd_info)     */
	uint32_t dyld_infos_count; /* offsetof(dyld_all_image_infos, infoArrayCount) */
	uint32_t dyld_infos_array; /* offsetof(dyld_all_image_infos, infoArray) */
	uint32_t dyld_image_size;  /* sizeof(struct dyld_image_info) */
	uint32_t dyld_image_path;  /* offsetof(dyld_image_info, imageFilePath) */
};

int  offsets_load(const char *path, struct kern_offsets *o);

/* 打印 patch 计划并校验原字节；dry=1 只校验不写 */
int  kern_patch_verified(krw_ctx *c, uint64_t addr,
			 const void *expect, const void *patch, size_t len, int dry);

/* 从 dyld_all_image_infos 里摘掉路径包含 needle 的镜像。
 * infos_va 是 dyld_all_image_infos 的地址（用户态 _dyld_get_all_image_infos() 可拿）。 */
int  stealth_hide_dylib(krw_ctx *c, const struct kern_offsets *o,
			uint64_t infos_va, const char *needle, int dry);

/* 从内核 allproc 链表里摘掉 pid（我们的守护进程） */
int  stealth_hide_proc(krw_ctx *c, const struct kern_offsets *o,
		       uint64_t allproc, int pid, int dry);

/* 把 task_for_pid 改成直接返回成功（只建议测试机） */
int  stealth_task_for_pid_open(krw_ctx *c, int dry);

#endif
