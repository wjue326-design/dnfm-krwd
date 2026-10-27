/* dnfkern — 内核补丁执行器（root 守护进程）
 *
 * 用法：
 *   dnfkern --probe
 *   dnfkern --hide-dylib /var/jb/usr/lib/libdnfagent.dylib [--dry]
 *   dnfkern --hide-proc <pid> [--dry]
 *   dnfkern --tfpid [--dry]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "krw.h"
#include "stealth.h"

static void usage(void)
{
	printf("dnfkern --probe | --hide-dylib PATH | --hide-proc PID | --tfpid [--dry]\n"
	       "         [--offsets /var/jb/etc/dnfkern/offsets.conf]\n");
}

static uint64_t infos_va_from_userland(void)
{
	/* dyld 的 public API，拿到共享区里的 dyld_all_image_infos 地址 */
	void *p = NULL;
	uint64_t v = 0;
	/* _dyld_get_all_image_infos 在 libdyld 里，符号存在 */
	p = dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
	if (p) {
		uint64_t (*fn)(void) = (uint64_t (*)(void))p;
		v = fn();
	}
	return v;
}

int main(int argc, char **argv)
{
	krw_ctx c;
	struct kern_offsets o;
	const char *offs = "/var/jb/etc/dnfkern/offsets.conf";
	const char *dylib = NULL;
	int dry = 0, pid = 0, do_probe = 0, do_tfpid = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dry")) dry = 1;
		else if (!strcmp(argv[i], "--probe")) do_probe = 1;
		else if (!strcmp(argv[i], "--tfpid")) do_tfpid = 1;
		else if (!strcmp(argv[i], "--hide-dylib") && i + 1 < argc) dylib = argv[++i];
		else if (!strcmp(argv[i], "--hide-proc") && i + 1 < argc) pid = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--offsets") && i + 1 < argc) offs = argv[++i];
	}
	if (argc == 1) { usage(); return 1; }

	memset(&o, 0, sizeof(o));
	if (krw_init(&c) != 0) return 1;
	if (do_probe) {
		printf("[probe] kernel r/w 正常，kbase=0x%llx\n", (unsigned long long)c.kbase);
		krw_close(&c);
		return 0;
	}
	if (offsets_load(offs, &o) != 0) { krw_close(&c); return 1; }

	if (dylib) {
		uint64_t infos = infos_va_from_userland();
		if (!infos) {
			fprintf(stderr, "[dyld] 拿不到 dyld_all_image_infos 地址\n");
		} else if (stealth_hide_dylib(&c, &o, infos, dylib, dry) != 0) {
			fprintf(stderr, "[dyld] 失败\n");
		}
	}
	if (pid > 0) {
		uint64_t allproc = krw_sym(&c, "allproc");
		if (stealth_hide_proc(&c, &o, allproc, pid, dry) != 0)
			fprintf(stderr, "[proc] 失败\n");
	}
	if (do_tfpid) {
		if (stealth_task_for_pid_open(&c, dry) != 0)
			fprintf(stderr, "[tfpid] 失败\n");
	}

	krw_close(&c);
	return 0;
}
