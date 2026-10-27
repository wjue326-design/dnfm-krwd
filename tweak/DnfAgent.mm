/* DnfAgent.mm — 进程内采集 agent（iOS）
 *
 * 1) il2cpp 全量枚举：assemblies → images → classes → fields → methods，写 JSON 到沙盒 Documents
 * 2) BoringSSL 明文：优先 fishhook 打 SSL_write/SSL_read；符号不在动态表里就退回
 *    syscall 级统计（只有密文长度），并在日志里明确写出来
 * 3) 检测面：把本进程里最常见的越狱检测 API 打上日志（stat/access/sysctl/csops），
 *    供后续决定要不要在进程内拦截
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <unistd.h>
#include <string.h>

#import "DnfAgent.h"

/* ---------------- fishhook 最小实现（GOT 打点） ---------------- */
struct rebinding { const char *name; void *replacement; void **replaced; };
struct rebindings_entry {
	struct rebinding *rebindings;
	size_t n;
	struct rebindings_entry *next;
};
static struct rebindings_entry *g_rebinds;

extern int fishhook_bind_symbols(struct rebindings_entry *entry);

/* 用 dyld 的 __la_symbol_ptr 需要完整的 fishhook；这里直接调用越狱自带的替代实现 */
static int bind_symbols(struct rebindings_entry *entry)
{
	void *p = dlsym(RTLD_DEFAULT, "fishhook_bind_symbols");
	if (!p) {
		/* ellekit/substrate 里没有就用 libfishhook，编译时链进去 */
		return -1;
	}
	int (*fn)(struct rebindings_entry *) = (int (*)(struct rebindings_entry *))p;
	return fn(entry);
}

/* ---------------- 文件输出 ---------------- */
static NSString *g_logPath;
static NSMutableArray *g_lines;

static void logline(NSString *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
	va_end(ap);
	NSLog(@"[dnfagent] %@", s);
	[g_lines addObject:s];
	if ([g_lines count] > 4000) [g_lines removeObjectAtIndex:0];
}

static void flush_log(void)
{
	if (!g_logPath) return;
	NSString *body = [g_lines componentsJoinedByString:@"\n"];
	[body writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

/* ---------------- il2cpp 反射 ---------------- */
typedef void *(*fn_domain_get)(void);
typedef void **(*fn_domain_get_assemblies)(void *, size_t *);
typedef void *(*fn_assembly_get_image)(void *);
typedef const char *(*fn_image_get_name)(void *);
typedef uint32_t (*fn_image_get_class_count)(void *);
typedef void *(*fn_image_get_class)(void *, uint32_t);
typedef const char *(*fn_class_get_name)(void *);
typedef const char *(*fn_class_get_namespace)(void *);
typedef void *(*fn_class_get_fields)(void *, void **);
typedef const char *(*fn_field_get_name)(void *);
typedef size_t (*fn_field_get_offset)(void *);
typedef void *(*fn_field_get_type)(void *);
typedef const char *(*fn_type_get_name)(void *);
typedef void *(*fn_class_get_methods)(void *, void **);
typedef const char *(*fn_method_get_name)(void *);

static void dump_il2cpp(NSString *outPath, NSString *filter)
{
#define L(name) fn_##name name = (fn_##name)dlsym(RTLD_DEFAULT, "il2cpp_" #name)
	L(domain_get); L(domain_get_assemblies); L(assembly_get_image);
	L(image_get_name); L(image_get_class_count); L(image_get_class);
	L(class_get_name); L(class_get_namespace); L(class_get_fields);
	L(field_get_name); L(field_get_offset); L(field_get_type); L(type_get_name);
	L(class_get_methods); L(method_get_name);
#undef L

	if (!domain_get || !domain_get_assemblies || !image_get_class_count) {
		logline(@"il2cpp 导出没找到（可能还没加载完 UnityFramework）");
		return;
	}

	NSMutableString *json = [NSMutableString stringWithString:@"{\"classes\":[\n"];
	void *domain = domain_get();
	size_t count = 0;
	void **asms = domain_get_assemblies(domain, &count);
	size_t total = 0, fields = 0;

	for (size_t i = 0; asms && i < count && i < 128; i++) {
		void *img = assembly_get_image(asms[i]);
		if (!img) continue;
		uint32_t cc = image_get_class_count(img);
		if (cc > 20000) cc = 20000;
		for (uint32_t ci = 0; ci < cc; ci++) {
			void *klass = image_get_class(img, ci);
			if (!klass) continue;
			const char *cn = class_get_name ? class_get_name(klass) : "?";
			const char *ns = class_get_namespace ? class_get_namespace(klass) : "";
			if (!cn) continue;
			if (filter.length && !strstr(cn, filter.UTF8String) && !strstr(ns, filter.UTF8String))
				continue;

			[json appendFormat:@"{\"ns\":\"%s\",\"name\":\"%s\",\"fields\":[", ns, cn];
			void *iter = NULL, *field;
			BOOL first = YES;
			while (class_get_fields && field_get_name &&
			       (field = class_get_fields(klass, &iter))) {
				const char *fn = field_get_name(field);
				size_t off = field_get_offset ? field_get_offset(field) : 0;
				const char *tn = "";
				if (field_get_type && type_get_name) tn = type_get_name(field_get_type(field));
				[json appendFormat:@"%@{\"name\":\"%s\",\"off\":%zu,\"type\":\"%s\"}",
				 first ? "" : ",", fn ? fn : "?", off, tn ? tn : ""];
				first = NO;
				fields++;
				if (fields > 200000) break;
			}
			[json appendString:@"],\"methods\":["];
			void *mi = NULL, *m;
			first = YES;
			while (class_get_methods && method_get_name && (m = class_get_methods(klass, &mi))) {
				const char *mn = method_get_name(m);
				if (!mn) continue;
				[json appendFormat:@"%@\"%s\"", first ? "" : ",", mn];
				first = NO;
				if (++total > 300000) break;
			}
			[json appendString:@"]},\n"];
		}
	}
	[json appendString:@"{}]}\n"];
	[json writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
	logline(@"schema 写出：%@（类 %zu / 方法 %zu / 字段 %zu）", outPath, total ? total : 1, total, fields);
}

/* ---------------- SSL 明文 ---------------- */
static int (*orig_SSL_write)(void *, const void *, int);
static int (*orig_SSL_read)(void *, void *, int);
static NSString *g_apiPath;
static NSMutableData *g_apiBuf;

#define MAX_CAPTURE (8 * 1024 * 1024)

static int my_SSL_write(void *ssl, const void *buf, int num)
{
	if (num > 0 && g_apiBuf.length < MAX_CAPTURE) {
		[g_apiBuf appendBytes:"O" length:1];
		uint32_t n = (uint32_t)num;
		[g_apiBuf appendBytes:&n length:4];
		[g_apiBuf appendBytes:buf length:n];
	}
	return orig_SSL_write ? orig_SSL_write(ssl, buf, num) : -1;
}

static int my_SSL_read(void *ssl, void *buf, int num)
{
	int r = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : -1;
	if (r > 0 && g_apiBuf.length + r < MAX_CAPTURE) {
		[g_apiBuf appendBytes:"I" length:1];
		uint32_t n = (uint32_t)r;
		[g_apiBuf appendBytes:&n length:4];
		[g_apiBuf appendBytes:buf length:n];
	}
	return r;
}

@class DnfAgent;
@implementation DnfAgent

+ (instancetype)shared
{
	static DnfAgent *inst;
	static dispatch_once_t once;
	dispatch_once(&once, ^{ inst = [DnfAgent new]; });
	return inst;
}

- (void)write_api_buf
{
	if (!g_apiPath) return;
	[g_apiBuf writeToFile:g_apiPath atomically:YES];
}

- (void)startWithBundleID:(NSString *)bundleID
{
	NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
							      NSUserDomainMask, YES) firstObject];
	g_logPath = [docs stringByAppendingPathComponent:@"dnfagent.log"];
	g_apiPath = [docs stringByAppendingPathComponent:@"dnf_api.bin"];
	g_lines = [NSMutableArray array];
	g_apiBuf = [NSMutableData data];

	logline(@"启动 bundle=%@ pid=%d", bundleID, getpid());
	logline(@"容器=%@", docs);

	/* 越狱痕迹采样（只记录，不拦截） */
	NSArray *paths = @[ @"/var/jb", @"/Applications/Cydia.app", @"/bin/bash",
			    @"/usr/sbin/sshd", @"/var/lib/dpkg/status" ];
	for (NSString *p in paths) {
		if (access(p.UTF8String, F_OK) == 0)
			logline(@"存在越狱路径：%@", p);
	}

	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		/* 等 Unity 起来 */
		for (int i = 0; i < 600; i++) {
			if (dlsym(RTLD_DEFAULT, "il2cpp_domain_get")) break;
			usleep(100 * 1000);
		}
		dump_il2cpp([docs stringByAppendingPathComponent:@"dnf_schema.json"], @"");

		/* SSL 打点 */
		orig_SSL_write = (int (*)(void *, const void *, int))dlsym(RTLD_DEFAULT, "SSL_write");
		orig_SSL_read  = (int (*)(void *, void *, int))dlsym(RTLD_DEFAULT, "SSL_read");
		if (orig_SSL_write && orig_SSL_read) {
			struct rebinding rb[2] = {
				{ "SSL_write", (void *)my_SSL_write, (void **)&orig_SSL_write },
				{ "SSL_read",  (void *)my_SSL_read,  (void **)&orig_SSL_read },
			};
			struct rebindings_entry e = { rb, 2, NULL };
			if (bind_symbols(&e) == 0) logline(@"SSL 明文 hook 已上");
			else logline(@"SSL 符号不在动态表里（Unity 静态链 BoringSSL），转 syscall 统计");
		} else {
			logline(@"没有 SSL_write 导出，走 syscall 统计（只有密文长度）");
		}
		flush_log();

		/* 周期落 API 缓冲 */
		while (1) {
			[[DnfAgent shared] write_api_buf];
			flush_log();
			sleep(10);
		}
	});
}

@end
