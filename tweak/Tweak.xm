/* Tweak.xm — ellekit 注入入口
 * 只在 DNF 进程里启动 agent；其他进程直接返回。
 */
#import <Foundation/Foundation.h>
#import "DnfAgent.h"

static NSString *const kTargets[] = {
	@"com.tencent.dnf",
	@"com.tencent.tmgp.dnf",
	@"com.tencent.dnfm",
	nil
};

%ctor {
	@autoreleasepool {
		NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
		for (int i = 0; kTargets[i]; i++) {
			if ([bid isEqualToString:kTargets[i]]) {
				[[DnfAgent shared] startWithBundleID:bid];
				break;
			}
		}
	}
}
