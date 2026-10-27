/* DnfAgent.h */
#import <Foundation/Foundation.h>

@interface DnfAgent : NSObject
+ (instancetype)shared;
- (void)startWithBundleID:(NSString *)bundleID;
@end
