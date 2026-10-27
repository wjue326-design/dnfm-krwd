# dnfm-ios — DNFM（iOS）内核态采集/外挂框架

目标设备（实测读出来的）：**iPhone 11 Pro / A13 / iOS 18.6.2 / arm64e / UDID 00008030-0011305A117B802E**。

## 为什么要走内核

- iOS 没有 LKM，kext 只能开机加载 → 运行时的「内核外挂」= **内核 r/w + 数据结构/函数补丁**。
- A13 不适用 checkm8，18.6.2 也没有公开内核提权 → **必须先越狱**（Relaxin 一代，A12/A13 支持到 18.7.1）。
- 越狱提供内核 r/w（libkrw 一族）后，本工程负责：把我们的痕迹从内核视角抹掉 + 给进程内 agent 铺路。

## 目录

    kern/krw.[ch]        内核 r/w 抽象（自动找 libkrw / 自备 shim）
    kern/stealth.[ch]    dyld 镜像摘链 / allproc 摘链 / task_for_pid 放行（全部先校验原字节）
    kern/dnfkern.c       补丁执行器（root 守护进程）
    kern/offsets.example.conf  结构体偏移模板（按版本填）
    tweak/               Theos 工程：进程内 agent（il2cpp 枚举 + SSL 明文 + 检测采样）
    docs/PLAN.md         设备事实、路线、检测链、风险
    docs/BUILD.md        Windows → WSL → Theos 构建与安装

## 三分钟流程

    # 1. 手机越狱（Relaxin），装 OpenSSH + ellekit
    # 2. WSL 里编译
    cd tweak && make package
    cd ../kern && make
    # 3. 装
    scp -P 2222 tweak/packages/*.deb root@127.0.0.1:/tmp/
    ssh -P 2222 root@127.0.0.1 'dpkg -i /tmp/*.deb && killall -9 SpringBoard'
    # 4. 内核层
    scp kern/dnfkern kern/offsets.conf root@127.0.0.1:/var/jb/usr/bin/
    ssh root@127.0.0.1 'dnfkern --probe'
    ssh root@127.0.0.1 'dnfkern --hide-dylib /var/jb/usr/lib/libDnfAgent.dylib --dry'
    ssh root@127.0.0.1 'dnfkern --hide-dylib /var/jb/usr/lib/libDnfAgent.dylib'

## 数据产物（游戏沙盒 Documents 下）

- dnf_schema.json：全部类/字段/方法（il2cpp 反射现枚举）
- dnf_api.bin：SSL 明文流（O + len + data / I + len + data）
- dnfagent.log：越狱痕迹采样、hook 状态

## 还没有的东西（下一步）

- UnityFramework 里 BoringSSL 是静态链接时，dlsym("SSL_write") 拿不到 → 需要加 Mach-O 符号扫描 + inline hook（或内核侧读 SSL 会话密钥）。
- offsets 必须按 18.6.2 的 kernelcache 填，模板已给，填错会 panic（所有补丁先校验原字节）。
- 本机没有 Xcode/Theos，编译在 WSL 里做，见 docs/BUILD.md。
