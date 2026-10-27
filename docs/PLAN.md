# DNFM iOS 内核外挂 — 方案与设备事实

## 0. 现在这台机器的真实状态（从 i4Tools 缓存读出来的硬数据）

| 项 | 值 |
|---|---|
| 机型 | iPhone 11 Pro（ProductType iPhone12,3 / HardwareModel D421AP） |
| 芯片 | A13（t8030, arm64e, ChipID 32816, BoardId 6） |
| 系统 | iOS 18.6.2（22G100，iBoot-11881.140.96） |
| UDID | 00008030-0011305A117B802E |
| 序列号 | F17D62T5N6YQ |
| 激活 | Activated / 未越狱（当前无 jailbreakd、无 /var/jb） |
| 连接 | Windows + Apple Mobile Device Support 19.4.0.10 + 爱思助手 9.21.010 |

结论先摆：**A13 + iOS 18.6.2，checkm8 不适用**（checkm8 只打 A5–A11）。要拿到内核态，只有两条路：

1. **越狱（推荐，且你的机器在支持范围内）**：Relaxin 0.5.x 的公开说明里，A12/A13 支持到 iOS 17.4–18.7.1，18.6.2 落在区间内。越狱后由 jailbreakd 提供内核 r/w（libkrw / 内核补丁），我们才能做「内核外挂」。
2. 无越狱：需要 18.6.2 的内核提权链，非公开，不走这条路。

所以工程分两层，**用户态那层在越狱后立刻能用，内核那层依赖越狱给的 r/w 原语**。

## 1. 两层结构

    ┌─────────────────────────────────────────────────────┐
    │ Tweak（ellekit 注入，跑在 DNF 进程内）               │
    │  · il2cpp 反射：类/字段/方法全量枚举 → JSON          │
    │  · SSL_write/SSL_read（BoringSSL）明文 → 环形缓冲    │
    │  · 数据面：角色/怪物/副本状态读取（只读不写）        │
    │  · 检测面：hook 掉本进程里的越狱检测 API             │
    └──────────────────────┬──────────────────────────────┘
                           │ 越狱提供的内核 r/w
    ┌──────────────────────▼──────────────────────────────┐
    │ 内核层（kern/，由 root 守护进程加载执行补丁）        │
    │  · dyld 镜像隐藏：从 dyld_all_image_infos 摘掉我们的 │
    │    dylib，_dyld_image_count 扫描看不见               │
    │  · 进程隐藏：从 allproc 链表摘掉我们的守护进程       │
    │  · task_for_pid 放行：让 root 守护进程拿到游戏 task  │
    │  · 页表挂页：VMA 不可见的 payload 页（进阶）         │
    └─────────────────────────────────────────────────────┘

## 2. 为什么 iOS 的「内核外挂」和安卓那套不一样

- iOS 没有 LKM：内核是 XNU，kext 必须在 boot 时加载，运行时只能**打内核补丁 / 改数据结构**。
- 所以 iOS 的「内核外挂」= **内核 r/w + 数据结构和函数补丁**，不是写 ko。
- 越狱已经给了你内核 r/w（libkrw 一族），我们要做的是：**用这份 r/w 去改那些用户态改不到的东西**（dyld 镜像表、allproc、task 端口策略）。

## 3. 检测链（iOS 侧，ACE 会看的）

| # | 检测点 | ACE 怎么查 | 我们怎么绕 |
|---|---|---|---|
| I1 | 越狱痕迹 | /var/jb、/bin/bash、Cydia、jailbreakd、apt | 内核文件隐藏 / 进程内 stat hook |
| I2 | 注入 dylib | _dyld_image_count 遍历，比对白名单 | 内核摘链（kern/stealth.c:dylib_hide） |
| I3 | 调试 | sysctl KERN_PROC_PID 的 P_TRACED、csops | 内核清 flag / 进程内 hook sysctl |
| I4 | 代码完整性 | __TEXT CRC、codesign 校验 | 只做数据面 GOT 打点，不改 __TEXT |
| I5 | hook 痕迹 | 扫函数头 B/BR 指令 | 只用 GOT/data 打点，不做 inline hook |
| I6 | 环境变量 | DYLD_INSERT_LIBRARIES、DYLD_FORCE_FLAT_NAMESPACE | 不清环境，改用 ellekit 注入（不写 env） |
| I7 | 进程列表 | sysctl KERN_PROC_ALL 找可疑进程 | 守护进程摘 allproc |
| I8 | 端口 | 9000/27042、Frida 特征 | 不用 Frida，走注入式 tweak |
| I9 | 页表扫描 | 有 PTE 无 VM 映射 | 进阶页表挂页，或者干脆不挂页 |
| I10 | 上报一致性 | 设备指纹 / 完整性上报 | 只读采集，不对抗上报内容 |

## 4. 交付物

    dnfm-ios/
    ├── kern/krw.h/.c        内核读写抽象（libkrw / 用户提供后端）
    ├── kern/stealth.h/.c    内核补丁：dyld 镜像摘链、allproc 摘链、task_for_pid 放行
    ├── tweak/Tweak.xm       Theos 工程入口（进程内 agent）
    ├── tweak/DnfAgent.mm    il2cpp 枚举 + SSL 明文 + 检测 API hook
    ├── docs/BUILD.md        Windows→WSL→Theos 构建与安装
    └── docs/PLAN.md         本文件

## 5. 前置条件（缺一不可）

1. 手机先越狱（Relaxin 或同代 A13/18.x 方案），装 openssh、ellekit。
2. 电脑侧编译：Windows 用 WSL2 Ubuntu 装 Theos（见 BUILD.md）。
3. 装包：SSH over USB（iproxy 22）或直接 usbmuxd + iproxy，或 Sileo 本地源。
4. 游戏 bundle id 先确认（越狱后 `ps -A | grep -i dnf` 或 `ls /var/containers/Bundle/Application/*/*.app`）。

## 6. 风险边界（心里有数）

- 内核补丁每次改动都可能 panic：所有函数都先验证原始字节再写，写前打印，panic 后重启即可恢复。
- 越狱本身是最显眼的检测项；内核层只能隐藏我们自己的东西，藏不住 jailbreakd 全貌。
- iOS 18.x 的 kernelcache 符号名与偏移随版本变，offsets 必须现场生成，不能写死。
