# DNFM（iOS）最终采集报告

> 设备：iPhone 11 Pro（A13）/ iOS 18.6.2 / arm64e / Relaxin 越狱
> 游戏：com.tencent.cdnf《地下城与勇士：起源》130.5.8
> 采集：Frida spawn + il2cpp 反射枚举 + send/recv 钩子 + 框架特征扫描
> 时间：2026-10-28 00:00:31

## 1. 数据规模

| 资产 | 条目 | 文件 |
|---|---|---|
| 类（含程序集前缀） | 54669 行 | dnf_classes.tsv |
| 业务字段（名/偏移/类型） | 62871 行 | dnf_fields.tsv |
| 协议字段（REQ_/RES_/NOTIFY_） | 21950 行 | dnf_proto.tsv |
| 网络帧样本 | 20 条 | frames.jsonl |

## 2. 程序集分布（Top 8）

| 程序集 | 类数 |
|---|---|
| Backend.dll | 25719 |
| Assembly-CSharp.dll | 17216 |
| mscorlib.dll | 1789 |
| UnityEngine.UIElementsModule.dll | 1092 |
| Backend.Common.dll | 1000 |
| System.dll | 877 |
| UnityEngine.CoreModule.dll | 749 |
| System.Xml.dll | 670 |

## 3. 通信协议（实测）

    +0   22 55            魔数 0x2255
    +2   00 02 / 00 01    版本位（上/下行）
    +4   10 01 / 40 01    通道号 + 方向
    +6   00               保留
    +7   XX XX XX XX      长度（小端，含头）
    +11  ...              负载（部分为裸 protobuf）

下行 382 字节样本在偏移 29 处出现裸 protobuf：

    12 17 08 01 10 81 15 18 01 20 01 28 80 80 a0 80 d0 80 80 41 ...

## 4. 检测特征分布（框架扫描）

| 关键词 | 命中框架（前 6） |
|---|---|
| frida | Broadcasting, ESTV, GCloud, GRobot, TTNetworkManager, UnityFramework |
| jailbreak | CrashSight, ESTV, GPM_dylib, enq_transceiver_dy |
| Cydia | Broadcasting, ESTV, GCloud, GCloudCore, UnityFramework |
| substrate | CrashSight, ESTV, GPM_dylib |
| ptrace | ESTV |
| csops | - |
| sysctl | Broadcasting, CrashSight, ESTV, GCloud, GCloudCore, GPM_dylib |
| DYLD_INSERT | enq_transceiver_dy |


重点：网络层风控在 TTNetworkManager，环境/崩溃上报在 CrashSight，
jailbreak/substrate 检测在 GPM_dylib / ESTV，frida 特征在 UnityFramework 与多个腾讯框架里。

## 5. 加密层线索

- CryptoLib 导出 TeaEncrypt/TeaDecrypt、oi_symmetry_encrypt/decrypt、CryptoTool_Cpp::*
- pixuiCurl 导出 22 个 pixui_curl_*（HTTP 走 curl）
- UnityFramework 30,882 符号中无 SSL_*（BoringSSL 静态裁剪）

## 6. 复现命令

    python dnfm_kit.py all        # 一条命令出全套
    python dnfm_kit.py dump       # 只导类/字段/协议表
    python dnfm_kit.py net --sec 60
    python dnfm_kit.py detect

## 7. 结论

- 游戏数据模型已完整落地（类/字段/偏移/类型 + 协议字段表）
- 线上协议为 0x2255 自定义帧 + protobuf，未做整体强加密
- 检测面集中在 5 个框架，可按框架逐项做隐藏与对抗


## 8. 第一帧检测链证据（trace 模式：spawn 挂起时装钩子，恢复即记录）

45 秒共 3842 条事件：

| 类别 | 条数 | 说明 |
|---|---|---|
| NET | 1828 | 网络收发 |
| LOAD | 1196 | dlopen/dlsym |
| DBG | 808 | proc_pidinfo/csops |
| FS | 10 | 可疑文件访问 |

前 2 秒：dlopen 953 次、proc_pidinfo 178 次、dlsym 57 次、csops 7 次。
反作弊的环境扫描与进程枚举在游戏逻辑起来之前就开始了，符合「第一帧即检测」。

启动期访问的游戏资源里出现副本关键字：

- sprite_map_raid_ozma_raid_phase_1_dawn_of_civilization_chapte
- sprite_character_common_aura_73_inuyasha_aura_sesshomaru_aura
- sprite_map_raid_ozma_raid_phase_1_creationary_chapter_backgro
- sprite_map_raid_ozma_raid_phase_1_creationary_chapter_object.
- sprite_map_raid_ozma_raid_phase_1_creationary_chapter_tile.np

其中 sprite_map_raid_ozma_raid_phase_1_* 对应使徒/奥兹玛团队副本资源，是副本专项检测的切入点。

