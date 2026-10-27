# DNFM（iOS）采集报告

- 设备：iPhone 11 Pro / iOS 18.6.2 / arm64e
- 游戏：com.tencent.cdnf 130.5.8
- 时间：2026-10-27 23:54:06

## 类表

- 文件：dnf_classes.tsv（0 行，0.0 KB）

## 业务字段

- 文件：dnf_fields.tsv（0 行，0.0 KB）

## 协议字段

- 文件：dnf_proto.tsv（0 行，0.0 KB）

## 网络帧

- 帧数：20（out 0 / in 20）
- 魔数：0x2255，版本位/通道号见 frames.jsonl

## 检测特征分布

| 关键词 | 命中框架 |
|---|---|
| frida | Broadcasting, ESTV, GCloud, GRobot, TTNetworkManager, UnityFramework |
| jailbreak | CrashSight, ESTV, GPM_dylib, enq_transceiver_dy |
| Cydia | Broadcasting, ESTV, GCloud, GCloudCore, UnityFramework |
| substrate | CrashSight, ESTV, GPM_dylib |
| ptrace | ESTV |
| csops | - |
| sysctl | Broadcasting, CrashSight, ESTV, GCloud, GCloudCore, GPM_dylib |
| DYLD_INSERT | enq_transceiver_dy |

