# DNFM（iOS）运行时数据报告 — il2cpp 元数据实证

> 设备：iPhone 11 Pro / iOS 18.6.2 / Relaxin 越狱 / com.tencent.cdnf 130.5.8
> 采集：Frida spawn + il2cpp 反射 API 全量枚举（UnityFramework）

## 1. 总量

| 指标 | 数值 |
|---|---|
| 程序集/镜像 | 86 |
| 唯一类 | 40131 |
| 有字段的类（过滤后） | 8860 |
| 字段行 | 69251 |
| 协议类 | 2301 |
| 协议字段 | 21950 |

## 2. 程序集分布（Top 15）

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
| System.Core.dll | 666 |
| Unity.InputSystem.dll | 632 |
| QCloud.COS.dll | 433 |
| MoonSharp.Interpreter.dll | 376 |
| PixUI.dll | 375 |
| Newtonsoft.Json.dll | 306 |
| System.Data.dll | 238 |

## 3. 协议层

协议由 Google.Protobuf 生成：

- REQ_* 上行请求：6168 字段
- RES_* 下行响应：11372 字段
- NOTIFY_* 推送：1644 字段
- 每个类都带 _parser / _unknownFields（protobuf 标准字段），标准 wire format，可直接用 net/proto_dump.py 解析

### 3.1 典型类字段表

**REQ_ENTER_CHANNEL**（24 个字段）

| 字段名 | 类型 |
|---|---|
| _parser | Google.Protobuf.MessageParser<REQ_ENTER_CHANNEL> |
| _unknownFields | Google.Protobuf.UnknownFieldSet |
| openidFieldNumber | System.Int32 |
| openid_ | System.String |
| charguidFieldNumber | System.Int32 |
| charguid_ | System.UInt64 |
| authkeyFieldNumber | System.Int32 |
| authkey_ | System.String |
| versionFieldNumber | System.Int32 |
| version_ | System.String |
| accesstokenFieldNumber | System.Int32 |
| accesstoken_ | System.String |
| launchinfoFieldNumber | System.Int32 |
| launchinfo_ | System.Int32 |
| dungeonguidFieldNumber | System.Int32 |
| dungeonguid_ | System.UInt64 |
| deviceinfoFieldNumber | System.Int32 |
| deviceinfo_ | PT_CLIENTINFO |
| registeredchannelidFieldNumber | System.Int32 |
| registeredchannelid_ | System.String |
| installchannelidFieldNumber | System.Int32 |
| installchannelid_ | System.String |
| isexternpackageFieldNumber | System.Int32 |
| isexternpackage_ | System.Boolean |

**RES_ENTER_CHANNEL**（59 个字段）

| 字段名 | 类型 |
|---|---|
| _parser | Google.Protobuf.MessageParser<RES_ENTER_CHANNEL> |
| _unknownFields | Google.Protobuf.UnknownFieldSet |
| errorFieldNumber | System.Int32 |
| error_ | System.Int32 |
| standbyFieldNumber | System.Int32 |
| standby_ | System.Int32 |
| encryptFieldNumber | System.Int32 |
| encrypt_ | System.Boolean |
| servertimeFieldNumber | System.Int32 |
| servertime_ | System.UInt64 |
| authkeyFieldNumber | System.Int32 |
| authkey_ | System.String |
| launchinfoFieldNumber | System.Int32 |
| launchinfo_ | System.Int32 |
| vipFieldNumber | System.Int32 |
| vip_ | System.Int32 |
| checkupFieldNumber | System.Int32 |
| checkup_ | System.Int32 |
| checkuptypeFieldNumber | System.Int32 |
| checkuptype_ | System.Int32 |
| keyFieldNumber | System.Int32 |
| key_ | System.String |
| roxytutorialFieldNumber | System.Int32 |
| roxytutorial_ | System.Int32 |
| gamecenterregdateFieldNumber | System.Int32 |
| gamecenterregdate_ | System.Int64 |
| areatypeFieldNumber | System.Int32 |
| areatype_ | System.Int32 |
| channelinfoFieldNumber | System.Int32 |
| channelinfo_ | PT_CHANNEL |
| platformauthtypeFieldNumber | System.Int32 |
| platformauthtype_ | System.Int32 |
| bannersFieldNumber | System.Int32 |
| _repeated_banners_codec | Google.Protobuf.FieldCodec<PT_CONTENTS_BANNER> |
| banners_ | Google.Protobuf.Collections.RepeatedField<PT_CONTENTS_BANNER> |
| fatiguehelpinfoFieldNumber | System.Int32 |
| fatiguehelpinfo_ | PT_FATIGUE_HELP_INFO |
| event_select_infosFieldNumber | System.Int32 |
| eventSelectInfos_ | PT_EVENT_SELECT_INFOS |
| seedsFieldNumber | System.Int32 |

**REQ_LOGIN**（18 个字段）

| 字段名 | 类型 |
|---|---|
| _parser | Google.Protobuf.MessageParser<REQ_LOGIN> |
| _unknownFields | Google.Protobuf.UnknownFieldSet |
| openidFieldNumber | System.Int32 |
| openid_ | System.String |
| typeFieldNumber | System.Int32 |
| type_ | System.UInt32 |
| tokenFieldNumber | System.Int32 |
| token_ | System.String |
| platIDFieldNumber | System.Int32 |
| platID_ | System.UInt32 |
| clientIPFieldNumber | System.Int32 |
| clientIP_ | System.String |
| versionFieldNumber | System.Int32 |
| version_ | System.String |
| friendopenidFieldNumber | System.Int32 |
| friendopenid_ | System.String |
| cancelunregistFieldNumber | System.Int32 |
| cancelunregist_ | System.UInt32 |

**RES_LOGIN**（32 个字段）

| 字段名 | 类型 |
|---|---|
| _parser | Google.Protobuf.MessageParser<RES_LOGIN> |
| _unknownFields | Google.Protobuf.UnknownFieldSet |
| errorFieldNumber | System.Int32 |
| error_ | System.Int32 |
| authkeyFieldNumber | System.Int32 |
| authkey_ | System.String |
| accountkeyFieldNumber | System.Int32 |
| accountkey_ | System.String |
| encryptFieldNumber | System.Int32 |
| encrypt_ | System.Boolean |
| servertimeFieldNumber | System.Int32 |
| servertime_ | System.UInt64 |
| localtimeFieldNumber | System.Int32 |
| localtime_ | System.String |
| authorityFieldNumber | System.Int32 |
| authority_ | System.UInt32 |
| keyFieldNumber | System.Int32 |
| key_ | System.String |
| channelFieldNumber | System.Int32 |
| _repeated_channel_codec | Google.Protobuf.FieldCodec<PT_CHANNEL_INFO> |
| channel_ | Google.Protobuf.Collections.RepeatedField<PT_CHANNEL_INFO> |
| intrudeinfoFieldNumber | System.Int32 |
| intrudeinfo_ | PT_INTRUDE_INFO |
| worldidFieldNumber | System.Int32 |
| worldid_ | System.Int32 |
| seedsFieldNumber | System.Int32 |
| _repeated_seeds_codec | Google.Protobuf.FieldCodec<System.Int32> |
| seeds_ | Google.Protobuf.Collections.RepeatedField<System.Int32> |
| pandora_asyncmodeFieldNumber | System.Int32 |
| pandoraAsyncmode_ | System.Boolean |
| viewOptionFieldNumber | System.Int32 |
| viewOption_ | System.Boolean |

## 4. 命名混淆

业务层大量字段名为 14 字符混淆串（如 efdgehfcbhdcacg），但：

- 协议层字段名真实可读（protobuf 生成器保留）
- 混淆只影响 C# 业务类，不影响按偏移读写
- 混淆串+偏移已一并 dump，可建字段指纹表做版本对比

## 5. 数据文件

| 文件 | 内容 | 大小 |
|---|---|---|
| dnf_classes.tsv | 程序集 / 命名空间::类名（全量） | 2181.0 KB |
| dnf_fields.tsv | 类 / 字段 / 偏移 / 类型（关键词过滤） | 4892.3 KB |
| dnf_proto.tsv | F/M 行：协议类字段与方法 | 1814.7 KB |

## 6. 下一步

1. SSL 明文：UnityFramework 未导出 SSL_*，需在 PixUI_Unity / pixuiCurl 定位 BoringSSL，或 hook send/recv 配合 keylog。
2. 内核层：libkrw 在应用沙盒内 dlopen 被拒，需要 root 侧工具 dnfkern 或非沙盒进程承载。
3. 上报层：从 REQ_* 里筛 Report/Risk/Device 类，配 TLS 明文补全上报链。
4. 副本专项：筛 Dungeon/Raid/Boss（四维、罗特斯）对应包做时间线。
