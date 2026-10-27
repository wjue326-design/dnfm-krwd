# dnfm-krwd —— 内核读写守护进程（Theos 工程）

## 作用

越狱手机上的 libkrw 只能在 jbroot 上下文 + 已签名的进程里加载。本守护进程由 launchd 以 root 拉起，
加载 libkrw，在 127.0.0.1:27050 提供 kbase / kread / kwrite RPC，PC 端走 SSH 隧道调用。

打通后即可做真正的内核读写：读内核结构、改页表、隐藏进程/镜像、放行 task_for_pid。

## 构建

    export THEOS=~/theos
    cd kernhelper
    make package
    # 产物 packages/com.xingshu.dnfm-krwd_0.1.0_iphoneos-arm64.deb

## 安装

    scp -P 2222 packages/*.deb root@127.0.0.1:/tmp/
    ssh -P 2222 root@127.0.0.1 'dpkg -i /tmp/*.deb && launchctl bootstrap system /Library/LaunchDaemons/com.xingshu.krwd.plist'

rootless 结构下实际路径是 /var/jb/Library/LaunchDaemons/，Theos 的 layout 会自动放对。

## 验证

    python krw_client.py ping      # 返回 backend 路径 = libkrw 加载成功
    python krw_client.py kbase     # 返回内核基址 = 内核通道打通
    python krw_client.py read 0xfffffff007004000 16

## 原理

    launchd(root, jbroot) -> dnfm-krwd -> dlopen libkrw.0.dylib
                                 |
                                 +-> 127.0.0.1:27050 --SSH 隧道--> PC(krw_client.py)

## 内核层能改什么（打通之后）

| 能力 | 实现方式 | 用途 |
|---|---|---|
| kbase/kread/kwrite | libkrw 原语 | 读内核结构、找 task/proc |
| dyld 镜像摘链 | 改 dyld_all_image_infos 的 count/array | _dyld_image_count 看不到注入库 |
| allproc 摘链 | 改内核 proc 链表 | sysctl KERN_PROC 看不到守护进程 |
| task_for_pid 放行 | 打内核函数 | root 进程直接拿游戏 task 端口 |
| 页表挂页 | 改 PTE（无 VMA） | 注入页在 maps 里不可见 |
| 越狱痕迹隐藏 | 改 vnode/路径可见性 | 屏蔽 /var/jb 等路径 |

## 注意

- libkrw 各版本符号名不同，main.c 已做 kread/kreadbuf/krw_read 多路探测。
- 守护进程只监听 127.0.0.1，必须走 SSH 隧道，不要改成 0.0.0.0。
- 内核写之前先 kread 校验原字节（模板里留了接口）。

## 云端构建（不用本地 Theos）

仓库推到 GitHub 后，Actions 自动跑 .github/workflows/build-kernhelper.yml：

1. 以 dnfm-ios 为仓库根（.github 与 kernhelper 同级）
2. push 上去，Actions 里选 Build dnfm-krwd
3. 跑完在 Artifacts 下载 dnfm-krwd-deb，解压得到 com.xingshu.dnfm-krwd_0.1.0_iphoneos-arm64.deb
4. scp 到手机，dpkg -i，launchctl bootstrap 拉起

本地推送：

    git init && git add . && git commit -m kernhelper
    git remote add origin git@github.com:<你的账号>/dnfm-krwd.git
    git push -u origin main

