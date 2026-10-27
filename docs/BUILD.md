# Windows 上构建与安装（iPhone 11 Pro / iOS 18.6.2）

## 1. 越狱（手机侧）

- Relaxin 0.5.x：公开说明支持 A12/A13 到 iOS 18.7.1，18.6.2 在范围内。
- 越狱后装：OpenSSH、ellekit（或 Substitute）、PreferenceLoader。
- 验证：SSH 进去 `whoami` 是 root，`ls /var/jb` 存在（rootless 结构）。

## 2. 编译环境（电脑侧）

Windows 没有 iOS 工具链，走 WSL2：

    wsl --install -d Ubuntu-22.04
    # Ubuntu 内：
    sudo apt update && sudo apt install -y git make perl clang ldid curl
    git clone --recursive https://github.com/theos/theos.git ~/theos
    export THEOS=~/theos
    echo 'export THEOS=~/theos' >> ~/.bashrc
    # SDK：
    git clone https://github.com/theos/sdks ~/theos/sdks

工程目录可以直接用 /mnt/d/dsh/dnfm-ios。

## 3. 构建

    cd /mnt/d/dsh/dnfm-ios/tweak
    make clean package
    # 产物：packages/com.xingshu.dnfagent_0.1.0_iphoneos-arm64.deb

## 4. 安装（三种，任选）

1. SSH（USB 转发）：
   - Windows 装 libimobiledevice 的 iproxy，或越狱后用手机自身 SSH。
   - `iproxy 2222 22` 然后 `scp -P 2222 packages/*.deb root@127.0.0.1:/tmp/`
   - `ssh -p 2222 root@127.0.0.1 'dpkg -i /tmp/*.deb && killall -9 SpringBoard'`
2. Sileo 本地源：把 deb 丢进一个静态目录，手机 Sileo 添加 file:// 源。
3. Filza 直接点 deb 安装。

## 5. 内核层跑法

内核补丁不是 dylib，需要一个 root 守护进程执行：

    # 把编译好的 dnfkern 二进制 + offsets.json 丢到 /var/jb/usr/bin/
    launchctl load /Library/LaunchDaemons/com.xingshu.dnfkern.plist

它做三件事（按顺序）：
1. 从 libkrw 拿内核 r/w（失败则退出，不 panic）。
2. 解析 offsets.json（kbase/symbol 偏移）。
3. dyld 摘链 + allproc 摘链 + task_for_pid 放行，然后常驻。

## 6. 验证顺序

    # 1) 越狱与内核 r/w
    dnfkern --probe
    # 2) dyld 隐藏
    dnfkern --hide-dylib /var/jb/usr/lib/libdnfagent.dylib
    # 3) tweak 是否注入
    tail -f /var/mobile/Library/Logs/dnfagent.log
    # 4) 游戏侧数据
    cat /var/mobile/Containers/Data/Application/.../Documents/dnf_schema.json
