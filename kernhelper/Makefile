# dnfm-krwd —— 内核读写守护进程（rootless Theos 工程）
THEOS ?= /opt/theos
TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TOOL_NAME = dnfm-krwd
dnfm-krwd_FILES = main.c
dnfm-krwd_CFLAGS = -Wall -O2 -fno-objc-arc
dnfm-krwd_LDFLAGS = -ldl
dnfm-krwd_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk

after-install::
	install.exec "launchctl kickstart -k system/com.xingshu.krwd || true"
