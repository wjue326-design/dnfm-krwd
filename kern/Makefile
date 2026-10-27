# dnfkern 交叉编译（Theos 工具链或 macOS clang）
THEOS ?= /opt/theos
include $(THEOS)/makefiles/common.mk

TOOL_NAME = dnfkern
dnfkern_FILES = dnfkern.c krw.c stealth.c
dnfkern_CFLAGS = -I. -Wall -Wno-unused-parameter -fobjc-arc
dnfkern_LDFLAGS = -ldl
dnfkern_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk
