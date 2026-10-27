# Theos tweak（rootless 结构）
THEOS ?= /opt/theos
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DnfAgent
DnfAgent_FILES = Tweak.xm DnfAgent.mm
DnfAgent_CFLAGS = -fobjc-arc -I. -Wall
DnfAgent_FRAMEWORKS = UIKit Foundation
DnfAgent_LDFLAGS = -ldl

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard || true"
