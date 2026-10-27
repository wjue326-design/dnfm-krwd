THEOS ?= /opt/theos
TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = krwtweak
krwtweak_FILES = krwtweak.c
krwtweak_CFLAGS = -Wall -O2 -fno-objc-arc
krwtweak_LDFLAGS = -lpthread

include $(THEOS_MAKE_PATH)/tweak.mk
