TARGET = iphone:clang:latest:15.0
ARCHS = arm64
INSTALL_TARGET_PROCESSES = BetaScreenTYMDESUJCX8TAgent BetaScreenTYMDESUJCX8T

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bs_unlock
bs_unlock_FILES = Tweak.xm BSNet.xm BSSync.xm BSCore.xm fishhook.c
bs_unlock_CFLAGS = -fobjc-arc -w
bs_unlock_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
