ifndef PIN_ROOT
$(error "PIN_ROOT is undefined.")
endif

TARGET_OS   := linux
TARGET      := intel64
OBJDIR      := obj-$(TARGET)/

CONFIG_ROOT ?= $(PIN_ROOT)/source/tools/Config

ANALYSIS := cetchecker
TEST_TOOL_ROOTS := $(ANALYSIS)

include $(CONFIG_ROOT)/makefile.config
include $(CONFIG_ROOT)/makefile.default.rules
