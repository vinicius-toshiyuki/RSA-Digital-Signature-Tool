EXEC_NAME := rsa
BUILD_DIR := build
SRC_DIR := src
DEP_DIR := $(BUILD_DIR)/.deps
OBJ_DIR := $(BUILD_DIR)/.objs

SRCS := $(shell find $(SRC_DIR) -name '*.c')
MAKE_DIR = @mkdir -p $(@D)
DEL_FILES = $(RM) *~ $(OBJS) $(DEPS) $(EXEC)
EXEC := $(EXEC_NAME).out

OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS := $(SRCS:$(SRC_DIR)/%.c=$(DEP_DIR)/%.d)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$*.d
CXX := gcc
INCLUDES := -I"include/"
CXXFLAGS := -std=c99
CFLAGS := -g -Wall -pedantic -Wpedantic -Werror
LINKER_FLAGS := -lgmp

.PHONY: all clean docs

all: $(EXEC)

$(EXEC): $(OBJS)
	@echo Generating executable $@
	@$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -o $@ $(LINKER_FLAGS)

$(DEP_DIR)/%.d: $(SRC_DIR)/%.c
	@$(MAKE_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEP_DIR)/%.d
	@$(MAKE_DIR)
	@echo Compiling $<
	@$(CXX) -c $< $(DEPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -o $@

$(DEPS):
include $(wildcard $(DEPS))

clean:
	@$(DEL_FILES)

fix:
	@clang-format -style=google -dump-config > .clang-format
	@echo Formatting src/ and include/
	@./formatter $(SRC_DIR) && ./formatter include/
	@rm ./.clang-format

docs:
	doxygen ./Doxyfile

-include $(wildcard $(DEPS))
