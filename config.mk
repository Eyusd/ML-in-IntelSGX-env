ifneq ($(CC),cc)
else ifneq ($(shell $(CC) --version | grep clang),)
else
        CLANG_VERSION = $(shell for v in "9" "8" "7"; do \
                                        if [ -n "$$(command -v clang-$$v)" ]; then \
                                                echo $$v; \
                                                break; \
                                        fi; \
                                done)

        ifneq ($(CLANG_VERSION),)
                CC = clang-$(CLANG_VERSION)
                CXX = clang++-$(CLANG_VERSION)
        endif
endif

C_COMPILER = clang
CXX_COMPILER = clang++
ifeq ($(shell $(CC) --version | grep clang),)
        C_COMPILER = gcc
        CXX_COMPILER = g++
endif

COMPILER = $(C_COMPILER)