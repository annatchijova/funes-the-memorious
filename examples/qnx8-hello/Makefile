# Fixture build. With a licensed QNX SDP 8.0 loaded (QNX_HOST/QNX_TARGET
# set, qcc on PATH) this uses qcc; otherwise it falls back to the host
# compiler and the result must be labeled host-only. The target variant is
# never hard-coded here: pass QNX_TARGET_FLAGS after validating against
# the installed qcc (see ../../docs/QNX-SETUP.md).
QCC ?= qcc
HOSTCC ?= cc
QNX_TARGET_FLAGS ?=

ifeq ($(shell command -v $(QCC) 2>/dev/null),)
all:
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -O2 -o qnx8-hello main.c
	@echo "built with host compiler: label VERIFIED_HOST_ONLY, not QNX evidence"
else
all:
	$(QCC) $(QNX_TARGET_FLAGS) -o qnx8-hello main.c
	@echo "built with qcc: record the exact flags and target as evidence"
endif

clean:
	rm -f qnx8-hello

.PHONY: all clean
