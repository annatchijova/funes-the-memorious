CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2 -g
CPPFLAGS ?=

BIN = bin/funes bin/funes-verify

.PHONY: all clean test

all: $(BIN)

bin/funes: src/funes.c src/sha256.c src/sha256.h
	mkdir -p bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/funes.c src/sha256.c

# The verifier must not link collector objects: it has its own SHA-256 and
# its own parser (see docs/spec/VERIFIER-SEMANTICS.md and ADR-001).
bin/funes-verify: verifier/funes_verify.c verifier/sha256.c verifier/sha256.h
	mkdir -p bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ verifier/funes_verify.c verifier/sha256.c

test: all
	sh tests/run_tests.sh

clean:
	rm -rf bin
