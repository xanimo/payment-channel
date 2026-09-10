# payment-channel: a unidirectional Dogecoin payment channel on koinu (libkw)
#
# The crypto, transactions, PSBT and base58 come from koinu, which is a released
# static library rather than an unreleased libdogecoin fork. It is a submodule,
# so a first build is:
#
#   git submodule update --init --recursive depends/koinu
#   make -C depends/koinu
#   make check
#
# v0.2.1 is the pinned tag; it carries the scriptSig-length fix a P2SH multisig
# spend needs. Whatever KOINU points at must contain libkw.a,
# depends/secp256k1/.libs/libsecp256k1.a, and the crypto/ net/ wallet/ headers.

# koinu is a submodule pinned at KOINU_TAG, so a local build is the same one CI
# runs rather than whatever a sibling checkout happens to be on. CI does not use
# the submodule: koinu is private, so it clones with a deploy key into its own
# workspace and passes KOINU explicitly. Both pin the same tag, which is the
# point. Set KOINU to a checkout of your own to develop the two trees together.
KOINU     ?= depends/koinu
KOINU_TAG ?= v0.2.1

CC       ?= cc
CFLAGS   ?= -std=gnu99 -O2 -g -Wall -Wextra -Wno-unused-parameter

# An implicit declaration means a koinu entry point used without its header, a
# warning in a wall of output and a bug at runtime, so make it stop the build.
# Overridden rather than appended so it survives a CFLAGS= on the command line.
override CFLAGS += -Werror=implicit-function-declaration
CPPFLAGS += -Iinclude -Isrc -I$(KOINU)/crypto -I$(KOINU)/net -I$(KOINU)/wallet
LDLIBS   += $(KOINU)/libkw.a $(KOINU)/depends/secp256k1/.libs/libsecp256k1.a -lm

CORE_SRC = src/channel.c src/envelope.c src/state.c src/txcheck.c src/wire.c
CORE_OBJ = $(CORE_SRC:.c=.o)

BINS = alice bob
TESTS = test_channel test/mkfunding test/adversary test/attack test/sighash_vectors

all: koinu-version $(BINS)

# Whatever tree KOINU points at is what gets linked, and nothing in the build
# says which revision that was. A sibling checkout mid-feature silently builds a
# different program than CI does, and the failure surfaces as anything at all:
# a link error against a sanitizer-instrumented archive is how this was found.
# KOINU_ANY=1 downgrades it to a warning, which is what developing both trees
# together wants.
.PHONY: koinu-version
koinu-version:
	@if [ ! -f "$(KOINU)/Makefile" ]; then \
	    echo "koinu is not at $(KOINU)." >&2; \
	    echo "  git submodule update --init --recursive depends/koinu" >&2; \
	    echo "  or set KOINU to a koinu checkout at $(KOINU_TAG)" >&2; \
	    exit 1; \
	fi; \
	have=`git -C "$(KOINU)" describe --tags --always --dirty 2>/dev/null || echo unknown`; \
	if [ "$$have" != "$(KOINU_TAG)" ]; then \
	    if [ -n "$(KOINU_ANY)" ]; then \
	        echo "warning: koinu at $$have, not the pinned $(KOINU_TAG)" >&2; \
	    else \
	        echo "koinu at $(KOINU) is $$have, not the pinned $(KOINU_TAG)." >&2; \
	        echo "CI builds $(KOINU_TAG), so this would test a different program." >&2; \
	        echo "Set KOINU_ANY=1 to build against it anyway." >&2; \
	        exit 1; \
	    fi; \
	fi

alice: src/alice.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

bob: src/bob.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test_channel: test/test_channel.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/attack: test/attack.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/adversary: test/adversary.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/mkfunding: test/mkfunding.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/sighash_vectors: test/sighash_vectors.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/bench: test/bench.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Two hand-rolled parsers consume attacker-controlled bytes: pc_envelope_decode
# on a line off the socket, and the reader in txcheck.c on peer-supplied
# transaction hex. Both are read carefully and neither had been fuzzed, which is
# the bug class reading misses. clang only, since it needs libFuzzer.
FUZZ_SAN = -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
FUZZERS  = fuzz/fuzz_envelope fuzz/fuzz_txcheck fuzz/fuzz_opening fuzz/fuzz_refund fuzz/fuzz_payment

fuzz/mkseed: fuzz/mkseed.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

fuzz: koinu-version $(FUZZERS)

fuzz/fuzz_%: fuzz/fuzz_%.c $(CORE_SRC)
	clang -std=gnu99 -O1 -g $(FUZZ_SAN) $(CPPFLAGS) -o $@ $^ \
	      $(KOINU)/libkw.a $(KOINU)/depends/secp256k1/.libs/libsecp256k1.a -lm

# -MMD writes a .d beside each .o naming every header that went into it, -MP
# adds a phony target for each so a deleted header does not wedge the build, and
# the -include below feeds them back to make. Without this an edit to
# include/channel.h rebuilt nothing under test/, and renumbering an enum left
# stale objects whose failures landed in assertions nowhere near the change.
# On the compile rule rather than in CFLAGS, which is also passed at link time
# where -MMD would write stray dependency files next to the binaries.
%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

-include $(wildcard src/*.d test/*.d fuzz/*.d)

check: koinu-version $(TESTS) $(BINS)
	./test_channel
	./test/attack
	./test/sighash_vectors
	./test/loopback.sh
	./test/slowpeer.sh
	./test/resume.sh
	./test/height.sh
	./test/confirm.sh
	./test/sweep.sh
	./test/keyguard.sh
	./test/signer.sh
	./test/replicate.sh
	./test/feerate.sh
	./test/metrics.sh

clean:
	rm -f $(BINS) $(TESTS) src/*.o test/*.o src/*.d test/*.d fuzz/*.o fuzz/*.d

.PHONY: all check clean fuzz
