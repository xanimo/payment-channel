# payment-channel: a unidirectional Dogecoin payment channel on libdogecoin
#
# libdogecoin is not yet released with the entry points this needs, so point
# LIBDOGECOIN at a staged install built from a tree carrying:
#   dogecoinfoundation/libdogecoin#454 #455 #456 #457 #459
#
#   make LIBDOGECOIN=/path/to/staged/install
#
# The install must contain include/dogecoin/libdogecoin.h and lib/libdogecoin.a.

LIBDOGECOIN ?= /usr/local

CC       ?= cc
CFLAGS   ?= -std=gnu99 -O2 -g -Wall -Wextra -Wno-unused-parameter

# An implicit declaration here means a libdogecoin entry point that is exported
# from the archive but missing from the installed header. It links, and then it
# returns int where the real one returns dogecoin_bool. That is a warning in a
# wall of output and a bug at runtime, so make it stop the build. Overridden
# rather than appended so it survives a CFLAGS= on the command line.
override CFLAGS += -Werror=implicit-function-declaration
CPPFLAGS += -Iinclude -Isrc -I$(LIBDOGECOIN)/include
LDFLAGS  += -L$(LIBDOGECOIN)/lib
LDLIBS   += $(LIBDOGECOIN)/lib/libdogecoin.a -levent -levent_core -levent_extra \
            -levent_pthreads -lpthread -lm

CORE_SRC = src/channel.c src/envelope.c src/txcheck.c src/wire.c
CORE_OBJ = $(CORE_SRC:.c=.o)

BINS = alice bob
TESTS = test_channel test/mkfunding test/adversary test/attack

all: $(BINS)

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

# Two hand-rolled parsers consume attacker-controlled bytes: pc_envelope_decode
# on a line off the socket, and the reader in txcheck.c on peer-supplied
# transaction hex. Both are read carefully and neither had been fuzzed, which is
# the bug class reading misses. clang only, since it needs libFuzzer.
FUZZ_SAN = -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
FUZZERS  = fuzz/fuzz_envelope fuzz/fuzz_txcheck fuzz/fuzz_opening fuzz/fuzz_refund fuzz/fuzz_payment

fuzz/mkseed: fuzz/mkseed.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

fuzz: $(FUZZERS)

fuzz/fuzz_%: fuzz/fuzz_%.c $(CORE_SRC)
	clang -std=gnu99 -O1 -g $(FUZZ_SAN) $(CPPFLAGS) -o $@ $^ \
	      $(LIBDOGECOIN)/lib/libdogecoin.a -levent -levent_core -levent_extra \
	      -levent_pthreads -lpthread -lm

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check: $(TESTS) $(BINS)
	./test_channel
	./test/attack
	./test/loopback.sh
	./test/slowpeer.sh

clean:
	rm -f $(BINS) $(TESTS) src/*.o test/*.o

.PHONY: all check clean fuzz
