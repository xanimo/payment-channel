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
CPPFLAGS += -Iinclude -Isrc -I$(LIBDOGECOIN)/include
LDFLAGS  += -L$(LIBDOGECOIN)/lib
LDLIBS   += $(LIBDOGECOIN)/lib/libdogecoin.a -levent -levent_core -levent_extra \
            -levent_pthreads -lpthread -lm

CORE_SRC = src/channel.c src/envelope.c src/txcheck.c src/wire.c
CORE_OBJ = $(CORE_SRC:.c=.o)

BINS = alice bob
TESTS = test_channel test/mkfunding test/adversary

all: $(BINS)

alice: src/alice.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

bob: src/bob.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test_channel: test/test_channel.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/adversary: test/adversary.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test/mkfunding: test/mkfunding.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check: $(TESTS) $(BINS)
	./test_channel
	./test/loopback.sh

clean:
	rm -f $(BINS) $(TESTS) src/*.o test/*.o

.PHONY: all check clean
