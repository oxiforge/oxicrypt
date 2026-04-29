# C integration tests for oxicrypt-ffi.
#
# Targets:
#   make test-cdylib    — build + run all tests against liboxicrypt_ffi.so
#   make test-staticlib — build + run all tests against liboxicrypt_ffi.a
#   make all            — both
#   make clean          — remove built test binaries
#
# Tests are compiled against the cbindgen-generated header at
# ../../include/oxicrypt.h and linked against the corresponding
# release artifact in target/release/. Both artifacts MUST be
# fips-integrity-sign'd before the test binaries can call oxi_init —
# absent a signed slot the integrity self-test fails (when wired in
# for the executable case). Today's cdylib path skips the runtime
# integrity KAT (see security policy §4.7.1) so the tests will run
# whether or not the slot is signed; for executable parity the
# signed-slot precondition is recommended.

# Workspace target dir — assume default; override via env if needed.
CARGO_TARGET_DIR ?= $(shell cd ../../../.. && pwd)/target
LIB_DIR := $(CARGO_TARGET_DIR)/release
INCLUDE_DIR := ../../include

CC := cc
CFLAGS := -I$(INCLUDE_DIR) -Wall -Wextra -O2

TESTS := test_init test_aes_gcm test_handles

.PHONY: all test-cdylib test-staticlib clean help

help:
	@echo "C integration tests for oxicrypt-ffi"
	@echo ""
	@echo "  make test-cdylib    — link tests against liboxicrypt_ffi.so + run"
	@echo "  make test-staticlib — link tests against liboxicrypt_ffi.a + run"
	@echo "  make all            — both target sets (6 test runs)"
	@echo "  make clean          — remove built test binaries"
	@echo ""
	@echo "  CARGO_TARGET_DIR ?= $(CARGO_TARGET_DIR)"

all: test-cdylib test-staticlib

CDYLIB_BINS := $(addprefix $(LIB_DIR)/cdylib_,$(TESTS))
STATICLIB_BINS := $(addprefix $(LIB_DIR)/staticlib_,$(TESTS))

test-cdylib: $(CDYLIB_BINS)
	@for t in $(CDYLIB_BINS); do \
	  echo "Running $$t (cdylib)..."; \
	  LD_LIBRARY_PATH=$(LIB_DIR) $$t || exit 1; \
	done

test-staticlib: $(STATICLIB_BINS)
	@for t in $(STATICLIB_BINS); do \
	  echo "Running $$t (staticlib)..."; \
	  $$t || exit 1; \
	done

# cdylib link: dynamic — runtime needs LD_LIBRARY_PATH.
$(LIB_DIR)/cdylib_%: %.c $(LIB_DIR)/liboxicrypt_ffi.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LIB_DIR) -loxicrypt_ffi -lpthread -ldl -lm

# staticlib link: archive whole — staticlib pulls in dependent symbols.
$(LIB_DIR)/staticlib_%: %.c $(LIB_DIR)/liboxicrypt_ffi.a
	$(CC) $(CFLAGS) -o $@ $< $(LIB_DIR)/liboxicrypt_ffi.a -lpthread -ldl -lm

clean:
	rm -f $(LIB_DIR)/cdylib_* $(LIB_DIR)/staticlib_*
