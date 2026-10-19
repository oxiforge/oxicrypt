# C integration tests for oxicrypt-ffi.
#
# Targets:
#   make test-cdylib    — run every test against a signed copy of liboxicrypt_ffi.so
#   make test-staticlib — link every test against liboxicrypt_ffi.a, sign each
#                         executable, run it
#   make test-unsigned  — run the refusal test against an unsigned copy of the
#                         cdylib and an unsigned static executable, and check
#                         that it fails against the signed copy
#   make all            — all three
#   make clean          — remove everything these targets built
#
# Prerequisites: a key pair, and the libraries built with its public half
# in release mode into $(CARGO_TARGET_DIR)/release:
#
#   cargo build --release -p oxicrypt-integrity-sign
#   target/release/oxicrypt-integrity-sign --keygen <dir outside the tree>
#   OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub \
#       cargo build --release -p oxicrypt-ffi -p oxicrypt-integrity-sign
#   make SIGNING_KEY=<dir>/integrity-signing.key all
#
# Every artifact that links the module must be signed after it is linked:
# `oxi_init` runs the pre-operational integrity test, which fails with
# SelfTestFailed = 2 on an artifact whose integrity slot was never written.
# The refusal test expects SlotInvalid, which is what a library built with
# a verifying key and left unsigned reports; one built without a key
# reports NoVerifyKey instead.
# For the cdylib the signed artifact is the shared library; for the static
# library it is each test executable, because the archive is linked into
# it. The targets below sign copies under $(OUT_DIR) and never modify the
# cargo outputs in place.

# Workspace target dir — assume default; override via env if needed.
CARGO_TARGET_DIR ?= $(shell cd ../../../.. && pwd)/target
LIB_DIR := $(CARGO_TARGET_DIR)/release
OUT_DIR := $(LIB_DIR)/c-integration
INCLUDE_DIR := ../../include
SIGN := $(LIB_DIR)/oxicrypt-integrity-sign
# The private half of the key the libraries were built with. Required by
# every target that signs.
SIGNING_KEY ?=
# Its public half, the file the libraries were built with. The refusal test
# checks the fingerprint the library reports against its SHA-256.
VERIFY_KEY ?= $(dir $(SIGNING_KEY))integrity-verify.pub
FINGERPRINT = $(shell sha256sum $(VERIFY_KEY) | cut -d' ' -f1)
SIGN_CMD = $(if $(SIGNING_KEY),$(SIGN) --sign --key $(SIGNING_KEY),$(error SIGNING_KEY is not set; see the prerequisites at the top of this Makefile))

CC := cc
CFLAGS := -I$(INCLUDE_DIR) -Wall -Wextra -O2
LDLIBS := -lpthread -ldl -lm

TESTS := test_init test_aes_gcm test_aes_modes test_handles \
         test_ml_kem_512_smoke test_ml_kem_768_smoke test_ml_kem_1024_smoke \
         test_ml_dsa_44_smoke test_ml_dsa_65_smoke test_ml_dsa_87_smoke \
         test_slh_dsa_sha2_256s_smoke test_slh_dsa_shake_128f_smoke \
         test_lms_sha256_m32_h5_w4_smoke test_lms_shake_m32_h10_w4_smoke \
         test_lms_verify test_drbg_smoke

# Passes only against an artifact that was NOT signed.
REFUSAL_TEST := test_integrity_unsigned

# The dynamically linked tests ask the loader for the library's SONAME,
# liboxicrypt_ffi.so.<ABI>. Each copy is made under that name, read from the
# built library when the copy is made, with the plain name a link to it; a
# library whose name cannot be read stops the build.
LIB_FILE_NAME := ../../../../scripts/library-file-name.sh
SIGNED_SO := $(OUT_DIR)/signed/liboxicrypt_ffi.so
UNSIGNED_SO := $(OUT_DIR)/unsigned/liboxicrypt_ffi.so

CDYLIB_BINS := $(addprefix $(OUT_DIR)/cdylib/,$(TESTS) $(REFUSAL_TEST))
STATICLIB_BINS := $(addprefix $(OUT_DIR)/staticlib/,$(TESTS))
UNSIGNED_STATIC_BIN := $(OUT_DIR)/staticlib-unsigned/$(REFUSAL_TEST)

.PHONY: all test-cdylib test-staticlib test-unsigned clean help

help:
	@echo "C integration tests for oxicrypt-ffi"
	@echo ""
	@echo "  make test-cdylib    — $(words $(TESTS)) tests against a signed liboxicrypt_ffi.so"
	@echo "  make test-staticlib — $(words $(TESTS)) signed executables linked against liboxicrypt_ffi.a"
	@echo "  make test-unsigned  — $(REFUSAL_TEST) against an unsigned .so and an unsigned"
	@echo "                        static executable, and its control against the signed .so"
	@echo "  make all            — all three ($(words $(TESTS)) tests × 2 link modes, plus 3 refusal runs)"
	@echo "  make clean          — remove $(OUT_DIR)"
	@echo ""
	@echo "  CARGO_TARGET_DIR ?= $(CARGO_TARGET_DIR)"

all: test-cdylib test-staticlib test-unsigned

# Runs every test even after a failure, so one run reports all of them.
test-cdylib: $(addprefix $(OUT_DIR)/cdylib/,$(TESTS)) $(SIGNED_SO)
	@failed=0; \
	for t in $(TESTS); do \
	  echo "Running $$t (cdylib, signed)..."; \
	  LD_LIBRARY_PATH=$(dir $(SIGNED_SO)) $(OUT_DIR)/cdylib/$$t || { echo "FAILED: $$t"; failed=$$((failed + 1)); }; \
	done; \
	echo "cdylib: $$(( $(words $(TESTS)) - failed )) passed, $$failed failed"; \
	[ $$failed -eq 0 ]

test-staticlib: $(STATICLIB_BINS)
	@failed=0; \
	for t in $(TESTS); do \
	  echo "Running $$t (staticlib, signed)..."; \
	  $(OUT_DIR)/staticlib/$$t || { echo "FAILED: $$t"; failed=$$((failed + 1)); }; \
	done; \
	echo "staticlib: $$(( $(words $(TESTS)) - failed )) passed, $$failed failed"; \
	[ $$failed -eq 0 ]

# The control runs first: the refusal test must FAIL against the signed
# library, or a pass on the unsigned copies proves nothing.
test-unsigned: $(OUT_DIR)/cdylib/$(REFUSAL_TEST) $(SIGNED_SO) $(UNSIGNED_SO) $(UNSIGNED_STATIC_BIN)
	@echo "Running $(REFUSAL_TEST) against the signed cdylib (control, must exit 2)..."
	@LD_LIBRARY_PATH=$(dir $(SIGNED_SO)) $(OUT_DIR)/cdylib/$(REFUSAL_TEST); rc=$$?; \
	if [ $$rc -ne 2 ]; then \
	  echo "FAILED: $(REFUSAL_TEST) exited $$rc against a signed library; 2 means oxi_init succeeded"; \
	  exit 1; \
	fi
	@echo "control ok: oxi_init succeeds against the signed library ($(REFUSAL_TEST) exit 2)"
	@echo "Running $(REFUSAL_TEST) (cdylib, unsigned)..."
	@INTEGRITY_FINGERPRINT=$(FINGERPRINT) LD_LIBRARY_PATH=$(dir $(UNSIGNED_SO)) $(OUT_DIR)/cdylib/$(REFUSAL_TEST)
	@echo "Running $(REFUSAL_TEST) (staticlib, unsigned)..."
	@INTEGRITY_FINGERPRINT=$(FINGERPRINT) $(UNSIGNED_STATIC_BIN)

$(SIGNED_SO): $(LIB_DIR)/liboxicrypt_ffi.so $(SIGN)
	@mkdir -p $(dir $@)
	name=$$($(LIB_FILE_NAME) $<) || exit 1; \
	cp $< $(dir $@)$$name.tmp && \
	$(SIGN_CMD) $(dir $@)$$name.tmp && \
	mv $(dir $@)$$name.tmp $(dir $@)$$name && \
	ln -sfn $$name $@

$(UNSIGNED_SO): $(LIB_DIR)/liboxicrypt_ffi.so
	@mkdir -p $(dir $@)
	name=$$($(LIB_FILE_NAME) $<) || exit 1; \
	cp $< $(dir $@)$$name && \
	ln -sfn $$name $@

# cdylib link: dynamic. The library is chosen at run time by
# LD_LIBRARY_PATH, so one executable runs against the signed or the
# unsigned copy.
$(OUT_DIR)/cdylib/%: %.c $(LIB_DIR)/liboxicrypt_ffi.so
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $< -L$(LIB_DIR) -loxicrypt_ffi $(LDLIBS)

# staticlib link: the archive is linked into the executable, so the
# executable is what gets signed. It is signed under a temporary name, so a
# failed signing leaves no target that make would treat as up to date.
$(OUT_DIR)/staticlib/%: %.c $(LIB_DIR)/liboxicrypt_ffi.a $(SIGN)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@.tmp $< $(LIB_DIR)/liboxicrypt_ffi.a $(LDLIBS)
	$(SIGN_CMD) $@.tmp
	mv $@.tmp $@

$(OUT_DIR)/staticlib-unsigned/%: %.c $(LIB_DIR)/liboxicrypt_ffi.a
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_DIR)/liboxicrypt_ffi.a $(LDLIBS)

clean:
	rm -rf $(OUT_DIR)
