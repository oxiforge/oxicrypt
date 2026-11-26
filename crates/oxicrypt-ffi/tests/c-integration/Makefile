# C integration tests for oxicrypt-ffi.
#
# Targets:
#   make test-cdylib    — run every test against a signed copy of liboxicrypt_ffi.so
#   make test-staticlib — link every test against liboxicrypt_ffi.a, sign each
#                         executable, run it
#   make test-unsigned  — run the refusal test against an unsigned copy of the
#                         cdylib and an unsigned static executable, and check
#                         that it fails against the signed copy
#   make test-fault     — build the cdylib with the fault-injection feature
#                         into $(CARGO_TARGET_DIR)/fault, sign a copy, and run
#                         the tests that simulate failures against it
#   make all            — all four
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
#
# test-fault builds its own library with the public half of the same key,
# $(VERIFY_KEY), into a separate target directory, so the release build
# above is untouched. The fault-injection library exports the oxi_test_*
# functions of include/oxicrypt-test.h; no release artifact contains them.

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

# test_pq_input_checks reads the ML-KEM key-generation vectors from here at
# run time. The path is compiled in as a quoted C string, so a checkout path
# containing a quote character breaks the build.
ML_KEM_DATA_DIR := $(abspath ../../../oxicrypt-ml-kem/tests/data)

CC := cc
CFLAGS := -I$(INCLUDE_DIR) -Wall -Wextra -O2 -DML_KEM_DATA_DIR='"$(ML_KEM_DATA_DIR)"'
LDLIBS := -lpthread -ldl -lm

TESTS := test_init test_aes_gcm test_aes_modes test_handles \
         test_ml_kem_512_smoke test_ml_kem_768_smoke test_ml_kem_1024_smoke \
         test_ml_dsa_44_smoke test_ml_dsa_65_smoke test_ml_dsa_87_smoke \
         test_slh_dsa_sha2_256s_smoke test_slh_dsa_shake_128f_smoke \
         test_lms_sha256_m32_h5_w4_smoke test_lms_shake_m32_h10_w4_smoke \
         test_lms_verify test_drbg_smoke \
         test_kw_fail_writes_nothing test_ccm_decrypt_code_is_22 test_buffer_contract \
         test_gcm_key_count_ops test_key_handle_kind_checked \
         test_pq_rbg_entry_points test_pq_input_checks test_concurrent_services

# Prints one row=<name> line per oxi_aes_* function it drives and
# enumerated=<n>; the sorted row names are compared, as a list, with the
# int-returning oxi_aes_* functions oxicrypt.h declares, in test-cdylib and
# test-staticlib. A missing, extra or duplicated row, or a header with no
# such function, fails the run and prints the difference.
AES_CONTRACT_TEST := test_buffer_contract
AES_SYMBOL_NAME_PATTERN := '^int oxi_aes_[a-z0-9_]+'
# Run inside a test loop after $$t passed, with its output in $$out.
AES_CONTRACT_CHECK = if [ $$t = $(AES_CONTRACT_TEST) ]; then \
	    cmp_dir=$$(mktemp -d); \
	    echo "$$out" | sed -n 's/^row=\(oxi_aes_[a-z0-9_]*\)$$/\1/p' | sort > "$$cmp_dir/got"; \
	    grep -oE $(AES_SYMBOL_NAME_PATTERN) $(INCLUDE_DIR)/oxicrypt.h | sed 's/^int //' | sort > "$$cmp_dir/want"; \
	    if [ ! -s "$$cmp_dir/want" ]; then \
	      echo "FAILED: $$t: oxicrypt.h declares no int oxi_aes_* function"; \
	      failed=$$((failed + 1)); \
	    elif ! cmp -s "$$cmp_dir/got" "$$cmp_dir/want"; then \
	      echo "FAILED: $$t: its rows differ from the oxi_aes_* functions in oxicrypt.h (< rows, > header):"; \
	      diff "$$cmp_dir/got" "$$cmp_dir/want" | grep '^[<>]'; \
	      failed=$$((failed + 1)); \
	    else \
	      echo "$$t: $$(wc -l < "$$cmp_dir/want") rows match the oxi_aes_* functions oxicrypt.h declares"; \
	    fi; \
	    rm -f "$$cmp_dir/got" "$$cmp_dir/want"; \
	    rmdir "$$cmp_dir"; \
	  fi

# Prints one kind_row=<name> line per oxi_aes_* function it drives with a
# key handle of another mode; the sorted row names are compared, as a list,
# with the oxi_aes_* functions oxicrypt.h declares whose first parameter is
# a key handle, in test-cdylib and test-staticlib. A missing, extra or
# duplicated row, or a header with no such function, fails the run and
# prints the difference.
AES_KIND_TEST := test_key_handle_kind_checked
AES_KEY_TAKING_PATTERN := '^(int|void) oxi_aes_[a-z0-9_]+\((const )?OxiAes[A-Za-z]+Key \*'
# Run inside a test loop after $$t passed, with its output in $$out.
AES_KIND_CHECK = if [ $$t = $(AES_KIND_TEST) ]; then \
	    cmp_dir=$$(mktemp -d); \
	    echo "$$out" | sed -n 's/^kind_row=\(oxi_aes_[a-z0-9_]*\)$$/\1/p' | sort > "$$cmp_dir/got"; \
	    grep -oE $(AES_KEY_TAKING_PATTERN) $(INCLUDE_DIR)/oxicrypt.h | sed -E 's/^(int|void) //; s/\(.*//' | sort > "$$cmp_dir/want"; \
	    if [ ! -s "$$cmp_dir/want" ]; then \
	      echo "FAILED: $$t: oxicrypt.h declares no oxi_aes_* function taking a key handle"; \
	      failed=$$((failed + 1)); \
	    elif ! cmp -s "$$cmp_dir/got" "$$cmp_dir/want"; then \
	      echo "FAILED: $$t: its rows differ from the key-taking oxi_aes_* functions in oxicrypt.h (< rows, > header):"; \
	      diff "$$cmp_dir/got" "$$cmp_dir/want" | grep '^[<>]'; \
	      failed=$$((failed + 1)); \
	    else \
	      echo "$$t: $$(wc -l < "$$cmp_dir/want") rows match the key-taking oxi_aes_* functions oxicrypt.h declares"; \
	    fi; \
	    rm -f "$$cmp_dir/got" "$$cmp_dir/want"; \
	    rmdir "$$cmp_dir"; \
	  fi

# Prints one row=<name> line per ML-DSA and ML-KEM function it drives; the
# sorted row names are compared, as a list, with the keygen_rbg, expand_key
# and encapsulate_rbg functions oxicrypt.h declares, in test-cdylib and
# test-staticlib. A missing, extra or duplicated row, or a header with no
# such function, fails the run and prints the difference.
PQ_CONTRACT_TEST := test_pq_rbg_entry_points
PQ_SYMBOL_NAME_PATTERN := '^int oxi_ml_(dsa|kem)_[0-9]+_(keygen_rbg|expand_key|encapsulate_rbg)\('
# Run inside a test loop after $$t passed, with its output in $$out.
PQ_CONTRACT_CHECK = if [ $$t = $(PQ_CONTRACT_TEST) ]; then \
	    cmp_dir=$$(mktemp -d); \
	    echo "$$out" | sed -n 's/^row=\(oxi_ml_[a-z0-9_]*\)$$/\1/p' | sort > "$$cmp_dir/got"; \
	    grep -oE $(PQ_SYMBOL_NAME_PATTERN) $(INCLUDE_DIR)/oxicrypt.h | sed 's/^int //; s/($$//' | sort > "$$cmp_dir/want"; \
	    if [ ! -s "$$cmp_dir/want" ]; then \
	      echo "FAILED: $$t: oxicrypt.h declares no ML-DSA or ML-KEM keygen_rbg, expand_key or encapsulate_rbg"; \
	      failed=$$((failed + 1)); \
	    elif ! cmp -s "$$cmp_dir/got" "$$cmp_dir/want"; then \
	      echo "FAILED: $$t: its rows differ from the ML-DSA and ML-KEM functions in oxicrypt.h (< rows, > header):"; \
	      diff "$$cmp_dir/got" "$$cmp_dir/want" | grep '^[<>]'; \
	      failed=$$((failed + 1)); \
	    else \
	      echo "$$t: $$(wc -l < "$$cmp_dir/want") rows match the ML-DSA and ML-KEM functions oxicrypt.h declares"; \
	    fi; \
	    rm -f "$$cmp_dir/got" "$$cmp_dir/want"; \
	    rmdir "$$cmp_dir"; \
	  fi

# Passes only against an artifact that was NOT signed.
REFUSAL_TEST := test_integrity_unsigned

# Run against the fault-injection library, compiled with
# OXICRYPT_FAULT_INJECTION defined. Of the three tests also in TESTS,
# test_pq_rbg_entry_points and test_concurrent_services add fault-only
# cases under that macro and test_pq_input_checks runs unchanged; the rest
# run against this library only.
FAULT_TESTS := test_pq_rbg_entry_points test_pq_input_checks test_concurrent_services \
               test_pct_failure_code_ecdsa test_pct_failure_code_ecdh test_pct_failure_code_rsa \
               test_oxi_drbg_handle test_drbg_buffer_contract \
               test_typed_handle_fork_refusal_ecdsa test_typed_handle_fork_refusal_ecdh \
               test_typed_handle_fork_refusal_rsa test_typed_handle_fork_refusal_dh \
               test_drbg_free_zeroizes test_new_rbg_alloc_failure \
               test_output_inhibited_after_failure \
               test_typed_from_module_replace test_typed_uninstantiated_codes \
               test_inherited_handle_reinstantiate test_drbg_fork_two_threads \
               test_entropy_on_demand_codes test_drbg_generate_additional_bounds
# Must reach the output check through the test hold, never through a delay.
HANDSHAKE_TEST := test_output_inhibited_after_failure
# Prints enumerated=<n>, compared with the DRBG functions oxicrypt.h declares.
CONTRACT_TEST := test_drbg_buffer_contract
DRBG_SYMBOL_PATTERN := '^int oxi_[a-z0-9_]*drbg[a-z0-9_]*\('
FAULT_LIB_DIR := $(CARGO_TARGET_DIR)/fault/release
FAULT_SO := $(OUT_DIR)/fault/signed/liboxicrypt_ffi.so
FAULT_BINS := $(addprefix $(OUT_DIR)/fault/bin/,$(FAULT_TESTS))

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

.PHONY: all test-cdylib test-staticlib test-unsigned test-fault fault-lib clean help

help:
	@echo "C integration tests for oxicrypt-ffi"
	@echo ""
	@echo "  make test-cdylib    — $(words $(TESTS)) tests against a signed liboxicrypt_ffi.so"
	@echo "  make test-staticlib — $(words $(TESTS)) signed executables linked against liboxicrypt_ffi.a"
	@echo "  make test-unsigned  — $(REFUSAL_TEST) against an unsigned .so and an unsigned"
	@echo "                        static executable, and its control against the signed .so"
	@echo "  make test-fault     — $(words $(FAULT_TESTS)) tests against a signed fault-injection liboxicrypt_ffi.so"
	@echo "  make all            — all four ($(words $(TESTS)) tests × 2 link modes, 3 refusal runs,"
	@echo "                        $(words $(FAULT_TESTS)) fault-injection tests)"
	@echo "  make clean          — remove $(OUT_DIR)"
	@echo ""
	@echo "  CARGO_TARGET_DIR ?= $(CARGO_TARGET_DIR)"

all: test-cdylib test-staticlib test-unsigned test-fault

# Runs every test even after a failure, so one run reports all of them.
# Both link modes also fail when the row names of AES_CONTRACT_TEST,
# AES_KIND_TEST or PQ_CONTRACT_TEST differ from the oxicrypt.h functions
# each covers.
test-cdylib: $(addprefix $(OUT_DIR)/cdylib/,$(TESTS)) $(SIGNED_SO)
	@failed=0; \
	for t in $(TESTS); do \
	  echo "Running $$t (cdylib, signed)..."; \
	  out=$$(LD_LIBRARY_PATH=$(dir $(SIGNED_SO)) $(OUT_DIR)/cdylib/$$t); rc=$$?; \
	  [ -n "$$out" ] && echo "$$out"; \
	  if [ $$rc -ne 0 ]; then echo "FAILED: $$t (exit $$rc)"; failed=$$((failed + 1)); continue; fi; \
	  $(AES_CONTRACT_CHECK); \
	  $(AES_KIND_CHECK); \
	  $(PQ_CONTRACT_CHECK); \
	done; \
	echo "cdylib: $$(( $(words $(TESTS)) - failed )) passed, $$failed failed"; \
	[ $$failed -eq 0 ]

test-staticlib: $(STATICLIB_BINS)
	@failed=0; \
	for t in $(TESTS); do \
	  echo "Running $$t (staticlib, signed)..."; \
	  out=$$($(OUT_DIR)/staticlib/$$t); rc=$$?; \
	  [ -n "$$out" ] && echo "$$out"; \
	  if [ $$rc -ne 0 ]; then echo "FAILED: $$t (exit $$rc)"; failed=$$((failed + 1)); continue; fi; \
	  $(AES_CONTRACT_CHECK); \
	  $(AES_KIND_CHECK); \
	  $(PQ_CONTRACT_CHECK); \
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

# Runs every fault-injection test even after a failure. The contract test
# also fails when the number of DRBG functions it enumerates differs from
# the number oxicrypt.h declares.
test-fault: $(FAULT_BINS) $(FAULT_SO)
	@# A sleep or a slow-write delay can end before the call reaches the output check, so the handshake test must not use one.
	@if grep -nE 'sleep\(|nanosleep|usleep|slow-write' $(HANDSHAKE_TEST).c; then \
	  echo "FAILED: $(HANDSHAKE_TEST).c waits on a delay; use oxi_test_park_before_output and oxi_test_is_parked"; \
	  exit 1; \
	fi
	@if ! grep -qE '^[[:space:]]*while \(!oxi_test_is_parked\(\)' $(HANDSHAKE_TEST).c; then \
	  echo "FAILED: $(HANDSHAKE_TEST).c does not wait on oxi_test_is_parked"; \
	  exit 1; \
	fi
	@failed=0; \
	for t in $(FAULT_TESTS); do \
	  echo "Running $$t (cdylib, signed, fault injection)..."; \
	  out=$$(OXI_FAULT= LD_LIBRARY_PATH=$(dir $(FAULT_SO)) $(OUT_DIR)/fault/bin/$$t); rc=$$?; \
	  [ -n "$$out" ] && echo "$$out"; \
	  if [ $$rc -ne 0 ]; then echo "FAILED: $$t (exit $$rc)"; failed=$$((failed + 1)); continue; fi; \
	  if [ $$t = $(CONTRACT_TEST) ]; then \
	    got=$$(echo "$$out" | sed -n 's/.*enumerated=\([0-9][0-9]*\).*/\1/p'); \
	    want=$$(grep -cE $(DRBG_SYMBOL_PATTERN) $(INCLUDE_DIR)/oxicrypt.h); \
	    if [ "$$got" != "$$want" ]; then \
	      echo "FAILED: $$t enumerated $${got:-none} of the $$want DRBG functions in oxicrypt.h"; \
	      failed=$$((failed + 1)); \
	    else \
	      echo "$$t: enumerated $$got, oxicrypt.h declares $$want"; \
	    fi; \
	  fi; \
	done; \
	echo "fault: $$(( $(words $(FAULT_TESTS)) - failed )) passed, $$failed failed"; \
	[ $$failed -eq 0 ]

# Cargo decides whether the library is current, so this always runs it.
fault-lib:
	OXICRYPT_INTEGRITY_VERIFY_KEY=$(abspath $(VERIFY_KEY)) \
	  cargo build --release -p oxicrypt-ffi --features fault-injection \
	  --target-dir $(CARGO_TARGET_DIR)/fault

$(FAULT_SO): fault-lib $(SIGN)
	@mkdir -p $(dir $@)
	name=$$($(LIB_FILE_NAME) $(FAULT_LIB_DIR)/liboxicrypt_ffi.so) || exit 1; \
	cp $(FAULT_LIB_DIR)/liboxicrypt_ffi.so $(dir $@)$$name.tmp && \
	$(SIGN_CMD) $(dir $@)$$name.tmp && \
	mv $(dir $@)$$name.tmp $(dir $@)$$name && \
	ln -sfn $$name $@

$(OUT_DIR)/fault/bin/%: %.c fault-lib
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DOXICRYPT_FAULT_INJECTION -o $@ $< -L$(FAULT_LIB_DIR) -loxicrypt_ffi $(LDLIBS)

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
