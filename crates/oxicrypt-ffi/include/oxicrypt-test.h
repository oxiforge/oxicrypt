/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * oxicrypt test interface: functions that simulate failures, for testing a
 * caller's handling of them. They exist only in a library built with the
 * fault-injection feature; a release library does not export them.
 */

#ifndef OXICRYPT_TEST_H
#define OXICRYPT_TEST_H

#include "oxicrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Simulates a fixed entropy source: later seed draws are served from seed[0..len) in order. Requires the fault-injection feature. */
void oxi_test_set_seed_stream(const uint8_t *seed, uintptr_t len);

/* Simulates another thread using the handle: on non-zero takes the hold for this process, 0 releases it. Requires the fault-injection feature. */
void oxi_test_hold_busy(OxiDrbg *h, int on);

/* Simulates a pairwise consistency test failure in the next key generation (on non-zero arms, 0 disarms). Requires the fault-injection feature. */
void oxi_test_corrupt_next_key(int on);

/* Simulates an entropy source failure: the module enters its error state. Requires the fault-injection feature. */
void oxi_test_poison_entropy(void);

/* Simulates an on-demand health test failure: the next oxi_entropy_on_demand_test returns 33 and the module enters its error state. Requires the fault-injection feature. */
void oxi_test_fail_next_on_demand(void);

/* Reports whether the last handle allocation the module wiped and released, a DRBG handle freed by oxi_drbg_free or a typed DRBG _free or an AES key handle, read as all zero after its wipe and before release: 1 yes, 0 no, -1 none released since the last call, which each call clears. Requires the fault-injection feature. */
int oxi_test_last_freed_bytes_zero(void);

/* Simulates an allocation failure: the next _new_rbg call returns 255. Requires the fault-injection feature. */
void oxi_test_fail_next_alloc(void);

/* Holds the next DRBG generate at the DRBG's re-check of the module state, made before it produces any output bytes (not the later re-check before the copy to the caller), until oxi_test_release_parked or until it has spun 2^32 times, whichever comes first (on non-zero arms, 0 disarms). Requires the fault-injection feature. */
void oxi_test_park_before_output(int on);

/* Releases a generate held at its output check and disarms the hold. Requires the fault-injection feature. */
void oxi_test_release_parked(void);

/* Reports whether a generate is held at its output check: 1 yes, 0 no. Requires the fault-injection feature. */
int oxi_test_is_parked(void);

#ifdef __cplusplus
}
#endif

#endif /* OXICRYPT_TEST_H */
