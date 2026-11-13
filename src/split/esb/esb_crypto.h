/*
 * Copyright (c) 2026 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

/* First byte of every sealed packet. Plain packets start with 'Z' ("ZmKe"). */
#define ESB_CRYPTO_VERSION 0xE1

/* version(1) + sender(4) + epoch(4) + seq(4) ... ciphertext ... tag(16) */
#define ESB_CRYPTO_HEADER_SIZE 13
#define ESB_CRYPTO_TAG_SIZE 16

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_CRYPTO)

#define ESB_CRYPTO_OVERHEAD (ESB_CRYPTO_HEADER_SIZE + ESB_CRYPTO_TAG_SIZE)

/**
 * Load the key and the persisted counters. Call once, from thread context,
 * before the radio is started.
 */
int esb_crypto_init(void);

/** True when a valid key is provisioned, i.e. the link must be sealed. */
bool esb_crypto_enabled(void);

/**
 * Encrypt and authenticate @p len bytes. Thread context only.
 *
 * @return sealed length (len + ESB_CRYPTO_OVERHEAD) or a negative errno.
 */
int esb_crypto_seal(const uint8_t *in, size_t len, uint8_t *out, size_t out_size);

/**
 * Authenticate, decrypt and replay-check a sealed packet. ISR safe, but all
 * calls must come from one context (the ESB event handler).
 *
 * @return plain length, -EBADMSG if not authentic, -EALREADY for a replayed
 *         or duplicated packet, or another negative errno.
 */
int esb_crypto_open(const uint8_t *in, size_t len, uint8_t *out, size_t out_size);

#else

#define ESB_CRYPTO_OVERHEAD 0

static inline int esb_crypto_init(void) { return 0; }
static inline bool esb_crypto_enabled(void) { return false; }
static inline int esb_crypto_seal(const uint8_t *in, size_t len, uint8_t *out, size_t out_size) {
    return -ENOTSUP;
}
static inline int esb_crypto_open(const uint8_t *in, size_t len, uint8_t *out, size_t out_size) {
    return -ENOTSUP;
}

#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_CRYPTO) */
