/*
 * Copyright (c) 2026 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * Authenticated encryption for the ESB split link.
 *
 * Cipher: ChaCha20-Poly1305 (RFC 8439) from nrf_oberon, 256-bit key, 96-bit
 * nonce, 128-bit tag.
 *
 * Key: a pre-shared key that every device of one keyboard set holds (both
 * halves and any number of dongles). It is NOT part of the firmware image:
 * it lives in its own flash block, provisioned once per device with a small
 * UF2 file, so firmware can be built in public CI. Without a valid key block
 * the link stays unsealed, exactly as before; with one, nothing unsealed is
 * sent or accepted.
 *
 * Packet: version(1) | sender(4) | epoch(4) | seq(4) | ciphertext | tag(16)
 *
 * Nonce = sender | epoch | seq, never repeats for a key:
 *   - sender: derived from the factory device id, differs per device
 *   - epoch:  boot counter kept in flash, bumped on every boot
 *   - seq:    packet counter since boot
 *
 * Replay: a receiver keeps (epoch, highest seq, 64-packet window) per sender
 * and drops anything older or already seen. That also de-duplicates packets
 * the sender repeated because an ACK got lost. The last epoch of each sender
 * is persisted, so packets recorded before a sender's most recent boot stay
 * rejected even after the receiver itself restarts. What is NOT covered:
 * right after a receiver restart, packets the sender produced since its own
 * last boot are accepted once more.
 */

#include "esb_crypto.h"

#include <string.h>

#include <zephyr/drivers/hwinfo.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/crc.h>

#include <ocrypto_chacha20_poly1305.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_SPLIT_ESB_LOG_LEVEL);

BUILD_ASSERT(IS_ENABLED(CONFIG_SETTINGS), "ESB crypto needs CONFIG_SETTINGS for its counters");

#ifdef CONFIG_ZMK_LOW_PRIORITY_THREAD_STACK_SIZE
/* ZMK reports battery level changes from its low priority work queue, and on
 * a peripheral that ends in sealing a packet on that thread's stack. */
BUILD_ASSERT(IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL) ||
                 CONFIG_ZMK_LOW_PRIORITY_THREAD_STACK_SIZE >= 1536,
             "ESB crypto needs CONFIG_ZMK_LOW_PRIORITY_THREAD_STACK_SIZE >= 1536");
#endif

/* Key block as written by the provisioning UF2 */
#define KEY_BLOCK_ADDR ((const uint8_t *)CONFIG_ZMK_SPLIT_ESB_CRYPTO_KEY_ADDR)
#define KEY_MAGIC "ZESBKEY1"
#define KEY_MAGIC_LEN 8
#define KEY_LEN 32
#define KEY_BLOCK_CRC_OFFSET (KEY_MAGIC_LEN + KEY_LEN)

#define NONCE_LEN 12
#define AAD_LEN 1
#define REPLAY_WINDOW 64

#define SETTINGS_SUBTREE "esbsec"
#define SETTINGS_EPOCH SETTINGS_SUBTREE "/epoch"
#define SETTINGS_PEERS SETTINGS_SUBTREE "/peers"

/* Write peer epochs to flash only once the link has been quiet this long */
#define PEERS_SAVE_DELAY K_SECONDS(3)

static bool key_valid;
static bool tx_ready;
static uint8_t key[KEY_LEN];
static uint32_t self_id;
static uint32_t self_epoch;
static atomic_t self_seq;

struct peer {
    uint32_t id; /* 0 = free slot */
    uint32_t epoch;
    uint32_t last_seq;
    uint64_t window; /* bit n set = (last_seq - n) already seen */
};

struct peer_record {
    uint32_t id;
    uint32_t epoch;
} __packed;

static struct peer peers[CONFIG_ZMK_SPLIT_ESB_CRYPTO_MAX_PEERS];
static bool peers_dirty;

static void peers_save_work_cb(struct k_work *work) {
    struct peer_record records[ARRAY_SIZE(peers)];

    unsigned int irq_key = irq_lock();
    for (size_t i = 0; i < ARRAY_SIZE(peers); i++) {
        records[i].id = peers[i].id;
        records[i].epoch = peers[i].epoch;
    }
    peers_dirty = false;
    irq_unlock(irq_key);

    int err = settings_save_one(SETTINGS_PEERS, records, sizeof(records));
    if (err) {
        LOG_ERR("Failed to save peer epochs (%d)", err);
    }
}

static K_WORK_DELAYABLE_DEFINE(peers_save_work, peers_save_work_cb);

static int settings_load_cb(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg,
                            void *param) {
    if (!name) {
        return 0;
    }
    if (!strcmp(name, "epoch")) {
        uint32_t stored;
        if (len == sizeof(stored) && read_cb(cb_arg, &stored, sizeof(stored)) == sizeof(stored)) {
            self_epoch = stored;
        }
    } else if (!strcmp(name, "peers")) {
        struct peer_record records[ARRAY_SIZE(peers)];
        ssize_t got = read_cb(cb_arg, records, MIN(len, sizeof(records)));
        size_t count = (got > 0) ? (size_t)got / sizeof(records[0]) : 0;
        for (size_t i = 0; i < count; i++) {
            peers[i].id = records[i].id;
            peers[i].epoch = records[i].epoch;
            /* last_seq/window start at 0: any seq of that epoch is still new */
        }
    }
    return 0;
}

static bool load_key(void) {
    const uint8_t *block = KEY_BLOCK_ADDR;

    if (memcmp(block, KEY_MAGIC, KEY_MAGIC_LEN) != 0) {
        return false;
    }
    if (crc32_ieee(block, KEY_BLOCK_CRC_OFFSET) != sys_get_le32(&block[KEY_BLOCK_CRC_OFFSET])) {
        LOG_ERR("ESB key block is corrupted");
        return false;
    }
    memcpy(key, &block[KEY_MAGIC_LEN], KEY_LEN);
    return true;
}

int esb_crypto_init(void) {
    key_valid = load_key();
    if (!key_valid) {
        LOG_WRN("No ESB key provisioned: the split link is NOT encrypted");
        return 0;
    }

    uint8_t hwid[8] = {0};
    ssize_t hwid_len = hwinfo_get_device_id(hwid, sizeof(hwid));
    if (hwid_len <= 0) {
        LOG_ERR("No device id (%d), refusing to send", (int)hwid_len);
        return -ENODEV;
    }
    self_id = sys_get_le32(&hwid[0]) ^ sys_get_le32(&hwid[4]);
    if (self_id == 0) {
        self_id = 1; /* 0 marks a free peer slot */
    }

    int err = settings_subsys_init();
    if (!err) {
        err = settings_load_subtree_direct(SETTINGS_SUBTREE, settings_load_cb, NULL);
    }
    if (!err) {
        /* A new epoch per boot keeps (epoch, seq) - and so the nonce - unique */
        self_epoch++;
        err = settings_save_one(SETTINGS_EPOCH, &self_epoch, sizeof(self_epoch));
    }
    if (err) {
        /* Without a stored epoch a nonce could repeat: fail closed */
        LOG_ERR("Failed to persist ESB epoch (%d), refusing to send", err);
        return err;
    }

    tx_ready = true;
    LOG_INF("ESB link encrypted (id %08x, epoch %u)", (unsigned int)self_id, (unsigned int)self_epoch);
    return 0;
}

bool esb_crypto_enabled(void) { return key_valid; }

int esb_crypto_seal(const uint8_t *in, size_t len, uint8_t *out, size_t out_size) {
    if (!tx_ready) {
        return -EACCES;
    }
    if (len + ESB_CRYPTO_OVERHEAD > out_size) {
        return -EMSGSIZE;
    }

    uint32_t seq = (uint32_t)atomic_inc(&self_seq) + 1;
    if (seq == UINT32_MAX) {
        /* 4 billion packets in one boot; stop rather than wrap the nonce */
        tx_ready = false;
        return -EACCES;
    }

    out[0] = ESB_CRYPTO_VERSION;
    sys_put_le32(self_id, &out[1]);
    sys_put_le32(self_epoch, &out[5]);
    sys_put_le32(seq, &out[9]);

    ocrypto_chacha20_poly1305_encrypt(&out[ESB_CRYPTO_HEADER_SIZE + len],
                                      &out[ESB_CRYPTO_HEADER_SIZE], in, len, out, AAD_LEN,
                                      &out[1], NONCE_LEN, key);

    return len + ESB_CRYPTO_OVERHEAD;
}

static struct peer *find_peer(uint32_t id) {
    struct peer *free_slot = NULL;

    for (size_t i = 0; i < ARRAY_SIZE(peers); i++) {
        if (peers[i].id == id) {
            return &peers[i];
        }
        if (!free_slot && peers[i].id == 0) {
            free_slot = &peers[i];
        }
    }
    if (free_slot) {
        /* Only reached for authenticated packets, so this is one of ours */
        free_slot->id = id;
        free_slot->epoch = 0;
        free_slot->last_seq = 0;
        free_slot->window = 0;
    }
    return free_slot;
}

int esb_crypto_open(const uint8_t *in, size_t len, uint8_t *out, size_t out_size) {
    if (!key_valid) {
        return -EACCES;
    }
    if (len <= ESB_CRYPTO_OVERHEAD || in[0] != ESB_CRYPTO_VERSION) {
        return -EBADMSG;
    }

    size_t plain_len = len - ESB_CRYPTO_OVERHEAD;
    if (plain_len > out_size) {
        return -EMSGSIZE;
    }

    uint32_t sender = sys_get_le32(&in[1]);
    uint32_t epoch = sys_get_le32(&in[5]);
    uint32_t seq = sys_get_le32(&in[9]);

    if (sender == 0 || sender == self_id) {
        return -EBADMSG;
    }

    if (ocrypto_chacha20_poly1305_decrypt(&in[ESB_CRYPTO_HEADER_SIZE + plain_len], out,
                                          &in[ESB_CRYPTO_HEADER_SIZE], plain_len, in, AAD_LEN,
                                          &in[1], NONCE_LEN, key) != 0) {
        return -EBADMSG;
    }

    /* Authentic. Counters are only ever moved by authentic packets. */
    struct peer *peer = find_peer(sender);
    if (!peer) {
        LOG_ERR("ESB peer table full, dropping packets from %08x", (unsigned int)sender);
        return -ENOMEM;
    }

    if (epoch < peer->epoch) {
        return -EALREADY;
    }

    if (epoch > peer->epoch) {
        peer->epoch = epoch;
        peer->last_seq = seq;
        peer->window = 1;
        peers_dirty = true;
    } else if (seq > peer->last_seq) {
        uint32_t shift = seq - peer->last_seq;
        peer->window = (shift >= REPLAY_WINDOW) ? 1 : ((peer->window << shift) | 1);
        peer->last_seq = seq;
    } else {
        uint32_t age = peer->last_seq - seq;
        if (age >= REPLAY_WINDOW || (peer->window & BIT64(age))) {
            return -EALREADY;
        }
        peer->window |= BIT64(age);
    }

    if (peers_dirty) {
        /* Pushed back by every packet, so flash is written while idle */
        k_work_reschedule(&peers_save_work, PEERS_SAVE_DELAY);
    }

    return plain_len;
}
