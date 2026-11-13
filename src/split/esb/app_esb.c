/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "app_esb.h"
#include "esb_crypto.h"
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>
#include <esb.h>

#include <zmk/events/activity_state_changed.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(app_esb, CONFIG_ZMK_SPLIT_ESB_LOG_LEVEL);

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
#include "timeslot.h"
static void on_timeslot_start_stop(zmk_split_esb_timeslot_callback_type_t type);
#endif

#define DT_DRV_COMPAT zmk_esb_split
#if DT_HAS_COMPAT_STATUS_OKAY(DT_DRV_COMPAT)

#define HAS_BASE_ADDR_0 (DT_INST_NODE_HAS_PROP(0, base_addr_0))
#define HAS_BASE_ADDR_1 (DT_INST_NODE_HAS_PROP(0, base_addr_1))
#define HAS_ADDR_PREFIX (DT_INST_NODE_HAS_PROP(0, addr_prefix))

#define BASE_ADDR_0_LEN (DT_INST_PROP_LEN(0, base_addr_0))
#define BASE_ADDR_1_LEN (DT_INST_PROP_LEN(0, base_addr_1))
#define ADDR_PREFIX_LEN (DT_INST_PROP_LEN(0, addr_prefix))

#if (!HAS_BASE_ADDR_0 || BASE_ADDR_0_LEN != 4)
#error "zmk,esb-split :: base-addr-0 must include 4 bytes"
#endif

#if (!HAS_BASE_ADDR_1 || BASE_ADDR_1_LEN != 4)
#error "zmk,esb-split :: base-addr-1 must include 4 bytes"
#endif

#if (!HAS_ADDR_PREFIX || ADDR_PREFIX_LEN > CONFIG_ESB_PIPE_COUNT)
#error "zmk,esb-split :: base-addr-0 must include 8 bytes"
#endif

uint8_t esb_base_addr_0[BASE_ADDR_0_LEN] = DT_INST_PROP(0, base_addr_0);
uint8_t esb_base_addr_1[BASE_ADDR_1_LEN] = DT_INST_PROP(0, base_addr_1);
uint8_t esb_addr_prefix[ADDR_PREFIX_LEN] = DT_INST_PROP(0, addr_prefix);

#else
#error "Need to create a node with compatible of 'zmk,esb-split` with `all `address` property set."
#endif

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP)

#include <zephyr/sys/util_macro.h>

#define RF_CH_IDX(n, _) (CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP_CH_MIN + (n) * CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP_CH_STEP)
static uint8_t esb_rf_ch[CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP_CH_COUNT] = {
    LISTIFY(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP_CH_COUNT, RF_CH_IDX, (,))
};

static uint8_t esb_rf_ch_idx;

uint8_t esb_rf_ch_hop() {
    esb_rf_ch_idx = ++esb_rf_ch_idx % ARRAY_SIZE(esb_rf_ch);
    LOG_DBG("rf ch: %d", esb_rf_ch[esb_rf_ch_idx]);
    esb_set_rf_channel(esb_rf_ch[esb_rf_ch_idx]);
    return esb_rf_ch[esb_rf_ch_idx];
}

#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP) */

static app_esb_callback_t m_callback;

// Track msgq full errors
static uint32_t m_msgq_full_last_time;

/*
 * TX bookkeeping. CONFIG_ESB_TX_FIFO_SIZE is 1, so at most one payload is
 * ever handed to the ESB library at a time:
 *
 *   m_msgq_tx_payloads  payloads waiting for their first attempt (FIFO)
 *   m_inflight          the payload the ESB library is sending right now (PTX)
 *   m_retry             a payload whose attempt failed, re-sent before
 *                       anything newer so that events never overtake each other
 *
 * All of it is only touched with interrupts locked (see tx_pump()), because
 * it is used from both thread context and the ESB event handler.
 */
struct tx_item {
    struct esb_payload payload;
    uint8_t retries_left;
};

BUILD_ASSERT(CONFIG_ESB_TX_FIFO_SIZE == 1, "TX bookkeeping assumes CONFIG_ESB_TX_FIFO_SIZE=1");

// Define a buffer of payloads to store TX payloads in between timeslots
K_MSGQ_DEFINE(m_msgq_tx_payloads, sizeof(struct tx_item),
              CONFIG_ZMK_SPLIT_ESB_PROTO_MSGQ_ITEMS, 4);

static struct tx_item m_inflight;
static bool m_inflight_valid;
static uint32_t m_inflight_since;
static struct tx_item m_retry;
static bool m_retry_pending;
static struct tx_item m_next; // scratch for tx_pump(), too big for the ISR stack

static void reset_tx_state(void) {
    unsigned int key = irq_lock();
    m_inflight_valid = false;
    m_retry_pending = false;
    irq_unlock(key);
}

static app_esb_mode_t m_mode;
static bool m_active = false;
static bool m_enabled = false;

static int pull_packet_from_tx_msgq(void);

static void event_handler(struct esb_evt const *event) {
    app_esb_event_t m_event;
    switch (event->evt_id) {
        case ESB_EVENT_TX_SUCCESS:
            // LOG_DBG("TX SUCCESS, tx_attempts: %d", event->tx_attempts);
            m_inflight_valid = false;
            // Forward an event to the application
            m_event.evt_type = APP_ESB_EVT_TX_SUCCESS;
            m_callback(&m_event);
            pull_packet_from_tx_msgq();
            break;
        case ESB_EVENT_TX_FAILED:
            // LOG_WRN("TX FAILED, tx_attempts: %d", event->tx_attempts);
            if (m_inflight_valid) {
                m_inflight_valid = false;
                if (m_inflight.retries_left > 0) {
                    // Goes out again first, ahead of anything queued meanwhile
                    m_inflight.retries_left--;
                    m_retry = m_inflight;
                    m_retry_pending = true;
                } else {
                    LOG_WRN("TX failed, no retries left, payload dropped");
                }
            }

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP)
            esb_rf_ch_hop();
#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP) */

            // The failed payload stays in the ESB TX FIFO until flushed
            esb_flush_tx();
            // Forward an event to the application
            m_event.evt_type = APP_ESB_EVT_TX_FAIL;
            m_callback(&m_event);
            pull_packet_from_tx_msgq();
            break;
        case ESB_EVENT_RX_RECEIVED:
            // LOG_DBG("RX SUCCESS");
            struct esb_payload rx_payload;
            while (esb_read_rx_payload(&rx_payload) == 0) {
                // LOG_DBG("Chunk %d, pipe: %d, len: %d",
                //     rx_payload.pid, rx_payload.pipe, rx_payload.length);
                uint8_t buf[CONFIG_ESB_MAX_PAYLOAD_LENGTH];
                int len = rx_payload.length;
                if (esb_crypto_enabled()) {
                    // Drops anything unsealed, forged, replayed or duplicated
                    len = esb_crypto_open(rx_payload.data, rx_payload.length, buf, sizeof(buf));
                    if (len < 0) {
                        if (len != -EALREADY) {
                            LOG_WRN("Dropped unauthentic packet on pipe %d (%d)",
                                    rx_payload.pipe, len);
                        }
                        continue;
                    }
                } else if (len > 0 && rx_payload.data[0] == ESB_CRYPTO_VERSION) {
                    // Sealed by a peer, but this device has no key
                    LOG_WRN("Dropped encrypted packet: no key provisioned here");
                    continue;
                } else {
                    memcpy(buf, rx_payload.data, len);
                }
                // LOG_DBG("Packet len: %d", len);
                m_event.evt_type = APP_ESB_EVT_RX;
                m_event.pipe = rx_payload.pipe;
                m_event.buf = buf;
                m_event.data_length = len;
                m_callback(&m_event);
            }
            if (m_mode == APP_ESB_MODE_PRX) {
              pull_packet_from_tx_msgq();
            }
            break;
    }
}

static int clocks_start(void) {
    int err;
    int res;
    struct onoff_manager *clk_mgr;
    struct onoff_client clk_cli;

    clk_mgr = z_nrf_clock_control_get_onoff(CLOCK_CONTROL_NRF_SUBSYS_HF);
    if (!clk_mgr) {
        LOG_ERR("Unable to get the Clock manager");
        return -ENXIO;
    }

    sys_notify_init_spinwait(&clk_cli.notify);

    err = onoff_request(clk_mgr, &clk_cli);
    if (err < 0) {
        LOG_ERR("Clock request failed: %d", err);
        return err;
    }

    do {
        err = sys_notify_fetch_result(&clk_cli.notify, &res);
        if (!err && res) {
            LOG_ERR("Clock could not be started: %d", res);
            return res;
        }
    } while (err);

    LOG_DBG("HF clock started");
    return 0;
}

static int esb_initialize(app_esb_mode_t mode) {
    int err;
    struct esb_config config = ESB_DEFAULT_CONFIG;

    config.protocol = ESB_PROTOCOL_ESB_DPL;
    config.retransmit_delay = CONFIG_ZMK_SPLIT_ESB_PROTO_TX_RETRANSMIT_DELAY;
    config.retransmit_count = CONFIG_ZMK_SPLIT_ESB_PROTO_TX_RETRANSMIT_COUNT;
    config.bitrate = ESB_BITRATE_2MBPS;
    config.use_fast_ramp_up = true;
    config.event_handler = event_handler;
    config.mode = (mode == APP_ESB_MODE_PTX) ? ESB_MODE_PTX : ESB_MODE_PRX;
    config.tx_mode = ESB_TXMODE_MANUAL_START;
    config.selective_auto_ack = true;
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_CTLR_TX_PWR_PLUS_8)
    config.tx_output_power = ESB_TX_POWER_8DBM;
#endif

    err = esb_init(&config);

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP)
    esb_set_rf_channel(esb_rf_ch[esb_rf_ch_idx]);
#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_RF_CH_HOP) */

    if (err) {
        return err;
    }

    err = esb_set_base_address_0(esb_base_addr_0);
    if (err) {
        return err;
    }

    err = esb_set_base_address_1(esb_base_addr_1);
    if (err) {
        return err;
    }

    err = esb_set_prefixes(esb_addr_prefix, ARRAY_SIZE(esb_addr_prefix));
    if (err) {
        return err;
    }

    NVIC_SetPriority(RADIO_IRQn, 0);

    if (mode == APP_ESB_MODE_PRX) {
        esb_start_rx();
    }

    return 0;
}

#define ESB_TX_FIFO_REQUE_MAX (CONFIG_ZMK_SPLIT_ESB_PROTO_MSGQ_ITEMS \
                               * CONFIG_ZMK_SPLIT_ESB_PROTO_TX_RETRANSMIT_COUNT)

#define TX_RESULT_TIMEOUT_MS 200

// Hand the next payload to the ESB library, if it can take one.
// Must be called with interrupts locked.
static int tx_pump(void) {
    static uint16_t fifo_full_count = 0;

    if (m_mode == APP_ESB_MODE_PTX) {
        if (!esb_is_idle()) {
            return -EBUSY;
        }
        if (m_inflight_valid) {
            // Radio already idle, but the result of the last TX has not been
            // handled yet: it must be, before the next payload goes out.
            if (k_uptime_get_32() - m_inflight_since < TX_RESULT_TIMEOUT_MS) {
                return -EBUSY;
            }
            // A whole TX with all retransmits takes a few ms. The result is
            // not coming any more; do not let that block the link forever.
            LOG_WRN("TX result never arrived, payload dropped");
            m_inflight_valid = false;
            esb_flush_tx();
        }
    }

    if (m_retry_pending) {
        m_next = m_retry;
    } else if (k_msgq_peek(&m_msgq_tx_payloads, &m_next) != 0) {
        return 0; // nothing to send
    }

    int ret = esb_write_payload(&m_next.payload);

    if (ret == -ENOMEM && m_mode == APP_ESB_MODE_PTX) {
        // Idle with nothing in flight, so whatever sits in the FIFO is stale
        esb_flush_tx();
        ret = esb_write_payload(&m_next.payload);
    }

    if (ret == -ENOMEM) {
        // LOG_WRN("esb_tx_fifo: queue full %d", fifo_full_count);
        // force dequeue, guarding for phantom PRX.
        esb_flush_tx();
        if (++fifo_full_count < ESB_TX_FIFO_REQUE_MAX) {
            return ret; // keep the payload, try again on the next pump
        }
    } else if (ret == 0 && m_mode == APP_ESB_MODE_PTX) {
        int esb_ret = esb_start_tx();
        if (esb_ret < 0) {
            // Not started: take it back so the next pump starts clean
            LOG_WRN("esb_start_tx failed (%d)", esb_ret);
            esb_flush_tx();
            return esb_ret;
        }
        m_inflight = m_next;
        m_inflight_valid = true;
        m_inflight_since = k_uptime_get_32();
    } else if (ret == -EMSGSIZE) {
        LOG_WRN("esb_tx_fifo: tx_payload size too large (%d) > CONFIG_ESB_MAX_PAYLOAD_LENGTH (%d)",
                m_next.payload.length, CONFIG_ESB_MAX_PAYLOAD_LENGTH);
    } else if (ret) {
        LOG_WRN("esb_write_payload failed (%d), payload dropped", ret);
    }

    // Written, or given up on: either way it leaves the queue
    if (m_retry_pending) {
        m_retry_pending = false;
    } else {
        k_msgq_get(&m_msgq_tx_payloads, &m_next, K_NO_WAIT);
    }
    fifo_full_count = 0;

    return ret;
}

static int pull_packet_from_tx_msgq(void) {
    // Runs from thread context and from the ESB event handler, and from more
    // than one thread: one at a time. It is short, and returns at once while
    // the radio is busy sending.
    unsigned int key = irq_lock();
    int ret = tx_pump();
    irq_unlock(key);
    return ret;
}

int zmk_split_esb_init(app_esb_mode_t mode, app_esb_callback_t callback) {
    int ret;
    m_callback = callback;
    m_mode = mode;
    ret = esb_crypto_init();
    if (ret < 0) {
        // Keeps going: with a key present but unusable counters nothing is sent
        LOG_ERR("esb_crypto_init failed: %d", ret);
    }
    ret = clocks_start();
    if (ret < 0) {
        return ret;
    }
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
    LOG_INF("Timeslothandler init");
    zmk_split_esb_timeslot_init(on_timeslot_start_stop);
#else
    ret = zmk_split_esb_set_enable(true);
    if (ret) {
        LOG_ERR("esb enable failed: %d", ret);
    }
#endif
    return 0;
}

int zmk_split_esb_set_enable(bool enabled) {
    m_enabled = enabled;
    if (enabled) {
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
        zmk_split_esb_timeslot_open_session();
#else
        int ret = esb_initialize(m_mode);
        if (ret) {
            LOG_ERR("set_enable: esb_initialize failed: %d", ret);
            return ret;
        }
        m_active = true;
        if (m_mode == APP_ESB_MODE_PTX) {
            reset_tx_state();
        }
        pull_packet_from_tx_msgq();
#endif
        return 0;
    } else {
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
        zmk_split_esb_timeslot_close_session();
#else
        m_active = false;
        esb_disable();
#endif
        return 0;
    }
}

int zmk_split_esb_send(app_esb_data_t *tx_packet) {
    int ret = 0;
    struct tx_item item = {.retries_left = tx_packet->max_retry};
    struct esb_payload *tx_payload = &item.payload;

    if (!tx_packet->len) {
        LOG_WRN("bypass queuing null payload");
        return 0;
    }

    tx_payload->pipe = tx_packet->pipe;
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_PROTO_TX_ACK)
    tx_payload->noack = false;
#else
    tx_payload->noack = true;
#endif

    if (esb_crypto_enabled()) {
        // With a key provisioned nothing leaves unsealed
        ret = esb_crypto_seal(tx_packet->data, tx_packet->len, tx_payload->data,
                              sizeof(tx_payload->data));
        if (ret < 0) {
            LOG_ERR("Failed to seal payload (%d), dropped", ret);
            return ret;
        }
        tx_payload->length = ret;
    } else {
        if (tx_packet->len > sizeof(tx_payload->data)) {
            LOG_ERR("Payload too large (%d), dropped", (int)tx_packet->len);
            return -EMSGSIZE;
        }
        memcpy(tx_payload->data, tx_packet->data, tx_packet->len);
        tx_payload->length = tx_packet->len;
    }

    ret = k_msgq_put(&m_msgq_tx_payloads, &item, K_NO_WAIT);

    if (ret == 0) {
        m_msgq_full_last_time = 0;
    } else if (ret == -ENOMSG) {
        uint32_t now = k_uptime_get_32();
        if (!m_msgq_full_last_time) {
            m_msgq_full_last_time = now;
        }
        if (now - m_msgq_full_last_time > CONFIG_ZMK_SPLIT_ESB_MSGQ_FULL_TIMEOUT_MS) {
            LOG_WRN("Msgq full for %dms, clearing msgq and pending retry",
                CONFIG_ZMK_SPLIT_ESB_MSGQ_FULL_TIMEOUT_MS);
            k_msgq_purge(&m_msgq_tx_payloads);
            reset_tx_state();
            if (m_active) {
                esb_flush_tx();
            }
            m_msgq_full_last_time = 0;
        }
    } else {
        LOG_DBG("Failed to queue esb tx_payload_q (%d)", ret);
    }
    if (m_active) {
        pull_packet_from_tx_msgq();
    }
    return ret;
}

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
static int app_esb_suspend(void) {
    m_active = false;
    if (m_mode == APP_ESB_MODE_PTX) {
        uint32_t irq_key = irq_lock();

        irq_disable(RADIO_IRQn);
        NVIC_DisableIRQ(RADIO_IRQn);

        NRF_RADIO->SHORTS = 0;

        NRF_RADIO->EVENTS_DISABLED = 0;
        NRF_RADIO->TASKS_DISABLE = 1;
        while (NRF_RADIO->EVENTS_DISABLED == 0);

        NRF_TIMER2->TASKS_STOP = 1;
        NRF_RADIO->INTENCLR = 0xFFFFFFFF;
        
        esb_disable();

        NVIC_ClearPendingIRQ(RADIO_IRQn);

        irq_unlock(irq_key);
    }
    else {
        esb_stop_rx();
    }

    // Todo: Figure out how to use the esb_suspend() function 
    // rather than having to disable at the end of every timeslot
    //esb_suspend();
    return 0;
}

static int app_esb_resume(void) {
    if (m_mode == APP_ESB_MODE_PTX) {
        int err = esb_initialize(m_mode);
        m_active = true;
        reset_tx_state();
        pull_packet_from_tx_msgq();
        return err;
    }
    else {
        int err = esb_initialize(m_mode);
        m_active = true;
        pull_packet_from_tx_msgq();
        return err;
    }
}

/* Callback function signalling that a timeslot is started or stopped */
static void on_timeslot_start_stop(zmk_split_esb_timeslot_callback_type_t type) {
    switch (type) {
        case APP_TS_STARTED:
            app_esb_resume();
            break;
        case APP_TS_STOPPED:
            app_esb_suspend();
            break;
    }
}
#endif

static int on_activity_state(const zmk_event_t *eh) {
    struct zmk_activity_state_changed *state_ev = as_zmk_activity_state_changed(eh);
    if (!state_ev) {
        return 0;
    }

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT)
    if (m_mode == APP_ESB_MODE_PTX) {
        if (state_ev->state != ZMK_ACTIVITY_ACTIVE && m_enabled) {
            zmk_split_esb_set_enable(false);
        }
        else if (state_ev->state == ZMK_ACTIVITY_ACTIVE && !m_enabled) {
            zmk_split_esb_set_enable(true);
        }
    }
#endif

    return 0;
}

ZMK_LISTENER(zmk_split_esb_idle_sleeper, on_activity_state);
ZMK_SUBSCRIPTION(zmk_split_esb_idle_sleeper, zmk_activity_state_changed);
