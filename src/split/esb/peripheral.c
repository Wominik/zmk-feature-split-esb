/*
 * Copyright (c) 2025 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/types.h>
#include <zephyr/init.h>

#include <zephyr/settings/settings.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/ring_buffer.h>

#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_SPLIT_ESB_LOG_LEVEL);

#include <zmk/stdlib.h>
#include <zmk/behavior.h>
#include <zmk/sensors.h>
#include <zmk/split/transport/peripheral.h>
#include <zmk/split/transport/types.h>
#include <zmk/event_manager.h>
#include <zmk/events/position_state_changed.h>
#include <zmk/events/sensor_event.h>
#include <zmk/pointing/input_split.h>
#include <zmk/hid_indicators_types.h>
#include <zmk/physical_layouts.h>

#include "app_esb.h"
#include "common.h"
#include "esb_crypto.h"

#define RX_BUFFER_SIZE (sizeof(struct esb_command_envelope) + ESB_MSG_POSTFIX_SIZE)

// Every event has to fit a single ESB payload, sealed or not
BUILD_ASSERT(sizeof(struct esb_event_envelope) + ESB_MSG_POSTFIX_SIZE + ESB_CRYPTO_OVERHEAD <=
                 CONFIG_ESB_MAX_PAYLOAD_LENGTH,
             "CONFIG_ESB_MAX_PAYLOAD_LENGTH is too small for a peripheral event");

#define RX_RING_BUF_SIZE (RX_BUFFER_SIZE * CONFIG_ZMK_SPLIT_ESB_CMD_BUFFER_ITEMS)
struct ring_buf rx_bufs[CONFIG_ESB_PIPE_COUNT];
uint8_t rx_bufs_data[CONFIG_ESB_PIPE_COUNT][RX_RING_BUF_SIZE];

static const uint8_t peripheral_id = CONFIG_ZMK_SPLIT_ESB_PERIPHERAL_ID;

static void process_rx_cb(uint8_t pipe);

static struct zmk_split_esb_state state = {
    .tx_pipe = CONFIG_ZMK_SPLIT_ESB_PERIPHERAL_ID % CONFIG_ESB_PIPE_COUNT,
    .process_rx_callback = process_rx_cb,
    .rx_bufs = rx_bufs,
};

void zmk_split_esb_on_ptx_esb_callback(app_esb_event_t *event) {
    zmk_split_esb_cb(event, &state);
}

static ssize_t get_payload_data_size(const struct zmk_split_transport_peripheral_event *evt) {
    switch (evt->type) {
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_INPUT_EVENT:
        return sizeof(evt->data.input_event);
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_KEY_POSITION_EVENT:
        return sizeof(evt->data.key_position_event);
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_SENSOR_EVENT:
        return sizeof(evt->data.sensor_event);
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_BATTERY_EVENT:
        return sizeof(evt->data.battery_event);
    default:
        return -ENOTSUP;
    }
}

static uint8_t get_retry_count(const struct zmk_split_transport_peripheral_event *evt) {
    switch (evt->type) {
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_INPUT_EVENT:
        return CONFIG_ZMK_SPLIT_ESB_RETRY_INPUT_EVENT;
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_KEY_POSITION_EVENT:
        return CONFIG_ZMK_SPLIT_ESB_RETRY_KEY_POSITION;
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_SENSOR_EVENT:
        return CONFIG_ZMK_SPLIT_ESB_RETRY_SENSOR_EVENT;
    case ZMK_SPLIT_TRANSPORT_PERIPHERAL_EVENT_TYPE_BATTERY_EVENT:
        return CONFIG_ZMK_SPLIT_ESB_RETRY_BATTERY_EVENT;
    default:
        return 0;
    }
}

static int
split_peripheral_esb_report_event(const struct zmk_split_transport_peripheral_event *event) {
    ssize_t data_size = get_payload_data_size(event);
    if (data_size < 0) {
        LOG_WRN("Failed to determine payload data size %d", data_size);
        return data_size;
    }

    size_t payload_size = data_size
                        + sizeof(peripheral_id)
                        + sizeof(enum zmk_split_transport_peripheral_event_type);

    struct esb_event_envelope env = {.prefix = {
                                        .magic_prefix = ZMK_SPLIT_ESB_ENVELOPE_MAGIC_PREFIX,
                                        .payload_size = payload_size,
                                    },
                                    .payload = {
                                        .source = peripheral_id,
                                        .event = *event,
                                    }};

    size_t evt_env_len = sizeof(env.prefix) + payload_size;
    // LOG_HEXDUMP_DBG(&env, evt_env_len, "ota payload");

    return zmk_split_esb_tx(&state, (uint8_t *)&env, evt_env_len, get_retry_count(event));
}

static zmk_split_transport_peripheral_status_changed_cb_t transport_status_cb;
static bool is_enabled = false;

static int split_peripheral_esb_set_enabled(bool enabled) {
    is_enabled = enabled;
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ESB_USE_TIMESLOT) 
    return zmk_split_esb_set_enable(enabled);
#else
    return 0;
#endif
}

static int
split_peripheral_esb_set_status_callback(zmk_split_transport_peripheral_status_changed_cb_t cb) {
    transport_status_cb = cb;
    return 0;
}

static struct zmk_split_transport_status split_peripheral_esb_get_status(void) {
    return (struct zmk_split_transport_status){
        .available = true,
        .enabled = is_enabled,
        .connections = ZMK_SPLIT_TRANSPORT_CONNECTIONS_STATUS_ALL_CONNECTED,
    };
}

static const struct zmk_split_transport_peripheral_api peripheral_api = {
    .report_event = split_peripheral_esb_report_event,
    .set_enabled = split_peripheral_esb_set_enabled,
    .set_status_callback = split_peripheral_esb_set_status_callback,
    .get_status = split_peripheral_esb_get_status,
};

ZMK_SPLIT_TRANSPORT_PERIPHERAL_REGISTER(esb_peripheral, &peripheral_api,
                                        CONFIG_ZMK_SPLIT_ESB_PRIORITY);

static void notify_transport_status(void) {
    if (transport_status_cb) {
        transport_status_cb(&esb_peripheral, split_peripheral_esb_get_status());
    }
}

static void notify_status_work_cb(struct k_work *_work) { notify_transport_status(); }

static K_WORK_DEFINE(notify_status_work, notify_status_work_cb);

static int zmk_split_esb_peripheral_init(void) {
    for (int i = 0; i < CONFIG_ESB_PIPE_COUNT; i++) {
        ring_buf_init(&rx_bufs[i], RX_RING_BUF_SIZE, rx_bufs_data[i]);
    }
    int ret = zmk_split_esb_init(APP_ESB_MODE_PTX, zmk_split_esb_on_ptx_esb_callback);
    if (ret < 0) {
        LOG_ERR("zmk_split_esb_init failed (ret %d)", ret);
        return ret;
    }
    k_work_submit(&notify_status_work);
    return 0;
}

SYS_INIT(zmk_split_esb_peripheral_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

static void process_rx_work_cb(struct k_work *work) {
    for (int pipe = 0; pipe < CONFIG_ESB_PIPE_COUNT; pipe++) {
        struct ring_buf *rx_buf = &state.rx_bufs[pipe];
        while (ring_buf_size_get(rx_buf) > ESB_MSG_EXTRA_SIZE) {
            struct esb_command_envelope env;
            int item_err = zmk_split_esb_get_item(rx_buf, (uint8_t *)&env,
                                                  sizeof(struct esb_command_envelope));
            switch (item_err) {
            case 0:
                if (env.payload.cmd.type == ZMK_SPLIT_TRANSPORT_CENTRAL_CMD_TYPE_POLL_EVENTS) {
                    break;
                }
                if (env.payload.source != peripheral_id) {
                    LOG_WRN("Ignoring command type %d for source %d (expect %d)", 
                            env.payload.cmd.type, env.payload.source, peripheral_id);
                    break;
                }
                zmk_split_transport_peripheral_command_handler(&esb_peripheral, env.payload.cmd);
                break;
            case -EAGAIN:
                break;
            default:
                // LOG_WRN("Issue fetching an item from the RX buffer: %d", item_err);
                break;
            }
        }
    }
}

K_WORK_DEFINE(process_rx_work, process_rx_work_cb);

static void process_rx_cb(uint8_t pipe) {
    k_work_submit(&process_rx_work);
}
