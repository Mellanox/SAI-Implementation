/*
 *  Copyright (C) 2019-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"

#undef  __MODULE__
#define __MODULE__ SAI_BFD

#define DEFAULT_BFD_NETNS "/proc/1/net"
#define MAX_NETNS_STR_LEN 15
char bfd_netns[MAX_NETNS_STR_LEN];

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_get_bfd_session_stats_ext(_In_ sai_object_id_t      bfd_session_id,
                                                   _In_ uint32_t             number_of_counters,
                                                   _In_ const sai_stat_id_t *counter_ids,
                                                   _In_ sai_stats_mode_t     mode,
                                                   _Out_ uint64_t           *counters);
static sai_status_t mlnx_bfd_session_attr_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_bfd_session_attr_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static sai_status_t mlnx_bfd_session_db_entry_alloc(_Out_ mlnx_bfd_session_db_entry_t **bfd_session_db_entry,
                                                    _Out_ mlnx_shm_rm_array_idx_t      *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(bfd_session_db_entry);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *bfd_session_db_entry = ptr;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bfd_session_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t        idx,
                                                          _Out_ mlnx_bfd_session_db_entry_t **bfd_session_db_entry)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *bfd_session_db_entry = (mlnx_bfd_session_db_entry_t*)data;

    if (!(*bfd_session_db_entry)->array_hdr.is_used) {
        SX_LOG_ERR("BFD session DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_bfd_session_oid_to_data(_In_ sai_object_id_t                oid,
                                                 _Out_ mlnx_bfd_session_db_entry_t **bfd_session_db_entry,
                                                 _Out_ mlnx_shm_rm_array_idx_t      *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(bfd_session_db_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BFD_SESSION, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_bfd_session_db_entry_idx_to_data(mlnx_oid.id.bfd_db_idx, bfd_session_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.bfd_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bfd_session_db_entry_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t                 status;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_bfd_session_db_entry_idx_to_data(idx, &bfd_session_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&bfd_session_db_entry->data, 0, sizeof(bfd_session_db_entry->data));

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_bfd_session_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t        *oid)
{
    sai_status_t      status;
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    assert(oid);

    status = mlnx_shm_rm_idx_validate(idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx.type != MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION) {
        return SAI_STATUS_FAILURE;
    }

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_BFD_SESSION;
    mlnx_oid->id.bfd_db_idx = idx;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fill_sdk_bfd_tx_params(_In_ const mlnx_bfd_session_db_data_t *bfd_db_data,
                                                _Out_ mlnx_bfd_packet_t               *tx_bfd_packet,
                                                _Out_ sx_bfd_session_params_t         *tx_params)
{
    sai_status_t             status;
    sx_bfd_session_tx_data_t tx_data;
    sx_ip_addr_t             sdk_src_addr;
    sx_ip_addr_t             sdk_dst_addr;

    assert(bfd_db_data);
    assert(tx_bfd_packet);
    assert(tx_params);

    status = mlnx_translate_sai_ip_address_to_sdk(&bfd_db_data->src_ip, &sdk_src_addr);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_translate_sai_ip_address_to_sdk(&bfd_db_data->dst_ip, &sdk_dst_addr);
    if (SAI_ERR(status)) {
        return status;
    }

    tx_bfd_packet->vers_diag = (1 << 5) |    /* BFD version */
                               (0 << 0);     /* Diag */
    tx_bfd_packet->flags = ((bfd_db_data->bfd_session_state) << 6) |        /* 2-bit Sta */
                           ((bfd_db_data->is_polling) << 5) |        /* P flag */
                           ((bfd_db_data->is_final) << 4) |        /* F flag */
                           (0 << 3) |        /* C flag */
                           (0 << 2) |        /* A flag */
                           (0 << 1) |        /* D flag */
                           (0 << 0);         /* M flag */
    tx_bfd_packet->mult = bfd_db_data->multiplier;
    tx_bfd_packet->length = sizeof(*tx_bfd_packet);
    tx_bfd_packet->my_disc = htonl(bfd_db_data->local_discriminator);
    tx_bfd_packet->your_disc = htonl(bfd_db_data->remote_discriminator);
    tx_bfd_packet->min_tx = htonl(bfd_db_data->min_tx);
    tx_bfd_packet->min_rx = htonl(bfd_db_data->min_rx);
    tx_bfd_packet->min_rx_echo = htonl(0); /* 0 - Not supported */

    tx_params->session_data.type = SX_BFD_ASYNC_ACTIVE_TX;
    tx_data.packet_encap.encap_type = SX_BFD_UDP_OVER_IP;
    tx_data.packet_encap.encap_data.udp_over_ip.src_udp_port = bfd_db_data->udp_src_port;
    tx_data.packet_encap.encap_data.udp_over_ip.dest_udp_port = (bfd_db_data->multihop ? 4784 : 3784);
    tx_data.packet_encap.encap_data.udp_over_ip.src_ip_addr = sdk_src_addr;
    tx_data.packet_encap.encap_data.udp_over_ip.dest_ip_addr = sdk_dst_addr;
    tx_data.packet_encap.encap_data.udp_over_ip.ttl = bfd_db_data->ttl;
    tx_data.packet_encap.encap_data.udp_over_ip.dscp = bfd_db_data->tos;
    tx_data.interval = MAX(bfd_db_data->min_tx, bfd_db_data->remote_min_rx);
    tx_data.traffic_class = bfd_db_data->traffic_class;
    tx_params->session_data.data.tx_data = tx_data;
    tx_params->packet.packet_buffer = (uint8_t*)tx_bfd_packet;
    tx_params->packet.buffer_length = sizeof(*tx_bfd_packet);
    tx_params->peer.peer_type = SX_BFD_PEER_IP_AND_VRF;
    tx_params->peer.peer_data.ip_and_vrf.ip_addr = sdk_dst_addr;
    tx_params->peer.peer_data.ip_and_vrf.vrf_id = bfd_db_data->vr_id;
    if (strlen(bfd_netns) > 0) {
        snprintf(tx_params->peer.peer_data.ip_and_vrf.netns, MAX_NETNS_STR_LEN + 16, "/var/run/netns/%s", bfd_netns);
    } else {
        memcpy(tx_params->peer.peer_data.ip_and_vrf.netns, DEFAULT_BFD_NETNS, sizeof(DEFAULT_BFD_NETNS));
    }
    memcpy(tx_params->peer.peer_data.ip_and_vrf.default_netns, DEFAULT_BFD_NETNS, sizeof(DEFAULT_BFD_NETNS));
    tx_params->bfd_pid = 0;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fill_sdk_bfd_rx_params(_In_ const mlnx_bfd_session_db_data_t *bfd_db_data,
                                                _In_ uint64_t                          opaque_data,
                                                _Out_ mlnx_bfd_packet_t               *rx_bfd_packet,
                                                _Out_ sx_bfd_session_params_t         *rx_params)
{
    sai_status_t status;
    sx_ip_addr_t sdk_src_addr;
    sx_ip_addr_t sdk_dst_addr;

    assert(bfd_db_data);
    assert(rx_bfd_packet);
    assert(rx_params);

    status = mlnx_translate_sai_ip_address_to_sdk(&bfd_db_data->src_ip, &sdk_src_addr);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_translate_sai_ip_address_to_sdk(&bfd_db_data->dst_ip, &sdk_dst_addr);
    if (SAI_ERR(status)) {
        return status;
    }

    rx_bfd_packet->vers_diag = (1 << 5) |    /* BFD version */
                               (0 << 0); /* Diag */
    rx_bfd_packet->flags = (3 << 6) |        /* 2-bit Sta */
                           (0 << 5) | /* P flag */
                           (0 << 4) | /* F flag */
                           (0 << 3) | /* C flag */
                           (0 << 2) | /* A flag */
                           (0 << 1) | /* D flag */
                           (0 << 0); /* M flag */
    rx_bfd_packet->mult = bfd_db_data->remote_multiplier;
    rx_bfd_packet->length = sizeof(*rx_bfd_packet);
    rx_bfd_packet->my_disc = htonl(bfd_db_data->remote_discriminator);
    rx_bfd_packet->your_disc = htonl(bfd_db_data->local_discriminator);
    rx_bfd_packet->min_tx = htonl(bfd_db_data->remote_min_tx);
    rx_bfd_packet->min_rx = htonl(bfd_db_data->remote_min_rx);
    /**rx_bfd_packet->min_rx_echo = htonl(0);  0 - Not supported */
    rx_bfd_packet->min_rx_echo = htonl(bfd_db_data->remote_echo);

    rx_params->session_data.type = SX_BFD_ASYNC_ACTIVE_RX;
    rx_params->session_data.data.rx_data.interval =
        MAX(bfd_db_data->min_rx, bfd_db_data->remote_min_tx) * bfd_db_data->remote_multiplier;
    rx_params->session_data.data.rx_data.opaque_data = opaque_data;
    rx_params->packet.packet_buffer = (uint8_t*)rx_bfd_packet;
    rx_params->packet.buffer_length = sizeof(*rx_bfd_packet);
    rx_params->peer.peer_type = SX_BFD_PEER_IP_AND_VRF;
    rx_params->peer.peer_data.ip_and_vrf.ip_addr = sdk_dst_addr;
    rx_params->peer.peer_data.ip_and_vrf.vrf_id = bfd_db_data->vr_id;
    if (strlen(bfd_netns) > 0) {
        snprintf(rx_params->peer.peer_data.ip_and_vrf.netns, MAX_NETNS_STR_LEN + 16, "/var/run/netns/%s", bfd_netns);
    } else {
        memcpy(rx_params->peer.peer_data.ip_and_vrf.netns, DEFAULT_BFD_NETNS, sizeof(DEFAULT_BFD_NETNS));
    }
    memcpy(rx_params->peer.peer_data.ip_and_vrf.default_netns, DEFAULT_BFD_NETNS, sizeof(DEFAULT_BFD_NETNS));
    rx_params->bfd_pid = 0;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bfd_session_destroy(_In_ mlnx_bfd_session_db_entry_t *bfd_session_db_entry)
{
    sx_status_t             sx_status_rx = SX_STATUS_SUCCESS;
    sx_status_t             sx_status_tx = SX_STATUS_SUCCESS;
    sx_bfd_session_params_t params = {0};

    if (bfd_session_db_entry->data.rx_session) {
        params.session_data.type = SX_BFD_ASYNC_ACTIVE_RX;
        sx_status_rx = sx_api_bfd_offload_set(gh_sdk,
                                              SX_ACCESS_CMD_DESTROY,
                                              &params,
                                              &bfd_session_db_entry->data.rx_session);
        if (SX_ERR(sx_status_rx)) {
            SX_LOG_ERR("Cannot remove RX BFD session id=%d, status=%s\n",
                       bfd_session_db_entry->data.rx_session,
                       SX_STATUS_MSG(sx_status_rx));
        }
    }

    if (bfd_session_db_entry->data.tx_session) {
        params.session_data.type = SX_BFD_ASYNC_ACTIVE_TX;
        sx_status_tx = sx_api_bfd_offload_set(gh_sdk,
                                              SX_ACCESS_CMD_DESTROY,
                                              &params,
                                              &bfd_session_db_entry->data.tx_session);
        if (SX_ERR(sx_status_tx)) {
            SX_LOG_ERR("Cannot remove TX BFD session id=%d, status=%s\n",
                       bfd_session_db_entry->data.tx_session,
                       SX_STATUS_MSG(sx_status_tx));
            return sdk_to_sai(sx_status_tx);
        }
    }

    return sdk_to_sai(sx_status_rx);
}

sai_status_t mlnx_set_offload_bfd_rx_session(_Inout_ mlnx_bfd_session_db_data_t *bfd_db_data,
                                             _In_ mlnx_shm_rm_array_idx_t        bfd_session_db_index,
                                             _In_ sx_access_cmd_t                cmd)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    sx_bfd_init_params_t    bfd_init_params;
    mlnx_bfd_packet_t       rx_bfd_packet = {0};
    sx_bfd_session_params_t rx_params = {0};

    assert(bfd_db_data);
    assert(cmd == SX_ACCESS_CMD_CREATE || cmd == SX_ACCESS_CMD_EDIT);

    status = mlnx_fill_sdk_bfd_rx_params(bfd_db_data,
                                         *(uint32_t*)&bfd_session_db_index,
                                         &rx_bfd_packet,
                                         &rx_params);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Cannot fill SDK rx BFD params.\n");
        return status;
    }

    if (!g_sai_db_ptr->is_bfd_module_initialized) {
        memset(&bfd_init_params, 0, sizeof(bfd_init_params));
        sx_status = sx_api_bfd_init_set(gh_sdk, &bfd_init_params);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Cannot init BFD module: %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            return status;
        }
        g_sai_db_ptr->is_bfd_module_initialized = true;
    }

    sx_status = sx_api_bfd_offload_set(gh_sdk, cmd, &rx_params, &bfd_db_data->rx_session);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error create RX BFD session: %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
    }

    return status;
}

sai_status_t mlnx_set_offload_bfd_tx_session(_Inout_ mlnx_bfd_session_db_data_t *bfd_db_data, _In_ sx_access_cmd_t cmd)
{
    sai_status_t            status;
    sx_status_t             sx_status;
    mlnx_bfd_packet_t       tx_bfd_packet = {0};
    sx_bfd_session_params_t tx_params = {0};

    assert(bfd_db_data);
    assert(cmd == SX_ACCESS_CMD_CREATE ||
           cmd == SX_ACCESS_CMD_EDIT);

    status = mlnx_fill_sdk_bfd_tx_params(bfd_db_data, &tx_bfd_packet, &tx_params);

    if (SAI_ERR(status)) {
        SX_LOG_ERR("Cannot fill SDK tx BFD params.\n");
        return status;
    }

    sx_status = sx_api_bfd_offload_set(gh_sdk, cmd, &tx_params, &bfd_db_data->tx_session);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error create TX BFD session: %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
    }

    return status;
}


static sai_status_t mlnx_bfd_session_counter_stats_get(_In_ mlnx_bfd_session_db_data_t *bfd_db_data,
                                                       _In_ sai_stat_id_t               stat,
                                                       _In_ bool                        clear,
                                                       _Out_ uint64_t                  *value)
{
    sx_status_t            sx_status;
    sx_access_cmd_t        cmd = clear ? SX_ACCESS_CMD_READ_CLEAR : SX_ACCESS_CMD_READ;
    sx_bfd_offload_stats_t sx_stats = {0};

    assert(MLNX_BFD_STAT_ID_RANGE_CHECK(stat));
    assert(bfd_db_data);
    assert(value);

    switch (stat) {
    case SAI_BFD_SESSION_STAT_IN_PACKETS:
        sx_status = sx_api_bfd_offload_get_stats(gh_sdk,
                                                 cmd,
                                                 SX_BFD_ASYNC_ACTIVE_RX,
                                                 &bfd_db_data->rx_session,
                                                 &sx_stats);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Get BFD session stats failed: %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        *value = sx_stats.bfd_session_stats.num_control;
        break;

    case SAI_BFD_SESSION_STAT_OUT_PACKETS:
        sx_status = sx_api_bfd_offload_get_stats(gh_sdk,
                                                 cmd,
                                                 SX_BFD_ASYNC_ACTIVE_TX,
                                                 &bfd_db_data->tx_session,
                                                 &sx_stats);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Get BFD session stats failed: %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        *value = sx_stats.bfd_session_stats.num_control;
        break;

    case SAI_BFD_SESSION_STAT_DROP_PACKETS:
        sx_status = sx_api_bfd_offload_get_stats(gh_sdk,
                                                 cmd,
                                                 SX_BFD_ASYNC_ACTIVE_RX,
                                                 &bfd_db_data->rx_session,
                                                 &sx_stats);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Get BFD session stats failed: %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
        *value = sx_stats.bfd_session_stats.num_dropped_control;
        break;

    default:
        SX_LOG_ERR("Unexpected counter id: %d\n", stat);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bfd_session_stats_get(_In_ sai_object_id_t      bfd_session_id,
                                        _In_ uint32_t             number_of_counters,
                                        _In_ const sai_stat_id_t *counter_ids,
                                        _In_ bool                 read,
                                        _In_ bool                 clear,
                                        _Out_ uint64_t           *counters)
{
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry;
    mlnx_bfd_session_db_data_t   bfd_db_data;
    uint64_t                     counter = 0;
    uint32_t                     ii;

    assert(counter_ids);
    assert(counters || !read);
    assert(!counters || read);

    sai_db_read_lock();

    status = mlnx_bfd_session_oid_to_data(bfd_session_id,
                                          &bfd_session_db_entry,
                                          NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Cannot get BFD DB data by OID - %" PRId64 ".\n", bfd_session_id);
        SX_LOG_EXIT();
        return status;
    }

    bfd_db_data = bfd_session_db_entry->data;

    sai_db_unlock();

    for (ii = 0; ii < number_of_counters; ii++) {
        status = mlnx_bfd_session_counter_stats_get(&bfd_db_data, counter_ids[ii], clear, &counter);
        if (SAI_ERR(status)) {
            return status;
        }

        if (read) {
            counters[ii] = counter;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t bfd_vendor_attribs[] = {
    { SAI_BFD_SESSION_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TYPE,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TYPE},
    { SAI_BFD_SESSION_ATTR_HW_LOOKUP_VALID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_HW_LOOKUP_VALID,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_HW_LOOKUP_VALID},
    { SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER},
    { SAI_BFD_SESSION_ATTR_PORT,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_PORT,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_PORT},
    { SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR},
    { SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR},
    { SAI_BFD_SESSION_ATTR_UDP_SRC_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_UDP_SRC_PORT,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_UDP_SRC_PORT},
    { SAI_BFD_SESSION_ATTR_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TC,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TC},
    { SAI_BFD_SESSION_ATTR_VLAN_TPID,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VLAN_TPID,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VLAN_TPID},
    { SAI_BFD_SESSION_ATTR_VLAN_ID,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VLAN_ID,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VLAN_ID},
    { SAI_BFD_SESSION_ATTR_VLAN_PRI,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VLAN_PRI,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VLAN_PRI},
    { SAI_BFD_SESSION_ATTR_VLAN_CFI,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VLAN_CFI,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VLAN_CFI},
    { SAI_BFD_SESSION_ATTR_VLAN_HEADER_VALID,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_VLAN_HEADER_VALID,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_VLAN_HEADER_VALID},
    { SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE},
    { SAI_BFD_SESSION_ATTR_IPHDR_VERSION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_IPHDR_VERSION,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_IPHDR_VERSION},
    { SAI_BFD_SESSION_ATTR_TOS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TOS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TOS},
    { SAI_BFD_SESSION_ATTR_TTL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TTL,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TTL},
    { SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS},
    { SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS},
    { SAI_BFD_SESSION_ATTR_TUNNEL_TOS,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_TOS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_TOS},
    { SAI_BFD_SESSION_ATTR_TUNNEL_TTL,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_TTL,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_TTL},
    { SAI_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS},
    { SAI_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS},
    { SAI_BFD_SESSION_ATTR_SRC_MAC_ADDRESS,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_SRC_MAC_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_SRC_MAC_ADDRESS},
    { SAI_BFD_SESSION_ATTR_DST_MAC_ADDRESS,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_DST_MAC_ADDRESS,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_DST_MAC_ADDRESS},
    { SAI_BFD_SESSION_ATTR_ECHO_ENABLE,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_ECHO_ENABLE,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_ECHO_ENABLE},
    { SAI_BFD_SESSION_ATTR_MULTIHOP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_MULTIHOP,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_MULTIHOP},
    { SAI_BFD_SESSION_ATTR_CBIT,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_CBIT,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_CBIT},
    { SAI_BFD_SESSION_ATTR_MIN_TX,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_MIN_TX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_MIN_TX},
    { SAI_BFD_SESSION_ATTR_MIN_RX,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_MIN_RX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_MIN_RX},
    { SAI_BFD_SESSION_ATTR_MULTIPLIER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_MULTIPLIER,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_MULTIPLIER},
    { SAI_BFD_SESSION_ATTR_REMOTE_MIN_TX,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MIN_TX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MIN_TX},
    { SAI_BFD_SESSION_ATTR_REMOTE_MIN_RX,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MIN_RX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MIN_RX},
    { SAI_BFD_SESSION_ATTR_STATE,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_STATE,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_STATE},
    { SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE},
    { SAI_BFD_SESSION_ATTR_NEGOTIATED_TX,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_NEGOTIATED_TX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_NEGOTIATED_TX},
    { SAI_BFD_SESSION_ATTR_NEGOTIATED_RX,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_NEGOTIATED_RX,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_NEGOTIATED_RX},
    { SAI_BFD_SESSION_ATTR_LOCAL_DIAG,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_LOCAL_DIAG,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_LOCAL_DIAG},
    { SAI_BFD_SESSION_ATTR_REMOTE_DIAG,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_REMOTE_DIAG,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_REMOTE_DIAG},
    { SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_bfd_session_attr_get, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER,
      mlnx_bfd_session_attr_set, (void*)SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER},
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        bfd_session_enum_info[] = {
    [SAI_BFD_SESSION_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_BFD_SESSION_TYPE_ASYNC_ACTIVE),
    [SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_BFD_ENCAPSULATION_TYPE_NONE),
    [SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_BFD_SESSION_OFFLOAD_TYPE_NONE,
        SAI_BFD_SESSION_OFFLOAD_TYPE_FULL,
        SAI_BFD_SESSION_OFFLOAD_TYPE_SUSTENANCE),
};
static const sai_stat_capability_t        bfd_session_stats_capabilities[] = {
    { SAI_BFD_SESSION_STAT_IN_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_BFD_SESSION_STAT_OUT_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_BFD_SESSION_STAT_DROP_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
static size_t bfd_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    return snprintf(str, max_len, "[ID:%u]", mlnx_oid.id.bfd_db_idx.idx);
}
const mlnx_obj_type_attrs_info_t mlnx_bfd_session_obj_type_info =
{ bfd_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(bfd_session_enum_info), OBJ_STAT_CAP_INFO(bfd_session_stats_capabilities),
  bfd_info_print};
static sai_status_t mlnx_bfd_session_attr_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_object_id_t              bfd_session_id = key->key.object_id;
    sai_status_t                 status;
    int64_t                      arg_type = (int64_t)arg;
    sai_object_id_t              default_vr_id;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry;
    mlnx_bfd_session_db_data_t   bfd_db_data;
    sai_bfd_session_state_t      bfd_session_state;

    SX_LOG_ENTER();

    assert((arg_type >= SAI_BFD_SESSION_ATTR_TYPE) &&
           (arg_type <= SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER));

    sai_db_read_lock();

    status = mlnx_bfd_session_oid_to_data(bfd_session_id,
                                          &bfd_session_db_entry,
                                          NULL);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_ERR("Cannot get BFD DB data by OID - %" PRId64 ".\n", bfd_session_id);
        SX_LOG_EXIT();
        return status;
    }

    default_vr_id = g_sai_db_ptr->default_vrid;
    bfd_db_data = bfd_session_db_entry->data;

    bfd_session_state = bfd_db_data.bfd_session_state;
    sai_db_unlock();

    switch (arg_type) {
    case SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR:
        value->u32 = bfd_db_data.local_discriminator;
        break;

    case SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR:
        value->u32 = bfd_db_data.remote_discriminator;
        break;

    case SAI_BFD_SESSION_ATTR_UDP_SRC_PORT:
        value->u32 = bfd_db_data.udp_src_port;
        break;

    case SAI_BFD_SESSION_ATTR_TC:
        value->u8 = bfd_db_data.traffic_class;
        break;

    case SAI_BFD_SESSION_ATTR_IPHDR_VERSION:
        value->u8 = bfd_db_data.ip_header_version;
        break;

    case SAI_BFD_SESSION_ATTR_TOS:
        value->u8 = bfd_db_data.tos;
        break;

    case SAI_BFD_SESSION_ATTR_TTL:
        value->u8 = bfd_db_data.ttl;
        break;

    case SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS:
        value->ipaddr = bfd_db_data.src_ip;
        break;

    case SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS:
        value->ipaddr = bfd_db_data.dst_ip;
        break;

    case SAI_BFD_SESSION_ATTR_MULTIHOP:
        value->booldata = bfd_db_data.multihop;
        break;

    case SAI_BFD_SESSION_ATTR_MIN_TX:
        value->u32 = bfd_db_data.min_tx;
        break;

    case SAI_BFD_SESSION_ATTR_MIN_RX:
        value->u32 = bfd_db_data.min_rx;
        break;

    case SAI_BFD_SESSION_ATTR_MULTIPLIER:
        value->u8 = bfd_db_data.multiplier;
        break;

    case SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER:
        value->oid = default_vr_id;
        break;

    case SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE:
        value->s32 = SAI_BFD_SESSION_OFFLOAD_TYPE_FULL;
        break;

    case SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE:
        value->s32 = SAI_BFD_ENCAPSULATION_TYPE_NONE;
        break;

    case SAI_BFD_SESSION_ATTR_TYPE:
        value->s32 = SAI_BFD_SESSION_TYPE_ASYNC_ACTIVE;
        break;

    case SAI_BFD_SESSION_ATTR_HW_LOOKUP_VALID:
        value->booldata = true;
        break;

    case SAI_BFD_SESSION_ATTR_STATE:
        value->s32 = bfd_session_state;
        break;

    case SAI_BFD_SESSION_ATTR_PORT:
    case SAI_BFD_SESSION_ATTR_VLAN_TPID:
    case SAI_BFD_SESSION_ATTR_VLAN_ID:
    case SAI_BFD_SESSION_ATTR_VLAN_PRI:
    case SAI_BFD_SESSION_ATTR_VLAN_CFI:
    case SAI_BFD_SESSION_ATTR_VLAN_HEADER_VALID:
    case SAI_BFD_SESSION_ATTR_CBIT:
    case SAI_BFD_SESSION_ATTR_TUNNEL_TOS:
    case SAI_BFD_SESSION_ATTR_TUNNEL_TTL:
    case SAI_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS:
    case SAI_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS:
    case SAI_BFD_SESSION_ATTR_SRC_MAC_ADDRESS:
    case SAI_BFD_SESSION_ATTR_DST_MAC_ADDRESS:
    case SAI_BFD_SESSION_ATTR_ECHO_ENABLE:
    case SAI_BFD_SESSION_ATTR_NEGOTIATED_TX:
    case SAI_BFD_SESSION_ATTR_NEGOTIATED_RX:
    case SAI_BFD_SESSION_ATTR_LOCAL_DIAG:
    case SAI_BFD_SESSION_ATTR_REMOTE_DIAG:
    case SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER:
    case SAI_BFD_SESSION_ATTR_REMOTE_MIN_TX:
    case SAI_BFD_SESSION_ATTR_REMOTE_MIN_RX:
        SX_LOG_ERR("Unsupported BFD attribute type: %" PRId64 "\n", arg_type);
        SX_LOG_EXIT();
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_index;

    default:
        SX_LOG_ERR("Unexpected BFD attribute type: %" PRId64 "\n", arg_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_bfd_session_attr_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sai_object_id_t              bfd_session_id = key->key.object_id;
    sai_status_t                 status;
    int64_t                      arg_type = (int64_t)arg;
    uint32_t                     vrid_data;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry;
    mlnx_shm_rm_array_idx_t      bfd_session_db_index;
    mlnx_bfd_session_db_data_t   bfd_db_data;

    SX_LOG_ENTER();

    assert((arg_type >= SAI_BFD_SESSION_ATTR_TYPE) &&
           (arg_type <= SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER));

    sai_db_write_lock();

    status = mlnx_bfd_session_oid_to_data(bfd_session_id,
                                          &bfd_session_db_entry,
                                          &bfd_session_db_index);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_ERR("Cannot get BFD DB data by OID - %" PRId64 ".\n", bfd_session_id);
        SX_LOG_EXIT();
        return status;
    }

    bfd_db_data = bfd_session_db_entry->data;

    switch (arg_type) {
    case SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR:
        bfd_db_data.local_discriminator = value->u32;
        break;

    case SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR:
        bfd_db_data.remote_discriminator = value->u32;
        break;

    case SAI_BFD_SESSION_ATTR_UDP_SRC_PORT:
        bfd_db_data.udp_src_port = value->u32;
        break;

    case SAI_BFD_SESSION_ATTR_TC:
        bfd_db_data.traffic_class = value->u8;
        break;

    case SAI_BFD_SESSION_ATTR_IPHDR_VERSION:
        bfd_db_data.ip_header_version = value->u8;
        break;

    case SAI_BFD_SESSION_ATTR_TOS:
        bfd_db_data.tos = value->u8;
        break;

    case SAI_BFD_SESSION_ATTR_TTL:
        bfd_db_data.ttl = value->u8;
        break;

    case SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS:
        bfd_db_data.src_ip = value->ipaddr;
        break;

    case SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS:
        bfd_db_data.dst_ip = value->ipaddr;
        break;

    case SAI_BFD_SESSION_ATTR_MULTIHOP:
        bfd_db_data.multihop = value->booldata;
        break;

    case SAI_BFD_SESSION_ATTR_MIN_TX:
        if (value->u32 < BFD_MIN_SUPPORTED_INTERVAL) {
            SX_LOG_ERR("Minimum supported TX interval is %d.\n", BFD_MIN_SUPPORTED_INTERVAL);
            status = SAI_STATUS_ATTR_NOT_SUPPORTED_0;
            goto out;
        }
        bfd_db_data.is_polling = 1;
        bfd_db_data.min_tx = value->u32;
        break;

    case SAI_BFD_SESSION_ATTR_MIN_RX:
        if (value->u32 < BFD_MIN_SUPPORTED_INTERVAL) {
            SX_LOG_ERR("Minimum supported RX interval is %d.\n", BFD_MIN_SUPPORTED_INTERVAL);
            status = SAI_STATUS_ATTR_NOT_SUPPORTED_0;
            goto out;
        }
        bfd_db_data.is_polling = 1;
        bfd_db_data.min_rx = value->u32;
        break;

    case SAI_BFD_SESSION_ATTR_MULTIPLIER:
        bfd_db_data.multiplier = value->u8;
        break;

    case SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(value->oid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &vrid_data, NULL))) {
            SX_LOG_EXIT();
            goto out;
        }
        bfd_db_data.vr_id = vrid_data;
        break;

    case SAI_BFD_SESSION_ATTR_OFFLOAD_TYPE:
    case SAI_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE:
    case SAI_BFD_SESSION_ATTR_TYPE:
    case SAI_BFD_SESSION_ATTR_HW_LOOKUP_VALID:
    case SAI_BFD_SESSION_ATTR_PORT:
    case SAI_BFD_SESSION_ATTR_VLAN_TPID:
    case SAI_BFD_SESSION_ATTR_VLAN_ID:
    case SAI_BFD_SESSION_ATTR_VLAN_PRI:
    case SAI_BFD_SESSION_ATTR_VLAN_CFI:
    case SAI_BFD_SESSION_ATTR_VLAN_HEADER_VALID:
    case SAI_BFD_SESSION_ATTR_CBIT:
    case SAI_BFD_SESSION_ATTR_TUNNEL_TOS:
    case SAI_BFD_SESSION_ATTR_TUNNEL_TTL:
    case SAI_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS:
    case SAI_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS:
    case SAI_BFD_SESSION_ATTR_SRC_MAC_ADDRESS:
    case SAI_BFD_SESSION_ATTR_DST_MAC_ADDRESS:
    case SAI_BFD_SESSION_ATTR_ECHO_ENABLE:
    case SAI_BFD_SESSION_ATTR_NEGOTIATED_TX:
    case SAI_BFD_SESSION_ATTR_NEGOTIATED_RX:
    case SAI_BFD_SESSION_ATTR_LOCAL_DIAG:
    case SAI_BFD_SESSION_ATTR_REMOTE_DIAG:
    case SAI_BFD_SESSION_ATTR_REMOTE_MULTIPLIER:
    case SAI_BFD_SESSION_ATTR_REMOTE_MIN_TX:
    case SAI_BFD_SESSION_ATTR_REMOTE_MIN_RX:
    case SAI_BFD_SESSION_ATTR_STATE:
        /* fall through */
        SX_LOG_ERR("Unsupported BFD attribute type: %" PRId64 "\n", arg_type);
        status = SAI_STATUS_ATTR_NOT_SUPPORTED_0;
        goto out;

    default:
        SX_LOG_ERR("Unexpected BFD attribute type: %" PRId64 "\n", arg_type);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0;
        goto out;
    }

    /** we can change only tx session**/
    status = mlnx_set_offload_bfd_tx_session(&bfd_db_data, SX_ACCESS_CMD_EDIT);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error edit BFD sessions.\n");
        goto out;
    }

    bfd_session_db_entry->data = bfd_db_data;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Create BFD session.
 *
 * Arguments:
 *    [out] bfd_session_id - BFD session id
 *    [in]  switch_id      - Switch id
 *    [in]  attr_count     - Number of attributes
 *    [in]  attr_list      - Value of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_bfd_session(_Out_ sai_object_id_t      *bfd_session_id,
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *read_attr = NULL;
    sai_status_t                 status;
    uint32_t                     index;
    uint32_t                     vrid_data;
    mlnx_shm_rm_array_idx_t      bfd_session_db_index;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry = NULL;
    mlnx_bfd_session_db_data_t   bfd_db_data = {0};

    SX_LOG_ENTER();

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_BFD_SESSION, bfd_session_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_BFD_SESSION);

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_VIRTUAL_ROUTER, &read_attr, &index);
    assert(read_attr);
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(read_attr->oid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &vrid_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }
    bfd_db_data.vr_id = vrid_data;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.local_discriminator = read_attr->u32;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.remote_discriminator = read_attr->u32;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_UDP_SRC_PORT, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.udp_src_port = read_attr->u32;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_TC, &read_attr, &index);
    bfd_db_data.traffic_class = read_attr ? read_attr->u8 : 0;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_IPHDR_VERSION, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.ip_header_version = read_attr->u8;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_TOS, &read_attr, &index);
    bfd_db_data.tos = read_attr ? read_attr->u8 : 0;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_TTL, &read_attr, &index);
    bfd_db_data.ttl = read_attr ? read_attr->u8 : 255;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_SRC_IP_ADDRESS, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.src_ip = read_attr->ipaddr;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.dst_ip = read_attr->ipaddr;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_MULTIHOP, &read_attr, &index);
    bfd_db_data.multihop = read_attr ? read_attr->booldata : false;

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_MIN_TX, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.remote_min_rx = bfd_db_data.min_tx = read_attr->u32;
    if (bfd_db_data.min_tx < BFD_MIN_SUPPORTED_INTERVAL) {
        SX_LOG_ERR("Minimum supported TX interval is %d.\n", BFD_MIN_SUPPORTED_INTERVAL);
        SX_LOG_EXIT();
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_MIN_RX, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.remote_min_tx = bfd_db_data.min_rx = read_attr->u32;
    if (bfd_db_data.min_rx < BFD_MIN_SUPPORTED_INTERVAL) {
        SX_LOG_ERR("Minimum supported RX interval is %d.\n", BFD_MIN_SUPPORTED_INTERVAL);
        SX_LOG_EXIT();
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    find_attrib_in_list(attr_count, attr_list, SAI_BFD_SESSION_ATTR_MULTIPLIER, &read_attr, &index);
    assert(read_attr);
    bfd_db_data.remote_multiplier = bfd_db_data.multiplier = read_attr->u8;

    sai_db_write_lock();

    status = mlnx_bfd_session_db_entry_alloc(&bfd_session_db_entry, &bfd_session_db_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Cannot allocate BFD session entry in DB.\n");
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_DBG("BFD session entry allocated in DB %p.\n", bfd_session_db_entry);

    status = mlnx_set_offload_bfd_rx_session(&bfd_db_data, bfd_session_db_index, SX_ACCESS_CMD_CREATE);
    if (SAI_ERR(status)) {
        goto out;
    }

    bfd_db_data.bfd_session_state = SAI_BFD_SESSION_STATE_DOWN;
    status = mlnx_set_offload_bfd_tx_session(&bfd_db_data, SX_ACCESS_CMD_CREATE);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_bfd_session_oid_create(bfd_session_db_index, bfd_session_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Cannot create BFD session OID.\n");
        goto out;
    }

    MLNX_LOG_OID_CREATED(*bfd_session_id);

out:

    bfd_session_db_entry->data = bfd_db_data;

    if (SAI_ERR(status)) {
        mlnx_bfd_session_destroy(bfd_session_db_entry);
        mlnx_bfd_session_db_entry_free(bfd_session_db_index);
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove BFD session.
 *
 * Arguments:
 *    [in] bfd_session_id - BFD session id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_bfd_session(_In_ sai_object_id_t bfd_session_id)
{
    sai_status_t                 status;
    mlnx_bfd_session_db_entry_t *bfd_session_db_entry;
    mlnx_shm_rm_array_idx_t      idx;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(bfd_session_id);

    sai_db_write_lock();

    status = mlnx_bfd_session_oid_to_data(bfd_session_id, &bfd_session_db_entry, &idx);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    status = mlnx_bfd_session_destroy(bfd_session_db_entry);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_bfd_session_db_entry_free(idx);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set BFD session attributes.
 *
 * Arguments:
 *    [in] bfd_session_id - BFD session id
 *    [in] attr           - Value of attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_bfd_session_attribute(_In_ sai_object_id_t        bfd_session_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = bfd_session_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_BFD_SESSION, attr);
}

/*
 * Routine Description:
 *    Get BFD session attributes.
 *
 * Arguments:
 *    [in]    bfd_session_id - BFD session id
 *    [in]    attr_count     - Number of attributes
 *    [inout] attr_list      - Value of attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_bfd_session_attribute(_In_ sai_object_id_t     bfd_session_id,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = bfd_session_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_BFD_SESSION, attr_count, attr_list);
}

/*
 * Routine Description:
 *    Get BFD session statistics counters. Deprecated for backward compatibility.
 *
 * Arguments:
 *    [in]  bfd_session_id     - BFD session id
 *    [in]  number_of_counters - Number of counters in the array
 *    [in]  counter_ids        - Specifies the array of counter ids
 *    [out] counters           - Array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_bfd_session_stats(_In_ sai_object_id_t      bfd_session_id,
                                               _In_ uint32_t             number_of_counters,
                                               _In_ const sai_stat_id_t *counter_ids,
                                               _Out_ uint64_t           *counters)
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = mlnx_get_bfd_session_stats_ext(bfd_session_id,
                                            number_of_counters,
                                            counter_ids,
                                            SAI_STATS_MODE_READ,
                                            counters);

    SX_LOG_EXIT();
    return status;
}


/*
 * Routine Description:
 *    Get BFD session statistics counters extended.
 *
 * Arguments:
 *    [in]  bfd_session_id     - BFD session id
 *    [in]  number_of_counters - Number of counters in the array
 *    [in]  counter_ids        - Specifies the array of counter ids
 *    [in]  mode               - Statistics mode
 *    [out] counters           - Array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_bfd_session_stats_ext(_In_ sai_object_id_t      bfd_session_id,
                                                   _In_ uint32_t             number_of_counters,
                                                   _In_ const sai_stat_id_t *counter_ids,
                                                   _In_ sai_stats_mode_t     mode,
                                                   _Out_ uint64_t           *counters)
{
    sai_status_t status;
    uint32_t     ii;
    bool         clear;

    SX_LOG_ENTER();

    if (number_of_counters == 0) {
        SX_LOG_ERR("Number_of_counters is 0\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (counter_ids == NULL) {
        SX_LOG_ERR("Counter_ids is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (mode > SAI_STATS_MODE_READ_AND_CLEAR) {
        SX_LOG_ERR("Mode %d is invalid\n", mode);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if ((mode == SAI_STATS_MODE_READ) && (counters == NULL)) {
        SX_LOG_ERR("Counters is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        if (!MLNX_BFD_STAT_ID_RANGE_CHECK(counter_ids[ii])) {
            SX_LOG_ERR("Invalid BFD stat id %d\n", counter_ids[ii]);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }
    }

    clear = (mode == SAI_STATS_MODE_READ_AND_CLEAR);

    status = mlnx_bfd_session_stats_get(bfd_session_id,
                                        number_of_counters,
                                        counter_ids,
                                        counters != NULL,
                                        clear,
                                        counters);

    SX_LOG_EXIT();
    return status;
}


/*
 * Routine Description:
 *    Clear BFD session statistics counters
 *
 * Arguments:
 *    [in] bfd_session_id     - BFD session id
 *    [in] number_of_counters - Number of counters in the array
 *    [in] counter_ids        - Specifies the array of counter ids
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_clear_bfd_session_stats(_In_ sai_object_id_t      bfd_session_id,
                                                 _In_ uint32_t             number_of_counters,
                                                 _In_ const sai_stat_id_t *counter_ids)
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = mlnx_get_bfd_session_stats_ext(bfd_session_id,
                                            number_of_counters,
                                            counter_ids,
                                            SAI_STATS_MODE_READ_AND_CLEAR,
                                            NULL);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_bfd_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_bfd_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_debug_set_bfd_namespace_for_ptf(_In_ const char* value)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    size_t       str_len;

    assert(NULL != value);

    str_len = strlen(value);
    if (str_len < MAX_NETNS_STR_LEN) {
        strncpy(bfd_netns, value, MAX_NETNS_STR_LEN - 1);
        bfd_netns[MAX_NETNS_STR_LEN - 1] = '\0';
        SX_LOG_NTC("namespace %s set for bfd creation.\n", bfd_netns);
    } else {
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        SX_LOG_WRN("namespace %s is too long (max length: %d)\n", bfd_netns, MAX_NETNS_STR_LEN - 1);
    }

    return sai_status;
}

const sai_bfd_api_t mlnx_bfd_api = {
    mlnx_create_bfd_session,
    mlnx_remove_bfd_session,
    mlnx_set_bfd_session_attribute,
    mlnx_get_bfd_session_attribute,
    mlnx_get_bfd_session_stats,
    mlnx_get_bfd_session_stats_ext,
    mlnx_clear_bfd_session_stats
};
