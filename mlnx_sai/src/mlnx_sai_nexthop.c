/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <fx_base_api.h>
#include <flextrum_types.h>
#include <sdk/sx_api_bmtor.h>

#undef  __MODULE__
#define __MODULE__ SAI_NEXT_HOP


static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_next_hop_attr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_next_hop_attr_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static sai_status_t mlnx_meta_tunnel_entry_remove(_In_ sx_mac_addr_t *sx_fake_mac, _In_ uint32_t priority);
static sai_status_t mlnx_meta_tunnel_entry_create(_In_ sx_mac_addr_t    *sx_fake_mac,
                                                  _In_ sai_object_id_t   tunnel_id,
                                                  _In_ sai_ip_address_t *dip,
                                                  _In_ const sai_mac_t   dmac,
                                                  _Out_ uint32_t        *priority);
static sai_status_t mlnx_next_hop_counter_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
static const sai_vendor_attribute_entry_t next_hop_vendor_attribs[] = {
    { SAI_NEXT_HOP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TYPE,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_IP,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_TUNNEL_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_ID,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_TUNNEL_MAC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_MAC,
      mlnx_next_hop_attr_set, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_MAC },
    { SAI_NEXT_HOP_ATTR_TUNNEL_VNI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_VNI,
      mlnx_next_hop_attr_set, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_VNI },
    { SAI_NEXT_HOP_ATTR_COUNTER_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_COUNTER_ID,
      mlnx_next_hop_counter_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        next_hop_enum_info[] = {
    [SAI_NEXT_HOP_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_NEXT_HOP_TYPE_IP,
        SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP
        ),
};
const mlnx_obj_type_attrs_info_t          mlnx_next_hop_obj_type_info =
{ next_hop_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(next_hop_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};
static void next_hop_key_to_str(_In_ sai_object_id_t next_hop_id, _Out_ char *key_str)
{
    uint32_t nexthop_data;
    uint16_t ext;

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &nexthop_data, (uint8_t*)&ext)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop id %u, ext %u", nexthop_data, ext);
    }
}

static sai_status_t mlnx_encap_nexthop_db_entry_alloc(_Out_ mlnx_encap_nexthop_db_entry_t **encap_nexthop_db_entry,
                                                      _Out_ mlnx_shm_rm_array_idx_t        *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(encap_nexthop_db_entry);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *encap_nexthop_db_entry = ptr;

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_encap_nexthop_db_entry_idx_to_data(_In_ mlnx_shm_rm_array_idx_t          idx,
                                                     _Out_ mlnx_encap_nexthop_db_entry_t **encap_nexthop_db_entry)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    if (SAI_ERR(status)) {
        return status;
    }

    *encap_nexthop_db_entry = (mlnx_encap_nexthop_db_entry_t*)data;

    if (!(*encap_nexthop_db_entry)->array_hdr.is_used) {
        SX_LOG_ERR("Encap Nexthop DB entry at index %u is removed or not created yet.\n", idx.idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_encap_nexthop_oid_to_data(_In_ sai_object_id_t                  oid,
                                            _Out_ mlnx_encap_nexthop_db_entry_t **encap_nexthop_db_entry,
                                            _Out_ mlnx_shm_rm_array_idx_t        *idx)
{
    sai_status_t     status;
    mlnx_object_id_t mlnx_oid;

    assert(encap_nexthop_db_entry);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_NEXT_HOP, oid, &mlnx_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    if (mlnx_oid.ext.nexthop_db.is_db_entry == 0) {
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_encap_nexthop_db_entry_idx_to_data(mlnx_oid.id.encap_nexthop_db_idx, encap_nexthop_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx) {
        *idx = mlnx_oid.id.encap_nexthop_db_idx;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_db_entry_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *encap_nexthop_db_entry;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_encap_nexthop_db_entry_idx_to_data(idx, &encap_nexthop_db_entry);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&encap_nexthop_db_entry->data, 0, sizeof(encap_nexthop_db_entry->data));

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_encap_nexthop_oid_create(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ sai_object_id_t        *oid)
{
    sai_status_t      status;
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)oid;

    assert(oid);

    status = mlnx_shm_rm_idx_validate(idx);
    if (SAI_ERR(status)) {
        return status;
    }

    if (idx.type != MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP) {
        return SAI_STATUS_FAILURE;
    }

    memset(oid, 0, sizeof(*oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_NEXT_HOP;
    mlnx_oid->id.encap_nexthop_db_idx = idx;
    mlnx_oid->ext.nexthop_db.is_db_entry = 1;

    return SAI_STATUS_SUCCESS;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_translate_sdk_next_hop_entry_to_sai(_In_ const sx_next_hop_t  *next_hop,
                                                             _Out_ sai_next_hop_type_t *type,
                                                             _Out_ sai_ip_address_t    *next_hop_ip,
                                                             _Out_ sai_object_id_t     *rif_id,
                                                             _Out_ sai_object_id_t     *tunnel_id,
                                                             _Out_ sai_object_id_t     *counter_id)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if ((SX_NEXT_HOP_TYPE_IP != next_hop->next_hop_key.type) &&
        (SX_NEXT_HOP_TYPE_TUNNEL_ENCAP != next_hop->next_hop_key.type)) {
        SX_LOG_ERR("Invalid next hop type %d\n", next_hop->next_hop_key.type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (next_hop->next_hop_key.type) {
    case SX_NEXT_HOP_TYPE_IP:
        *type = SAI_NEXT_HOP_TYPE_IP;

        status = mlnx_translate_sdk_ip_address_to_sai(
            &next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.address,
            next_hop_ip);
        if (SAI_STATUS_SUCCESS != status) {
            break;
        }

        status = mlnx_rif_sx_to_sai_oid(
            next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif,
            rif_id);
        if (SAI_STATUS_SUCCESS != status) {
            break;
        }

        status = mlnx_translate_flow_counter_to_sai_counter(
            next_hop->next_hop_data.counter_id,
            counter_id);

        break;

    case SX_NEXT_HOP_TYPE_TUNNEL_ENCAP:
        *type = SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP;

        status = mlnx_translate_sdk_tunnel_id_to_sai_tunnel_id(
            next_hop->next_hop_key.next_hop_key_entry.ip_tunnel.tunnel_id,
            tunnel_id);
        if (SAI_STATUS_SUCCESS != status) {
            break;
        }

        status = mlnx_translate_sdk_ip_address_to_sai(
            &next_hop->next_hop_key.next_hop_key_entry.ip_tunnel.underlay_dip,
            next_hop_ip);

        break;

    default:
        SX_LOG_ERR("Invalid next hop type %d\n", next_hop->next_hop_key.type);
        status = SAI_STATUS_INVALID_PARAMETER;
    }

    return status;
}

_Success_(return == SAI_STATUS_SUCCESS)
static sai_status_t mlnx_translate_sai_next_hop_to_sdk(_In_ sai_next_hop_type_t     type,
                                                       _In_ const sai_ip_address_t *next_hop_ip,
                                                       _In_ const sai_object_id_t  *rif_id,
                                                       _In_ const sai_object_id_t  *tunnel_id,
                                                       _In_ const sai_object_id_t  *counter_id,
                                                       _Out_ sx_next_hop_t         *next_hop)
{
    sai_status_t         sai_status;
    uint32_t             tunnel_idx;
    sx_flow_counter_id_t sx_counter_id = SX_FLOW_COUNTER_ID_INVALID;

    SX_LOG_ENTER();

    switch (type) {
    case SAI_NEXT_HOP_TYPE_IP:
        next_hop->next_hop_key.type = SX_NEXT_HOP_TYPE_IP;
        assert(NULL != next_hop_ip);
        assert(NULL != rif_id);
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_translate_sai_ip_address_to_sdk(next_hop_ip,
                                                                            &next_hop->next_hop_key.next_hop_key_entry.
                                                                            ip_next_hop.address))) {
            SX_LOG_EXIT();
            return sai_status;
        }

        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 mlnx_rif_oid_to_sdk_rif_id(*rif_id, &next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif))) {
            SX_LOG_EXIT();
            return sai_status;
        }

        break;

    case SAI_NEXT_HOP_TYPE_MPLS:
        SX_LOG_ERR("MPLS is not supported yet\n");
        sai_status = SAI_STATUS_NOT_SUPPORTED;
        SX_LOG_EXIT();
        return sai_status;
        break;

    case SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP:
        assert(NULL != next_hop_ip);
        assert(NULL != tunnel_id);
        next_hop->next_hop_key.type = SX_NEXT_HOP_TYPE_TUNNEL_ENCAP;
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_object_to_type(*tunnel_id, SAI_OBJECT_TYPE_TUNNEL,
                                              &tunnel_idx, NULL))) {
            SX_LOG_ERR("Cannot find tunnel from sai tunnel id %" PRIx64 "\n", *tunnel_id);
            SX_LOG_EXIT();
            return sai_status;
        }

        if (tunnel_idx >= MAX_TUNNEL_DB_SIZE) {
            SX_LOG_ERR("tunnel db index: %d out of bounds:%d\n", tunnel_idx, MAX_TUNNEL_DB_SIZE);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }

        sai_db_read_lock();

        if (!g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].is_used) {
            sai_db_unlock();
            SX_LOG_ERR("tunnel idx %d is not in use\n", tunnel_idx);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }

        next_hop->next_hop_key.next_hop_key_entry.ip_tunnel.tunnel_id =
            g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_idx].sx_tunnel_id_ipv4;

        sai_db_unlock();

        if (SAI_STATUS_SUCCESS != (sai_status =
                                       mlnx_translate_sai_ip_address_to_sdk(next_hop_ip,
                                                                            &next_hop->next_hop_key.next_hop_key_entry.
                                                                            ip_tunnel.underlay_dip))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        break;

    default:
        SX_LOG_ERR("Invalid next hop type %d\n", type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
        break;
    }

    if (NULL != counter_id) {
        sai_status = mlnx_get_flow_counter_id(*counter_id, &sx_counter_id);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Invalid counter attr\n");
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    next_hop->next_hop_data.counter_id = sx_counter_id;
    next_hop->next_hop_data.action = SX_ROUTER_ACTION_FORWARD;
    next_hop->next_hop_data.trap_attr.prio = SX_TRAP_PRIORITY_MED;
    next_hop->next_hop_data.weight = 1;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_encap_nexthop_get_ecmp(sai_object_id_t nh, sai_object_id_t vrf, sx_ecmp_id_t    *sx_ecmp)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        idx;

    assert(sx_ecmp);

    SX_LOG_ENTER();

    *sx_ecmp = 0;

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        return status;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (db_entry->data.fake_data[ii].associated_vrf == vrf) {
            *sx_ecmp = db_entry->data.fake_data[ii].sx_fake_nexthop;
            break;
        }
    }

    if (!*sx_ecmp) {
        SX_LOG_ERR("ECMP entry was not found\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_ip_generate(_In_ mlnx_shm_rm_array_idx_t nh_idx,
                                                        _In_ uint32_t                fd_idx,
                                                        _Out_ sx_ip_v4_addr_t       *fake_ip_v4)
{
    assert(fake_ip_v4);

    fake_ip_v4->s_addr = (nh_idx.idx & 0x0000FFFF) << 8 | (fd_idx & 0x000000FF);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_mac_generate(_In_ mlnx_shm_rm_array_idx_t nh_idx,
                                                         _Out_ sx_mac_addr_t         *fake_mac)
{
    assert(fake_mac);

    fake_mac->ether_addr_octet[0] = 0x0A;
    fake_mac->ether_addr_octet[1] = (nh_idx.idx & 0x000000FF);
    fake_mac->ether_addr_octet[2] = (nh_idx.idx & 0x0000FF00) >> 8;
    fake_mac->ether_addr_octet[3] = 0;
    fake_mac->ether_addr_octet[4] = 0;
    fake_mac->ether_addr_octet[5] = 0;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_nexthop_create(_In_ sx_router_interface_t br_rif,
                                                           _In_ bool                  reset,
                                                           _In_ sx_flow_counter_id_t  flow_counter,
                                                           _In_ sx_ip_addr_t         *fake_ip_addr,
                                                           _Out_ sx_ecmp_id_t        *nh_id)
{
    sx_next_hop_t   sx_next_hop = { 0 };
    sx_status_t     sx_status;
    uint32_t        sx_next_hop_count = 1;
    sx_access_cmd_t cmd = reset ? SX_ACCESS_CMD_SET : SX_ACCESS_CMD_CREATE;

    assert(fake_ip_addr);
    assert(nh_id);

    sx_next_hop.next_hop_key.type = SX_NEXT_HOP_TYPE_IP;
    sx_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.address = *fake_ip_addr;
    sx_next_hop.next_hop_key.next_hop_key_entry.ip_next_hop.rif = br_rif;
    sx_next_hop.next_hop_data.weight = 1;
    sx_next_hop.next_hop_data.action = SX_ROUTER_ACTION_FORWARD;
    sx_next_hop.next_hop_data.counter_id = flow_counter;

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       cmd,
                                       nh_id,
                                       &sx_next_hop,
                                       &sx_next_hop_count);
    if (SX_ERR(sx_status)) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_neighbor_create(_In_ sx_router_interface_t br_rif,
                                                            _In_ sx_ip_addr_t         *fake_ip_addr,
                                                            _In_ sx_mac_addr_t        *fake_mac)
{
    sx_status_t     sx_status;
    sx_neigh_data_t sx_neigh_data = {0};

    assert(fake_ip_addr);
    assert(fake_mac);

    sx_neigh_data.action = SX_ROUTER_ACTION_FORWARD;
    sx_neigh_data.trap_attr.prio = SX_TRAP_PRIORITY_MED;
    sx_neigh_data.is_software_only = true;
    memcpy(&sx_neigh_data.mac_addr, fake_mac, sizeof(sx_neigh_data.mac_addr));

    sx_status = sx_api_router_neigh_set(gh_sdk,
                                        SX_ACCESS_CMD_ADD,
                                        br_rif,
                                        fake_ip_addr,
                                        &sx_neigh_data);
    if (SX_ERR(sx_status)) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_init(_In_ mlnx_shm_rm_array_idx_t           nh_idx,
                                            _Inout_ mlnx_encap_nexthop_db_entry_t *db_entry)
{
    sai_status_t status;
    sai_mac_t    dmac;

    db_entry->data.acl_index = 0;

    status = mlnx_encap_nexthop_fake_mac_generate(nh_idx, &db_entry->data.sx_fake_mac);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to generate unique fake MAC.\n");
        return status;
    }

    if (!mlnx_is_mac_empty(db_entry->data.tunnel_mac)) {
        memcpy(dmac, db_entry->data.tunnel_mac, sizeof(dmac));
    } else {
        memcpy(dmac, g_sai_db_ptr->vxlan_mac, sizeof(dmac));
    }

    status = mlnx_meta_tunnel_entry_create(&db_entry->data.sx_fake_mac,
                                           db_entry->data.tunnel_id,
                                           &db_entry->data.dst_ip,
                                           dmac,
                                           &db_entry->data.acl_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create meta tunnel entry.\n");
        return status;
    }

    return status;
}

static sai_status_t mlnx_encap_nexthop_fake_data_init_ecmp(_In_ mlnx_encap_nexthop_db_entry_t *db_entry,
                                                           _In_ uint32_t                       vni,
                                                           _In_ sx_flow_counter_id_t           flow_counter,
                                                           _Inout_ mlnx_fake_nh_db_data_t     *fake_data)
{
    sai_status_t          status;
    sx_router_interface_t br_rif;
    sx_fid_t              br_fid;
    sx_ip_addr_t          fake_ip;

    status = mlnx_tunnel_get_bridge_and_rif(db_entry->data.tunnel_id,
                                            vni,
                                            fake_data->associated_vrf,
                                            &br_rif,
                                            &br_fid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get Bridge and RIF. [Tunnel=0x%lX, VNI=%u, VRF=0x%lX]\n",
                   db_entry->data.tunnel_id, vni, fake_data->associated_vrf);
        return status;
    }

    fake_ip.version = SX_IP_VERSION_IPV4;
    fake_ip.addr.ipv4 = fake_data->sx_fake_ip_v4_addr;
    status = mlnx_encap_nexthop_fake_nexthop_create(br_rif,
                                                    false,
                                                    flow_counter,
                                                    &fake_ip,
                                                    &fake_data->sx_fake_nexthop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create fake ecmp.\n");
        return status;
    }

    return status;
}

static sai_status_t mlnx_encap_nexthop_fake_fdb_create(_In_ sx_fid_t br_fid, _In_ sx_mac_addr_t *fake_mac)
{
    sx_status_t                 sx_status;
    sx_fdb_uc_mac_addr_params_t sx_mac_entry = {0};
    uint32_t                    macs_count = 1;

    assert(fake_mac);

    sx_mac_entry.fid_vid = br_fid;
    memcpy(&sx_mac_entry.mac_addr, fake_mac, sizeof(sx_mac_entry.mac_addr));
    sx_mac_entry.entry_type = SX_FDB_UC_STATIC;
    sx_mac_entry.action = SX_FDB_ACTION_FORWARD_TO_ROUTER;

    sx_status = sx_api_fdb_uc_mac_addr_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                           &sx_mac_entry, &macs_count);
    if (SX_ERR(sx_status)) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_data_init(_In_ mlnx_encap_nexthop_db_entry_t *db_entry,
                                                      _In_ uint32_t                       vni,
                                                      _In_ mlnx_shm_rm_array_idx_t        nh_idx,
                                                      _In_ uint32_t                       fd_idx,
                                                      _In_ sx_flow_counter_id_t           flow_counter,
                                                      _In_ bool                           reset,
                                                      _In_ bool                           init_ecmp,
                                                      _Inout_ mlnx_fake_nh_db_data_t     *fake_data)
{
    sai_status_t          status;
    sx_router_interface_t br_rif;
    sx_fid_t              br_fid;
    sx_ip_addr_t          fake_ip;

    if (!reset) {
        status = mlnx_encap_nexthop_fake_ip_generate(nh_idx,
                                                     fd_idx,
                                                     &fake_data->sx_fake_ip_v4_addr);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to generate unique fake IP.\n");
            return status;
        }
    }

    fake_ip.version = SX_IP_VERSION_IPV4;
    fake_ip.addr.ipv4 = fake_data->sx_fake_ip_v4_addr;

    status = mlnx_tunnel_get_bridge_and_rif(db_entry->data.tunnel_id,
                                            vni,
                                            fake_data->associated_vrf,
                                            &br_rif,
                                            &br_fid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get Bridge and RIF. [Tunnel=0x%lX, VNI=%d, VRF=0x%lX]\n",
                   db_entry->data.tunnel_id, vni, fake_data->associated_vrf);
        return status;
    }

    if (init_ecmp) {
        status = mlnx_encap_nexthop_fake_nexthop_create(br_rif,
                                                        reset,
                                                        flow_counter,
                                                        &fake_ip,
                                                        &fake_data->sx_fake_nexthop);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create fake ecmp.\n");
            return status;
        }
    }

    status = mlnx_encap_nexthop_fake_neighbor_create(br_rif,
                                                     &fake_ip,
                                                     &db_entry->data.sx_fake_mac);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create fake neighbor entry.\n");
        return status;
    }

    if (mlnx_chip_is_spc()) {
        status = mlnx_encap_nexthop_fake_fdb_create(br_fid,
                                                    &db_entry->data.sx_fake_mac);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create fake FDB entry.\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_deinit(_In_ mlnx_encap_nexthop_db_entry_t *db_entry)
{
    sai_status_t status;

    status = mlnx_meta_tunnel_entry_remove(&db_entry->data.sx_fake_mac,
                                           db_entry->data.acl_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove meta tunnel entry.\n");
        return status;
    }

    db_entry->data.acl_index = 0;

    return status;
}

static sai_status_t mlnx_encap_nexthop_fake_data_deinit_ecmp(_Inout_ mlnx_fake_nh_db_data_t *fake_data)
{
    sx_status_t sx_status;
    uint32_t    sx_next_hop_count = 1;

    sx_status = sx_api_router_ecmp_set(gh_sdk,
                                       SX_ACCESS_CMD_DESTROY,
                                       &fake_data->sx_fake_nexthop,
                                       NULL,
                                       &sx_next_hop_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy Next Hop - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_fake_data_deinit(_In_ sai_object_id_t            tunnel_id,
                                                        _In_ uint32_t                   vni,
                                                        _In_ sx_mac_addr_t             *fake_mac,
                                                        _In_ bool                       total_deinit,
                                                        _Inout_ mlnx_fake_nh_db_data_t *fake_data)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    uint32_t              sx_next_hop_count;
    sx_router_interface_t br_rif;
    sx_fid_t              br_fid;
    sx_ip_addr_t          fake_ip;

    assert(fake_data);

    status = mlnx_tunnel_get_bridge_and_rif(tunnel_id,
                                            vni,
                                            fake_data->associated_vrf,
                                            &br_rif,
                                            &br_fid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get Bridge and RIF.\n");
        return status;
    }

    fake_ip.version = SX_IP_VERSION_IPV4;
    fake_ip.addr.ipv4 = fake_data->sx_fake_ip_v4_addr;
    sx_neigh_data_t sx_neigh_data = {0};

    sx_neigh_data.action = SX_ROUTER_ACTION_FORWARD;
    sx_neigh_data.trap_attr.prio = SX_TRAP_PRIORITY_MED;
    sx_neigh_data.is_software_only = true;
    memcpy(&sx_neigh_data.mac_addr, fake_mac, sizeof(sx_neigh_data.mac_addr));

    sx_status = sx_api_router_neigh_set(gh_sdk,
                                        SX_ACCESS_CMD_DELETE,
                                        br_rif,
                                        &fake_ip,
                                        &sx_neigh_data);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete Neighbor - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (mlnx_chip_is_spc()) {
        sx_fdb_uc_mac_addr_params_t sx_mac_entry = {0};
        uint32_t                    macs_count = 1;

        sx_mac_entry.fid_vid = br_fid;
        memcpy(sx_mac_entry.mac_addr.ether_addr_octet, fake_mac->ether_addr_octet,
               sizeof(sx_mac_entry.mac_addr.ether_addr_octet));
        sx_mac_entry.entry_type = SX_FDB_UC_STATIC;
        sx_mac_entry.action = SX_FDB_ACTION_FORWARD_TO_ROUTER;

        sx_status = sx_api_fdb_uc_mac_addr_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                               &sx_mac_entry, &macs_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete Fake FDB entry - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    if (total_deinit) {
        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_DESTROY,
                                           &fake_data->sx_fake_nexthop,
                                           NULL,
                                           &sx_next_hop_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to destroy Next Hop - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        memset(&fake_data->sx_fake_nexthop, 0, sizeof(fake_data->sx_fake_nexthop));
        memset(&fake_data->sx_fake_nexthop, 0, sizeof(fake_data->sx_fake_nexthop));
        memset(&fake_data->sx_fake_ip_v4_addr, 0, sizeof(fake_data->sx_fake_ip_v4_addr));
        fake_data->associated_vrf = SAI_NULL_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_encap_nexthop_get_nh_data(mlnx_shm_rm_array_idx_t nh_idx,
                                            sai_object_id_t         vrf,
                                            sx_next_hop_t          *sx_next_hop)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    sx_router_interface_t          br_rif;
    sx_fid_t                       br_fid;
    int32_t                        ii = 0;

    memset(sx_next_hop, 0, sizeof(*sx_next_hop));

    status = mlnx_encap_nexthop_db_entry_idx_to_data(nh_idx, &db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        return status;
    }

    for (; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (db_entry->data.fake_data[ii].associated_vrf == vrf) {
            status = mlnx_tunnel_get_bridge_and_rif(db_entry->data.tunnel_id,
                                                    db_entry->data.tunnel_vni,
                                                    db_entry->data.fake_data[ii].associated_vrf,
                                                    &br_rif,
                                                    &br_fid);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get Bridge and RIF. [Tunnel=0x%lX, VNI=%d, VRF=0x%lX]\n",
                           db_entry->data.tunnel_id,
                           db_entry->data.tunnel_vni,
                           db_entry->data.fake_data[ii].associated_vrf);
                return status;
            }

            sx_next_hop->next_hop_key.type = SX_NEXT_HOP_TYPE_IP;
            sx_next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.address.version = SX_IP_VERSION_IPV4;
            sx_next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.address.addr.ipv4 =
                db_entry->data.fake_data[ii].sx_fake_ip_v4_addr;
            sx_next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif = br_rif;
            sx_next_hop->next_hop_data.weight = 1;
            sx_next_hop->next_hop_data.action = SX_ROUTER_ACTION_FORWARD;
            sx_next_hop->next_hop_data.counter_id = db_entry->data.flow_counter;
            break;
        }
    }

    if (ii == NUMBER_OF_LOCAL_VNETS) {
        SX_LOG_ERR("Fake data was not found.\n");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_encap_nh_data_get(mlnx_shm_rm_array_idx_t nh_idx,
                                    sai_object_id_t         vrf,
                                    int32_t                 diff,
                                    sx_next_hop_t          *sx_next_hop)
{
    sai_status_t status;

    assert(sx_next_hop);

    if (diff > 0) {
        status = mlnx_encap_nexthop_counter_update(nh_idx,
                                                   vrf,
                                                   diff,
                                                   NH_COUNTER_TYPE_NHGM);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to increment NHGM counter. [diff=%d]\n", diff);
            return status;
        }
    }

    status = mlnx_encap_nexthop_get_nh_data(nh_idx, vrf, sx_next_hop);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get NH data [NH_idx=%u, VRF=0x%lX]\n",
                   nh_idx.idx,
                   vrf);
        return status;
    }

    if (diff < 0) {
        status = mlnx_encap_nexthop_counter_update(nh_idx,
                                                   vrf,
                                                   diff,
                                                   NH_COUNTER_TYPE_NHGM);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to decrement NHGM counter. [diff=%d]\n", diff);
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_encap_nexthop_counter_update(_In_ mlnx_shm_rm_array_idx_t nh_idx,
                                               _In_ sai_object_id_t         vrf,
                                               _In_ int32_t                 diff,
                                               _In_ mlnx_nh_counter_type_t  counter_type)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    uint32_t                       fd_idx = 0;
    mlnx_fake_nh_db_data_t        *fake_data = NULL;
    bool                           nh_init = false;
    bool                           nhgm_init = false;
    bool                           nh_deinit = false;
    bool                           nhgm_deinit = false;

    assert((counter_type == NH_COUNTER_TYPE_NH) ||
           (counter_type == NH_COUNTER_TYPE_NHGM));

    SX_LOG_ENTER();

    if (diff == 0) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    status = mlnx_encap_nexthop_db_entry_idx_to_data(nh_idx, &db_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto out;
    }

    if (diff > 0) {
        status = mlnx_tunnel_bridge_counter_update(db_entry->data.tunnel_id,
                                                   db_entry->data.tunnel_vni,
                                                   vrf,
                                                   diff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Update tunnel bridge counter failed. [diff=%d]\n", diff);
            goto out;
        }
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (db_entry->data.fake_data[ii].associated_vrf == vrf) {
            fake_data = &db_entry->data.fake_data[ii];
            break;
        }
    }

    if (!fake_data) {
        for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
            if (db_entry->data.fake_data[ii].associated_vrf == SAI_NULL_OBJECT_ID) {
                fake_data = &db_entry->data.fake_data[ii];
                fake_data->associated_vrf = vrf;
                fake_data->counter = 0;
                fake_data->nhgm_counter = 0;
                fd_idx = ii;
                break;
            }
        }

        if (!fake_data) {
            SX_LOG_ERR("Fake data array is full.\n");
            status = SAI_STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    }

    if ((db_entry->data.acl_counter + diff) < 0) {
        SX_LOG_ERR("ACL counter is out of bounds: %ld\n", db_entry->data.acl_counter + diff);
        status = SAI_STATUS_FAILURE;
        goto out;
    } else if (db_entry->data.acl_counter == 0) {
        status = mlnx_encap_nexthop_init(nh_idx,
                                         db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed NH init.\n");
            goto out;
        }
    }

    if (counter_type == NH_COUNTER_TYPE_NH) {
        if ((fake_data->counter + diff) < 0) {
            SX_LOG_ERR("Counter value is out of bounds.\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        nh_init = fake_data->counter == 0;
        nh_deinit = (fake_data->counter + diff) == 0;
    } else if (counter_type == NH_COUNTER_TYPE_NHGM) {
        if ((fake_data->nhgm_counter + diff) < 0) {
            SX_LOG_ERR("NHGM counter value is out of bounds.\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        nhgm_init = fake_data->nhgm_counter == 0;
        nhgm_deinit = (fake_data->nhgm_counter + diff) == 0;
    }

    /* When updating counters we have to cover these cases:
     * +-------+-----------+----------------+-------------+---------------+
     * |nh\nhgm|     0     |        X       |    Init     |    Deinit     |
     * +-------+-----------+----------------+-------------+---------------+
     * |0      |     -     |        -       |Init w/o ECMP|Deinit w/o ECMP|
     * +-------+-----------+----------------+-------------+---------------+
     * |X      |     -     |        -       |      -      |       -       |
     * +-------+-----------+----------------+-------------+---------------+
     * |Init   |Full init  |Init ECMP only  |      -      |       -       |
     * +-------+-----------+----------------+-------------+---------------+
     * |Deinit |Full deinit|Deinit ECMP only|      -      |       -       |
     * +-------+-----------+----------------+-------------+---------------+
     */
    if (nhgm_init && (fake_data->counter == 0)) {
        status = mlnx_encap_nexthop_fake_data_init(db_entry,
                                                   db_entry->data.tunnel_vni,
                                                   nh_idx,
                                                   fd_idx,
                                                   db_entry->data.flow_counter,
                                                   false,
                                                   false,
                                                   fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data init w/o ECMP.\n");
            return status;
        }
    } else if (nh_init && (fake_data->nhgm_counter > 0)) {
        status = mlnx_encap_nexthop_fake_data_init_ecmp(db_entry,
                                                        db_entry->data.tunnel_vni,
                                                        db_entry->data.flow_counter,
                                                        fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data init ECMP.\n");
            return status;
        }
    } else if (nh_init && (fake_data->nhgm_counter == 0)) {
        status = mlnx_encap_nexthop_fake_data_init(db_entry,
                                                   db_entry->data.tunnel_vni,
                                                   nh_idx,
                                                   fd_idx,
                                                   db_entry->data.flow_counter,
                                                   false,
                                                   true,
                                                   fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data init FULL.\n");
            return status;
        }
    } else if (nhgm_deinit && (fake_data->counter == 0)) {
        status = mlnx_encap_nexthop_fake_data_deinit(db_entry->data.tunnel_id,
                                                     db_entry->data.tunnel_vni,
                                                     &db_entry->data.sx_fake_mac,
                                                     false,
                                                     fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data deinit w/o ECMP.\n");
            return status;
        }
        fake_data->associated_vrf = SAI_NULL_OBJECT_ID;
    } else if (nh_deinit && (fake_data->nhgm_counter > 0)) {
        status = mlnx_encap_nexthop_fake_data_deinit_ecmp(fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data deinit ECMP.\n");
            return status;
        }
    } else if (nh_deinit && (fake_data->nhgm_counter == 0)) {
        status = mlnx_encap_nexthop_fake_data_deinit(db_entry->data.tunnel_id,
                                                     db_entry->data.tunnel_vni,
                                                     &db_entry->data.sx_fake_mac,
                                                     true,
                                                     fake_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed Fake Data deinit FULL.\n");
            return status;
        }
        fake_data->associated_vrf = SAI_NULL_OBJECT_ID;
    }

    if ((db_entry->data.acl_counter + diff) == 0) {
        status = mlnx_encap_nexthop_deinit(db_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed NH deinit.\n");
            goto out;
        }
    }

    if (diff < 0) {
        status = mlnx_tunnel_bridge_counter_update(db_entry->data.tunnel_id,
                                                   db_entry->data.tunnel_vni,
                                                   vrf,
                                                   diff);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Update tunnel bridge counter failed. [diff=%d]\n", diff);
            goto out;
        }
    }

    if (counter_type == NH_COUNTER_TYPE_NH) {
        fake_data->counter += diff;
    } else {
        fake_data->nhgm_counter += diff;
    }
    db_entry->data.acl_counter += diff;

out:
    return status;
}


static sai_status_t mlnx_encap_nexthop_fake_data_reinit(_In_ mlnx_encap_nexthop_db_entry_t *db_entry,
                                                        _In_ uint32_t                       old_vni,
                                                        _In_ uint32_t                       new_vni,
                                                        _In_ sx_flow_counter_id_t           flow_counter,
                                                        _Inout_ mlnx_fake_nh_db_data_t     *fake_data)
{
    sai_status_t            status;
    mlnx_shm_rm_array_idx_t dummy_idx;

    assert(fake_data);

    status = mlnx_encap_nexthop_fake_data_deinit(db_entry->data.tunnel_id,
                                                 old_vni,
                                                 &db_entry->data.sx_fake_mac,
                                                 false,
                                                 fake_data);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to deinit fake data.\n");
        return status;
    }

    memset(&dummy_idx, 0, sizeof(dummy_idx));
    status = mlnx_encap_nexthop_fake_data_init(db_entry,
                                               new_vni,
                                               dummy_idx,
                                               0,
                                               flow_counter,
                                               true,
                                               true,
                                               fake_data);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to reinit fake data.\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create next hop
 *
 * Arguments:
 *    [out] next_hop_id - next hop id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP address expected in Network Byte Order.
 */
static sai_status_t mlnx_create_next_hop(_Out_ sai_object_id_t      *next_hop_id,
                                         _In_ sai_object_id_t        switch_id,
                                         _In_ uint32_t               attr_count,
                                         _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 sai_status;
    sx_status_t                  sdk_status;
    const sai_attribute_value_t *type_attr = NULL, *ip_attr = NULL, *rif_attr = NULL, *tunnel_id_attr = NULL;
    const sai_attribute_value_t *counter_id_attr, *attr;
    const sai_ip_address_t      *ip = NULL;
    const sai_object_id_t       *tunnel_id = NULL;
    const sai_object_id_t       *rif_id = NULL;
    const sai_object_id_t       *counter_id = NULL;
    uint32_t                     idx = 0, type_idx = 0, ip_idx = 0, tunnel_id_idx = 0, counter_id_idx = 0;
    uint32_t                     index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t                sdk_next_hop;
    sx_ecmp_id_t                 sdk_ecmp_id;
    uint32_t                     next_hop_cnt;
    bool                         is_tunnel_ipinip = false;
    bool                         is_tunnel_vxlan = false;
    bool                         is_tunnel_underlay_dst_ip_need = false;
    uint32_t                     tunnel_db_idx = 0;
    sx_flow_counter_id_t         flow_counter_id = SX_FLOW_COUNTER_ID_INVALID;

    SX_LOG_ENTER();

    memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));

    if (NULL == next_hop_id) {
        SX_LOG_ERR("NULL next hop id param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP, next_hop_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_NEXT_HOP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create next hop, %s\n", list_str);

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_TYPE, &type_attr, &type_idx);

    assert(SAI_STATUS_SUCCESS == sai_status);

    switch (type_attr->s32) {
    case SAI_NEXT_HOP_TYPE_IP:
    case SAI_NEXT_HOP_TYPE_MPLS:
    case SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP:
        break;

    default:
        SX_LOG_ERR("Invalid next hop type %d\n", type_attr->s32);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_idx;
        break;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, &rif_attr, &idx);

    if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) && (SAI_STATUS_SUCCESS == sai_status)) {
        SX_LOG_ERR("Rif is not valid for tunnel encap next hop\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + idx;
    } else if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != type_attr->s32) && (SAI_STATUS_SUCCESS != sai_status)) {
        SX_LOG_ERR("Missing rif for next hop ip type and mpls type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
    } else if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) {
        rif_id = NULL;
    } else {
        rif_id = &rif_attr->oid;
    }

    /* does MPLS need IP ? */
    if (SAI_STATUS_SUCCESS !=
        (sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_IP, &ip_attr, &ip_idx))) {
        if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) {
            is_tunnel_underlay_dst_ip_need = true;
        } else if (SAI_NEXT_HOP_TYPE_IP == type_attr->s32) {
            SX_LOG_ERR("Missing next hop ip on create when next hop type is ip\n");
            SX_LOG_EXIT();
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
    } else {
        ip = &ip_attr->ipaddr;
        if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) && (mlnx_is_ip_zero(ip))) {
            SX_LOG_DBG("NULL next hop ip for create tunnel next hop\n");
            is_tunnel_underlay_dst_ip_need = true;
        }
        if ((SAI_IP_ADDR_FAMILY_IPV4 != ip_attr->ipaddr.addr_family) &&
            (SAI_IP_ADDR_FAMILY_IPV6 != ip_attr->ipaddr.addr_family)) {
            SX_LOG_ERR("Invalid next hop ip address %d family on create\n", ip_attr->ipaddr.addr_family);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + ip_idx;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_TUNNEL_ID, &tunnel_id_attr,
                                 &tunnel_id_idx))) {
        tunnel_id = NULL;
    } else {
        tunnel_id = &tunnel_id_attr->oid;
    }

    /* check tunnel type (ip in ip or vxlan or something else) */
    if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) && (NULL == tunnel_id)) {
        SX_LOG_ERR("Missing next hop tunnel id on create when next hop type is tunnel encap\n");
        SX_LOG_EXIT();
        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
    } else if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != type_attr->s32) && (NULL != tunnel_id)) {
        SX_LOG_ERR("Tunnel id is not valid for non-next-hop-tunnel_encap type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + tunnel_id_idx;
    }

    if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) {
        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_get_sai_tunnel_db_idx(*tunnel_id, &tunnel_db_idx))) {
            SX_LOG_ERR("Not able to get SAI tunnel db idx from tunnel id: %" PRIx64 "\n", *tunnel_id);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + tunnel_id_idx;
        }

        sai_db_read_lock();

        switch (g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_tunnel_type) {
        case SAI_TUNNEL_TYPE_IPINIP:
        case SAI_TUNNEL_TYPE_IPINIP_GRE:
            is_tunnel_ipinip = true;
            break;

        case SAI_TUNNEL_TYPE_VXLAN:
            is_tunnel_ipinip = false;
            is_tunnel_vxlan = true;
            break;

        default:
            is_tunnel_ipinip = false;
            break;
        }

        sai_db_unlock();
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_COUNTER_ID, &counter_id_attr,
                                     &counter_id_idx);
    if (!SAI_ERR(sai_status)) {
        counter_id = &counter_id_attr->oid;
    }

    if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != type_attr->s32) || is_tunnel_ipinip) {
        if (is_tunnel_underlay_dst_ip_need) {
            char ip_str[MAX_KEY_STR_LEN];
            sai_db_read_lock();
            ip = &g_sai_tunnel_db_ptr->tunnel_entry_db[tunnel_db_idx].sai_underlay_dip;
            sai_ipaddr_to_str(*ip, MAX_KEY_STR_LEN - 1, ip_str, NULL);
            SX_LOG_DBG("Get P2P ip tunnel dst ip - %s from db.\n", ip_str);
            sai_db_unlock();
        }

        sai_status = mlnx_translate_sai_next_hop_to_sdk(type_attr->s32,
                                                        ip,
                                                        rif_id, tunnel_id, counter_id,
                                                        &sdk_next_hop);
        if (SAI_ERR(sai_status)) {
            SX_LOG_EXIT();
            return sai_status;
        }

        next_hop_cnt = 1;

        if (SX_STATUS_SUCCESS !=
            (sdk_status =
                 sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_ecmp_id, &sdk_next_hop, &next_hop_cnt))) {
            SX_LOG_ERR("Failed to create ecmp - %s.\n", SX_STATUS_MSG(sdk_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sdk_status);
        }

        if (SAI_STATUS_SUCCESS !=
            (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP, sdk_ecmp_id, NULL, next_hop_id))) {
            SX_LOG_EXIT();
            return sai_status;
        }
    }

    /* Encap Nexthop to VxLAN */
    if ((SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == type_attr->s32) && is_tunnel_vxlan) {
        mlnx_encap_nexthop_db_entry_t *db_entry;
        mlnx_shm_rm_array_idx_t        idx;
        sai_mac_t                      tunnel_mac;
        uint32_t                       vni = 0;

        memset(tunnel_mac, 0, sizeof(tunnel_mac));
        sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_TUNNEL_MAC, &attr, &index);
        if (SAI_STATUS_SUCCESS == sai_status) {
            memcpy(tunnel_mac, attr->mac, sizeof(attr->mac));
        }

        if (counter_id) {
            sai_status = mlnx_get_flow_counter_id(*counter_id, &flow_counter_id);
            if (SAI_ERR(sai_status)) {
                SX_LOG_ERR("Failed to get flow counter id from counters DB.\n");
                return sai_status;
            }
        }

        sai_status = find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_TUNNEL_VNI, &attr, &index);
        if (SAI_STATUS_SUCCESS == sai_status) {
            vni = attr->u32;
        }

        sai_db_write_lock();

        sai_status = mlnx_encap_nexthop_db_entry_alloc(&db_entry, &idx);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to allocate Encap Nexthop DB entry.\n");
            sai_db_unlock();
            return sai_status;
        }

        memcpy(db_entry->data.tunnel_mac, tunnel_mac, sizeof(tunnel_mac));
        db_entry->data.tunnel_id = *tunnel_id;
        db_entry->data.dst_ip = *ip;
        db_entry->data.tunnel_vni = vni;
        db_entry->data.flow_counter = flow_counter_id;

        sai_status = mlnx_encap_nexthop_oid_create(idx, next_hop_id);
        if (SAI_ERR(sai_status)) {
            mlnx_encap_nexthop_db_entry_free(idx); /* don't care about status */
            SX_LOG_ERR("Failed to create Encap Nexthop OID.\n");
            sai_db_unlock();
            return sai_status;
        }

        sai_db_unlock();
    }

    next_hop_key_to_str(*next_hop_id, key_str);
    SX_LOG_NTC("Created next hop %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove next hop
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_next_hop(_In_ sai_object_id_t next_hop_id)
{
    sx_status_t  sx_status;
    sai_status_t status;
    sx_ecmp_id_t sdk_ecmp_id;
    uint32_t     data;
    uint16_t     use_db;
    char         key_str[MAX_KEY_STR_LEN];
    uint32_t     next_hop_cnt = 0;

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    SX_LOG_NTC("Remove next hop %s\n", key_str);

    status = mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&use_db);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    if (use_db) {
        mlnx_encap_nexthop_db_entry_t *db_entry;
        mlnx_shm_rm_array_idx_t        idx = *(mlnx_shm_rm_array_idx_t*)&data;

        status = mlnx_encap_nexthop_oid_to_data(next_hop_id, &db_entry, &idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get data from DB.\n");
            goto out;
        }

        for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
            if ((db_entry->data.fake_data[ii].counter != 0) ||
                (db_entry->data.fake_data[ii].nhgm_counter != 0)) {
                SX_LOG_ERR("Internal entities weren't uninitialized, memory leak. [ii=%d, NH=%d, NHGM=%d]\n",
                           ii, db_entry->data.fake_data[ii].counter, db_entry->data.fake_data[ii].nhgm_counter);
                status = SAI_STATUS_OBJECT_IN_USE;
                goto out;
            }
        }

        status = mlnx_encap_nexthop_db_entry_free(idx);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        sdk_ecmp_id = (sx_ecmp_id_t)data;
        sx_status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_ecmp_id, NULL, &next_hop_cnt);
        if (SAI_ERR(sx_status)) {
            SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set Next Hop attribute
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_next_hop_attribute(_In_ sai_object_id_t next_hop_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = next_hop_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_NEXT_HOP, next_hop_vendor_attribs, attr);
}


/*
 * Routine Description:
 *    Get Next Hop attribute
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_next_hop_attribute(_In_ sai_object_id_t     next_hop_id,
                                                _In_ uint32_t            attr_count,
                                                _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = next_hop_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_NEXT_HOP, next_hop_vendor_attribs, attr_count, attr_list);
}

/* Next hop entry type [sai_next_hop_type_t] */
/* Next hop entry ipv4 address [sai_ip_address_t] */
/* Next hop entry router interface id [sai_object_id_t] (MANDATORY_ON_CREATE|CREATE_ONLY) */
static sai_status_t mlnx_next_hop_attr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sx_status_t          sx_status;
    sai_status_t         status;
    long                 attr = (long)arg;
    sx_next_hop_t        sdk_next_hop;
    uint32_t             sdk_next_hop_cnt;
    sx_ecmp_id_t         sdk_ecmp_id;
    sai_next_hop_type_t  next_hop_type;
    sai_ip_address_t     next_hop_ip;
    sai_object_id_t      rif;
    sai_object_id_t      tunnel_id;
    sai_mac_t            tunnel_mac;
    uint32_t             vni = 0;
    uint16_t             use_db;
    uint32_t             data;
    sai_object_id_t      counter_id;
    sx_flow_counter_id_t flow_counter;

    SX_LOG_ENTER();

    memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));
    memset(tunnel_mac, 0, sizeof(tunnel_mac));

    assert((SAI_NEXT_HOP_ATTR_TYPE == attr) ||
           (SAI_NEXT_HOP_ATTR_IP == attr) ||
           (SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID == attr) ||
           (SAI_NEXT_HOP_ATTR_TUNNEL_ID == attr) ||
           (SAI_NEXT_HOP_ATTR_TUNNEL_MAC == attr) ||
           (SAI_NEXT_HOP_ATTR_TUNNEL_VNI == attr) ||
           (SAI_NEXT_HOP_ATTR_COUNTER_ID == attr));

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&use_db);
    if (SAI_ERR(status)) {
        return status;
    }

    if (use_db) {
        mlnx_encap_nexthop_db_entry_t *db_entry;
        mlnx_shm_rm_array_idx_t        idx = *(mlnx_shm_rm_array_idx_t*)&data;

        sai_db_write_lock();

        status = mlnx_encap_nexthop_oid_to_data(key->key.object_id, &db_entry, &idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get data from DB.\n");
            sai_db_unlock();
            return status;
        }

        next_hop_type = SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP;
        next_hop_ip = db_entry->data.dst_ip;
        tunnel_id = db_entry->data.tunnel_id;
        memcpy(tunnel_mac, db_entry->data.tunnel_mac, sizeof(tunnel_mac));
        vni = db_entry->data.tunnel_vni;
        rif = SAI_NULL_OBJECT_ID;
        flow_counter = db_entry->data.flow_counter;

        sai_db_unlock();

        status = mlnx_translate_flow_counter_to_sai_counter(flow_counter, &counter_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to translate flow counter to SAI counter\n");
            return status;
        }
    } else {
        sdk_ecmp_id = (sx_ecmp_id_t)data;
        sdk_next_hop_cnt = 1;
        sx_status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        if (1 != sdk_next_hop_cnt) {
            SX_LOG_ERR("Invalid next hops count %u\n", sdk_next_hop_cnt);
            return SAI_STATUS_FAILURE;
        }

        status = mlnx_translate_sdk_next_hop_entry_to_sai(&sdk_next_hop, &next_hop_type, &next_hop_ip, &rif,
                                                          &tunnel_id, &counter_id);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    switch (attr) {
    case SAI_NEXT_HOP_ATTR_TYPE:
        value->s32 = next_hop_type;
        break;

    case SAI_NEXT_HOP_ATTR_IP:
        memcpy(&value->ipaddr, &next_hop_ip, sizeof(value->ipaddr));
        break;

    case SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID:
        if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP == next_hop_type) {
            SX_LOG_ERR("rif is not valid for tunnel encap next hop\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        value->oid = rif;
        break;

    case SAI_NEXT_HOP_ATTR_TUNNEL_ID:
        if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != next_hop_type) {
            SX_LOG_ERR("tunnel id is only valid for tunnel encap next hop\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        value->oid = tunnel_id;
        break;

    case SAI_NEXT_HOP_ATTR_TUNNEL_MAC:
        if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != next_hop_type) {
            SX_LOG_ERR("Tunnel MAC is only valid for tunnel encap next hop\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (mlnx_is_mac_empty(tunnel_mac)) {
            sai_db_read_lock();
            memcpy(value->mac, g_sai_db_ptr->vxlan_mac, sizeof(value->mac));
            sai_db_unlock();
        } else {
            memcpy(value->mac, tunnel_mac, sizeof(value->mac));
        }
        break;

    case SAI_NEXT_HOP_ATTR_TUNNEL_VNI:
        if (SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP != next_hop_type) {
            SX_LOG_ERR("Tunnel VNI is only valid for tunnel encap next hop\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        value->u32 = vni;
        break;

    case SAI_NEXT_HOP_ATTR_COUNTER_ID:
        value->oid = counter_id;
        break;

    default:
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_encap_nexthop_change_flow_counter(_In_ sai_object_id_t      nh,
                                                           _In_ sx_flow_counter_id_t flow_counter)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        idx;

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failure getting data from DB.\n");
        goto out;
    }

    sai_db_write_lock();
    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (db_entry->data.fake_data[ii].associated_vrf != SAI_NULL_OBJECT_ID) {
            status = mlnx_encap_nexthop_fake_data_reinit(db_entry,
                                                         db_entry->data.tunnel_vni,
                                                         db_entry->data.tunnel_vni,
                                                         flow_counter,
                                                         &db_entry->data.fake_data[ii]);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to reset fake data. [TunnelID=%lx,FlowCounter=%u,NewFlowCounter=%u,VRF=%lx]\n",
                           db_entry->data.tunnel_id,
                           db_entry->data.flow_counter,
                           flow_counter,
                           db_entry->data.fake_data[ii].associated_vrf);
                goto out;
            }
        }
    }

    db_entry->data.flow_counter = flow_counter;

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_next_hop_counter_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_status_t          sx_status;
    sai_status_t         status;
    uint32_t             sdk_next_hop_cnt = 1;
    sx_next_hop_t        sdk_next_hop;
    uint32_t             data;
    sx_ecmp_id_t         sdk_ecmp_id;
    sx_flow_counter_id_t counter_id;
    uint16_t             use_db;

    SX_LOG_ENTER();
    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_NEXT_HOP, &data, (uint8_t*)&use_db);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_get_flow_counter_id(value->oid, &counter_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get counter id.\n");
        return status;
    }

    if (use_db) {
        status = mlnx_encap_nexthop_change_flow_counter(key->key.object_id, counter_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update encap nexthop flow counter\n");
            return status;
        }
    } else {
        sdk_ecmp_id = data;
        sx_status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(status);
        }

        sdk_next_hop.next_hop_data.counter_id = counter_id;
        sx_status = sx_api_router_ecmp_set(gh_sdk,
                                           SX_ACCESS_CMD_SET,
                                           &sdk_ecmp_id,
                                           &sdk_next_hop,
                                           &sdk_next_hop_cnt);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to set ecmp - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_meta_tunnel_entry_remove(_In_ sx_mac_addr_t *sx_fake_mac, _In_ uint32_t priority)
{
    sx_status_t                           sx_status;
    sx_table_meta_tunnel_entry_key_data_t key;

    memcpy(&key.in_rif_metadata_field, sx_fake_mac->ether_addr_octet, sizeof(key.in_rif_metadata_field));
    key.priority = priority;

    sx_status = sx_api_table_meta_tunnel_entry_set(gh_sdk, SX_ACCESS_CMD_DELETE, &key, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove meta tunnel entry - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_meta_tunnel_entry_create(_In_ sx_mac_addr_t    *sx_fake_mac,
                                                  _In_ sai_object_id_t   tunnel_id,
                                                  _In_ sai_ip_address_t *dip,
                                                  _In_ const sai_mac_t   dmac,
                                                  _Out_ uint32_t        *priority)
{
    sx_status_t                              sx_status;
    sai_status_t                             status;
    sx_table_meta_tunnel_entry_key_data_t    key;
    sx_table_meta_tunnel_entry_action_data_t action;
    sx_tunnel_id_t                           sx_tunnel_id;
    sx_mac_addr_t                            tunnel_mac;
    sx_ip_addr_t                             sx_dip;

    memcpy(&key.in_rif_metadata_field, sx_fake_mac->ether_addr_octet, sizeof(key.in_rif_metadata_field));

    status = mlnx_sai_tunnel_to_sx_tunnel_id(tunnel_id, &sx_tunnel_id);
    if (SAI_ERR(status)) {
        return status;
    }

    action.action = SX_TABLE_META_TUNNEL_TUNNEL_ENCAP_ACTION;

    if (mlnx_is_mac_empty(dmac)) {
        memcpy(tunnel_mac.ether_addr_octet, g_sai_db_ptr->vxlan_mac, sizeof(tunnel_mac.ether_addr_octet));
    } else {
        memcpy(tunnel_mac.ether_addr_octet, dmac, sizeof(tunnel_mac.ether_addr_octet));
    }

    status = mlnx_translate_sai_ip_address_to_sdk(dip, &sx_dip);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert SAI IP to SX IP.\n");
        return status;
    }

    memcpy(&action.data.tunnel_encap_params.dst_mac.ether_addr_octet, tunnel_mac.ether_addr_octet,
           sizeof(tunnel_mac.ether_addr_octet));
    action.data.tunnel_encap_params.tunnel_id = sx_tunnel_id;
    action.data.tunnel_encap_params.underlay_dip = sx_dip;

    sx_status = sx_api_table_meta_tunnel_entry_set(gh_sdk, SX_ACCESS_CMD_CREATE, &key, &action);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create meta tunnel entry - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *priority = key.priority;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_encap_nexthop_change_dmac(_In_ sai_object_id_t nh, _In_ const sai_mac_t mac, _In_ bool store)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        idx;

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto out;
    }

    status = mlnx_meta_tunnel_entry_remove(&db_entry->data.sx_fake_mac,
                                           db_entry->data.acl_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove meta tunnel entry\n");
        goto out;
    }
    status = mlnx_meta_tunnel_entry_create(&db_entry->data.sx_fake_mac,
                                           db_entry->data.tunnel_id,
                                           &db_entry->data.dst_ip,
                                           mac,
                                           &db_entry->data.acl_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create meta tunnel entry\n");
        goto out;
    }

    if (store) {
        memcpy(db_entry->data.tunnel_mac, mac, sizeof(db_entry->data.tunnel_mac));
    }

out:
    return status;
}

sai_status_t mlnx_encap_nexthop_change_vni(_In_ sai_object_id_t nh, _In_ uint32_t vni)
{
    sai_status_t                   status;
    mlnx_encap_nexthop_db_entry_t *db_entry;
    mlnx_shm_rm_array_idx_t        idx;

    status = mlnx_encap_nexthop_oid_to_data(nh, &db_entry, &idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get data from DB.\n");
        goto out;
    }

    for (int32_t ii = 0; ii < NUMBER_OF_LOCAL_VNETS; ++ii) {
        if (db_entry->data.fake_data[ii].associated_vrf != SAI_NULL_OBJECT_ID) {
            status = mlnx_tunnel_bridge_counter_update(db_entry->data.tunnel_id,
                                                       vni,
                                                       db_entry->data.fake_data[ii].associated_vrf,
                                                       db_entry->data.fake_data[ii].counter);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to increase the Bridge counter. [TunnelID=%lx,VNI=%u,VRF=%lx,Counter=%d]\n",
                           db_entry->data.tunnel_id,
                           vni,
                           db_entry->data.fake_data[ii].associated_vrf,
                           db_entry->data.fake_data[ii].counter);
                goto out;
            }

            status = mlnx_encap_nexthop_fake_data_reinit(db_entry,
                                                         db_entry->data.tunnel_vni,
                                                         vni,
                                                         db_entry->data.flow_counter,
                                                         &db_entry->data.fake_data[ii]);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to reset fake data. [VNI=%u,NewVNI=%u,VRF=%lx]\n",
                           db_entry->data.tunnel_vni,
                           vni,
                           db_entry->data.fake_data[ii].associated_vrf);
                goto out;
            }

            status = mlnx_tunnel_bridge_counter_update(db_entry->data.tunnel_id,
                                                       db_entry->data.tunnel_vni,
                                                       db_entry->data.fake_data[ii].associated_vrf,
                                                       -db_entry->data.fake_data[ii].counter);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to decrease the Bridge counter. [TunnelID=%lx,VNI=%u,VRF=%lx,Counter=%d]\n",
                           db_entry->data.tunnel_id,
                           db_entry->data.tunnel_vni,
                           db_entry->data.fake_data[ii].associated_vrf,
                           -db_entry->data.fake_data[ii].counter);
                goto out;
            }
        }
    }

    db_entry->data.tunnel_vni = vni;

out:
    return status;
}

static sai_status_t mlnx_next_hop_attr_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t status = SAI_STATUS_FAILURE;
    int32_t      attr = (long)arg;

    assert(attr == SAI_NEXT_HOP_ATTR_TUNNEL_MAC ||
           attr == SAI_NEXT_HOP_ATTR_TUNNEL_VNI);

    sai_db_write_lock();

    switch (attr) {
    case SAI_NEXT_HOP_ATTR_TUNNEL_MAC:
        status = mlnx_encap_nexthop_change_dmac(key->key.object_id, value->mac, true);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to change DMAC.\n");
            goto out;
        }
        break;

    case SAI_NEXT_HOP_ATTR_TUNNEL_VNI:
        status = mlnx_encap_nexthop_change_vni(key->key.object_id, value->u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to change VNI.\n");
            goto out;
        }
        break;

    default:
        status = SAI_STATUS_FAILURE;
        break;
    }

out:
    sai_db_unlock();
    return status;
}

sai_status_t mlnx_nexthop_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_next_hop_api_t mlnx_next_hop_api = {
    mlnx_create_next_hop,
    mlnx_remove_next_hop,
    mlnx_set_next_hop_attribute,
    mlnx_get_next_hop_attribute
};
