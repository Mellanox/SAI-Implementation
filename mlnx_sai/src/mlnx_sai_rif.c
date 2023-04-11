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
#include "meta/saimetadata.h"

#undef  __MODULE__
#define __MODULE__ SAI_RIF

/* Length of MAC address in bits */
#define MAC_ADDRESS_LEN_BITS (6 * 8)

/* Initial value used to create MAC prefix bit mask */
#define MAC_PREFIX_INITIAL_MASK UINT64_C(0xffffffffffffffff)

/* Clear N least significant bits */
#define CLEAR_LSB(var, bits) ((var >> bits) << bits)

/* Get MAC address prefix value of N first bits */
#define MAC_PREFIX_GET(mac, size) (CLEAR_LSB(MAC_PREFIX_INITIAL_MASK, (MAC_ADDRESS_LEN_BITS - size)) & mac)

bool g_additional_mac_enabled;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_rif_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_rif_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static const sai_vendor_attribute_entry_t rif_vendor_attribs[] = {
    { SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_TYPE,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_PORT_ID,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE },
    { SAI_ROUTER_INTERFACE_ATTR_MTU,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_MTU,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_MTU },
    { SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION },
    { SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE},
    { SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE},
    { SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE },
    { SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE },
    { SAI_ROUTER_INTERFACE_ATTR_NEIGHBOR_MISS_PACKET_ACTION,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_ROUTER_INTERFACE_ATTR_BRIDGE_ID,
      { true, false, false, false },
      { true, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        rif_enum_info[] = {
    [SAI_ROUTER_INTERFACE_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_ROUTER_INTERFACE_TYPE_PORT,
        SAI_ROUTER_INTERFACE_TYPE_VLAN,
        SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
        SAI_ROUTER_INTERFACE_TYPE_BRIDGE,
        SAI_ROUTER_INTERFACE_TYPE_SUB_PORT),
    [SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION] = ATTR_ENUM_VALUES_LIST(
        SAI_PACKET_ACTION_DROP,
        SAI_PACKET_ACTION_FORWARD,
        SAI_PACKET_ACTION_TRAP),
};
static const sai_stat_capability_t        rif_stats_capabilities[] = {
    { SAI_ROUTER_INTERFACE_STAT_IN_OCTETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_IN_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_IN_ERROR_OCTETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_OCTETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
    { SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS, SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR },
};
static size_t rif_info_print(_In_ const sai_object_key_t *key, _Out_ char *str, _In_ size_t max_len)
{
    mlnx_object_id_t mlnx_oid = *(mlnx_object_id_t*)&key->key.object_id;

    if (mlnx_oid.field.sub_type == MLNX_RIF_TYPE_BRIDGE) {
        return snprintf(str, max_len, "[Type:BRIDGE, ID:%u]", mlnx_oid.id.bridge_rif_idx);
    }

    return snprintf(str, max_len, "[Type:DEFAULT, ID:%u]", mlnx_oid.id.rif_db_idx.idx);
}
const mlnx_obj_type_attrs_info_t mlnx_rif_obj_type_info =
{ rif_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(rif_enum_info), OBJ_STAT_CAP_INFO(rif_stats_capabilities), rif_info_print};

sai_status_t mlnx_rif_availability_get(_In_ sai_object_id_t        switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t *attr_list,
                                       _Out_ uint64_t             *count)
{
    sx_status_t sx_status;
    uint32_t    rifs_max = 0, rifs_exists = 0;

    assert(count);

    if (!g_sai_db_ptr->issu_enabled) {
        rifs_max = g_resource_limits.router_rifs_max;
    } else {
        rifs_max = g_resource_limits.router_rifs_max / 2;
    }

    sx_status = sx_api_router_interface_iter_get(get_sdk_handle(), SX_ACCESS_CMD_GET, NULL, NULL, NULL, &rifs_exists);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get count of router interfaces - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *count = (uint64_t)(rifs_max - g_sai_db_ptr->max_ipinip_ipv6_loopback_rifs - rifs_exists);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_rif_db_alloc(_Out_ mlnx_rif_db_t **rif_data, _Out_ mlnx_shm_rm_array_idx_t  *idx)
{
    sai_status_t status;
    void        *ptr;

    assert(rif_data);
    assert(idx);

    status = mlnx_shm_rm_array_alloc(MLNX_SHM_RM_ARRAY_TYPE_RIF, idx, &ptr);
    if (SAI_ERR(status)) {
        return status;
    }

    *rif_data = ptr;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_rif_db_idx_to_data(_In_ mlnx_shm_rm_array_idx_t idx, _Out_ mlnx_rif_db_t          **rif)
{
    sai_status_t status;
    void        *data;

    status = mlnx_shm_rm_array_idx_to_ptr(idx, &data);
    *rif = (mlnx_rif_db_t*)data;

    return status;
}

static sai_status_t mlnx_rif_db_free(_In_ mlnx_shm_rm_array_idx_t idx)
{
    sai_status_t   status;
    mlnx_rif_db_t *rif_db_data;

    if (MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_rif_db_idx_to_data(idx, &rif_db_data);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&rif_db_data->sx_data, 0, sizeof(rif_db_data->sx_data));
    memset(&rif_db_data->mac_data, 0, sizeof(rif_db_data->mac_data));

    return mlnx_shm_rm_array_free(idx);
}

sai_status_t mlnx_rif_oid_create(_In_ mlnx_rif_type_t          rif_type,
                                 _In_ const mlnx_bridge_rif_t *bridge_rif,
                                 _In_ mlnx_shm_rm_array_idx_t  idx,
                                 _Out_ sai_object_id_t        *rif_oid)
{
    mlnx_object_id_t *mlnx_oid = (mlnx_object_id_t*)rif_oid;

    assert(rif_type <= MLNX_RIF_TYPE_BRIDGE);
    assert(rif_oid);

    memset(rif_oid, 0, sizeof(*rif_oid));

    mlnx_oid->object_type = SAI_OBJECT_TYPE_ROUTER_INTERFACE;
    mlnx_oid->field.sub_type = rif_type;

    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        assert(bridge_rif == NULL);
        mlnx_oid->id.rif_db_idx = idx;
    } else { /* MLNX_RIF_TYPE_BRIDGE */
        assert(bridge_rif);
        mlnx_oid->id.bridge_rif_idx = bridge_rif->index;
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_rif_counter_db_cmp(_In_ const void *elem, _In_ const void *data)
{
    const mlnx_rif_db_t  *rif_db = (const mlnx_rif_db_t*)elem;
    sx_router_interface_t rif = *(const sx_router_interface_t*)data;

    return rif_db->sx_data.rif_id == rif;
}

sai_status_t mlnx_rif_sx_to_sai_oid(_In_ sx_router_interface_t sx_rif_id, _Out_ sai_object_id_t      *oid)
{
    sai_status_t             status;
    void                    *elem;
    const mlnx_bridge_rif_t *bridge_rif;
    mlnx_shm_rm_array_idx_t  idx;
    uint32_t                 ii;

    status = mlnx_shm_rm_array_find(MLNX_SHM_RM_ARRAY_TYPE_RIF, mlnx_rif_counter_db_cmp,
                                    MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED,
                                    (void*)&sx_rif_id, &idx, &elem);
    if (status == SAI_STATUS_SUCCESS) {
        return mlnx_rif_oid_create(MLNX_RIF_TYPE_DEFAULT, NULL, idx, oid);
    }

    for (ii = 0; ii < MAX_BRIDGE_RIFS; ii++) {
        bridge_rif = &g_sai_db_ptr->bridge_rifs_db[ii];
        if ((bridge_rif->is_used) && (bridge_rif->sx_data.rif_id == sx_rif_id)) {
            return mlnx_rif_oid_create(MLNX_RIF_TYPE_BRIDGE, bridge_rif, MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED, oid);
        }
    }

    SX_LOG_ERR("Failed to find rif %d in SAI DB\n", sx_rif_id);

    return SAI_STATUS_FAILURE;
}

sai_status_t mlnx_rif_oid_to_mac_data(_In_ sai_object_id_t rif_oid, _Out_ mlnx_rif_mac_data_t       **rif_mac_data)
{
    sai_status_t       status;
    mlnx_object_id_t   mlnx_rif_obj = {0};
    mlnx_bridge_rif_t *br_rif = NULL;
    mlnx_rif_db_t     *rif_db = NULL;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_oid, &mlnx_rif_obj);
    if (SAI_ERR(status)) {
        return status;
    }

    if (mlnx_rif_obj.field.sub_type > MLNX_RIF_TYPE_BRIDGE) {
        SX_LOG_ERR("Invalid rif sub type - %d\n", mlnx_rif_obj.field.sub_type);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (mlnx_rif_obj.field.sub_type == MLNX_RIF_TYPE_DEFAULT) {
        status = mlnx_rif_db_idx_to_data(mlnx_rif_obj.id.rif_db_idx, &rif_db);
        if (SAI_ERR(status)) {
            return status;
        }

        if (rif_mac_data) {
            *rif_mac_data = &rif_db->mac_data;
        }
    } else { /* SAI_ROUTER_INTERFACE_TYPE_BRIDGE */
        status = mlnx_bridge_rif_by_idx(mlnx_rif_obj.id.bridge_rif_idx, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup mlnx bridge rif entry by idx %u\n", mlnx_rif_obj.id.bridge_rif_idx);
            return status;
        }
        if (rif_mac_data) {
            *rif_mac_data = &br_rif->mac_data;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_rif_oid_data_fetch(_In_ sai_object_id_t             rif_oid,
                                            _Out_ mlnx_rif_type_t           *rif_type,
                                            _Inout_ uint32_t                *bridge_rif_idx,
                                            _Inout_ mlnx_shm_rm_array_idx_t *rif_db_idx,
                                            _Out_ mlnx_rif_sx_data_t       **sx_data,
                                            _Out_ bool                      *is_created)
{
    sai_status_t        status;
    mlnx_object_id_t    mlnx_rif_obj = {0};
    mlnx_bridge_rif_t  *br_rif = NULL;
    mlnx_rif_db_t      *rif_db = NULL;
    mlnx_rif_sx_data_t *data;
    bool                created;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_oid, &mlnx_rif_obj);
    if (SAI_ERR(status)) {
        return status;
    }

    if (mlnx_rif_obj.field.sub_type > MLNX_RIF_TYPE_BRIDGE) {
        SX_LOG_ERR("Invalid rif sub type - %d\n", mlnx_rif_obj.field.sub_type);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (rif_type) {
        *rif_type = mlnx_rif_obj.field.sub_type;
    }

    if (mlnx_rif_obj.field.sub_type == MLNX_RIF_TYPE_DEFAULT) {
        status = mlnx_rif_db_idx_to_data(mlnx_rif_obj.id.rif_db_idx, &rif_db);
        if (SAI_ERR(status)) {
            return status;
        }

        created = true;

        if (rif_db_idx) {
            *rif_db_idx = mlnx_rif_obj.id.rif_db_idx;
        }

        data = &rif_db->sx_data;
    } else { /* SAI_ROUTER_INTERFACE_TYPE_BRIDGE */
        status = mlnx_bridge_rif_by_idx(mlnx_rif_obj.id.bridge_rif_idx, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup mlnx bridge rif entry by idx %u\n", mlnx_rif_obj.id.bridge_rif_idx);
            return status;
        }

        created = br_rif->is_created;

        if (bridge_rif_idx) {
            *bridge_rif_idx = br_rif->index;
        }

        data = &br_rif->sx_data;
    }

    if (is_created) {
        *is_created = created;
    }

    if (sx_data) {
        *sx_data = data;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_oid_counter_get(_In_ sai_object_id_t rif_oid, _Out_ sx_router_counter_id_t *sx_counter)
{
    sai_status_t        status;
    mlnx_rif_sx_data_t *sx_data;
    bool                is_created;

    assert(sx_counter);

    status = mlnx_rif_oid_data_fetch(rif_oid, NULL, NULL, NULL, &sx_data, &is_created);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!is_created) {
        SX_LOG_ERR("RIF %lx is removed or not created yet\n", rif_oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *sx_counter = sx_data->counter;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_oid_to_bridge_rif(_In_ sai_object_id_t rif_oid, _Out_ uint32_t       *bridge_rif_idx)
{
    sai_status_t    status;
    mlnx_rif_type_t rif_type;

    status = mlnx_rif_oid_data_fetch(rif_oid, &rif_type, bridge_rif_idx, NULL, NULL, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    if (rif_type != MLNX_RIF_TYPE_BRIDGE) {
        SX_LOG_ERR("Invalid rif type - only router interface type bridge is supported\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_oid_to_sdk_rif_id(_In_ sai_object_id_t rif_oid, _Out_ sx_router_interface_t *sdk_rif_id)
{
    sai_status_t        status;
    mlnx_rif_type_t     rif_type;
    mlnx_rif_sx_data_t *sx_data;
    bool                is_created;

    assert(sdk_rif_id);

    status = mlnx_rif_oid_data_fetch(rif_oid, &rif_type, NULL, NULL, &sx_data, &is_created);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!is_created) {
        SX_LOG_ERR("Failed to find rif - rif is removed or not created\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *sdk_rif_id = sx_data->rif_id;

    return SAI_STATUS_SUCCESS;
}

bool mlnx_rif_is_additional_mac_supported(void)
{
    return (g_additional_mac_enabled && mlnx_chip_is_spc());
}

static bool mlnx_rif_check_additional_mac(_In_ const void *mac)
{
    sx_mac_addr_t input_mac;
    uint64_t      base_mac_addr_64 = 0;
    uint64_t      base_mac_prefix = 0;
    uint64_t      in_mac_addr_64 = 0;
    uint64_t      in_mac_prefix = 0;

    SX_LOG_ENTER();
    assert(NULL != mac);

    if (0 == g_sai_db_ptr->rif_mac_range_ref_counter) {
        return false;
    }

    memcpy(&input_mac, mac, sizeof(input_mac));
    base_mac_addr_64 = SX_MAC_TO_U64(g_sai_db_ptr->rif_mac_range_addr);
    base_mac_prefix = MAC_PREFIX_GET(base_mac_addr_64, g_resource_limits.router_mac_prefix_size);
    in_mac_addr_64 = SX_MAC_TO_U64(input_mac);
    in_mac_prefix = MAC_PREFIX_GET(in_mac_addr_64, g_resource_limits.router_mac_prefix_size);

    return (in_mac_prefix != base_mac_prefix);
}

static sai_status_t mlnx_rif_get_mac_in_profile_range(sx_mac_addr_t *mac)
{
    assert(NULL != mac);
    if (0 != g_sai_db_ptr->rif_mac_range_ref_counter) {
        memcpy(mac, &g_sai_db_ptr->rif_mac_range_addr, sizeof(*mac));
    } else {
        return mlnx_switch_get_mac(mac);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_sx_init(_In_ sx_router_id_t                     vrf_id,
                              _In_ const sx_router_interface_param_t *intf_params,
                              _In_ const sx_interface_attributes_t   *intf_attribs,
                              _Out_ sx_router_interface_t            *sx_rif_id,
                              _Out_ sx_router_counter_id_t           *sx_counter)
{
    sai_status_t status;
    sx_status_t  sx_status, out_status;
    bool         rif_created = false;
    bool         counter_created = false;
    bool         binded = false;
    bool         rif_mac_range_ref_updated = false;

    assert(sx_rif_id);
    assert(sx_counter);

    if (mlnx_rif_is_additional_mac_supported() && (intf_params->type != SX_L2_INTERFACE_TYPE_LOOPBACK)) {
        if (0 == g_sai_db_ptr->rif_mac_range_ref_counter) {
            memcpy(&g_sai_db_ptr->rif_mac_range_addr, &intf_attribs->mac_addr,
                   sizeof(g_sai_db_ptr->rif_mac_range_addr));
        } else {
            if (mlnx_rif_check_additional_mac(&intf_attribs->mac_addr)) {
                SX_LOG_ERR("Should not use additional mac in creating rif.\n");
                return SAI_STATUS_FAILURE;
            }
        }
        g_sai_db_ptr->rif_mac_range_ref_counter++;
        rif_mac_range_ref_updated = true;
    }

    sx_status = sx_api_router_interface_set(get_sdk_handle(),
                                            SX_ACCESS_CMD_ADD,
                                            vrf_id,
                                            intf_params,
                                            intf_attribs,
                                            sx_rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }
    rif_created = true;

    sx_status = sx_api_router_counter_set(get_sdk_handle(), SX_ACCESS_CMD_CREATE, sx_counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create router counter - %s\n", SX_STATUS_MSG(sx_status));
        goto out;
    }
    counter_created = true;

    sx_status =
        sx_api_router_interface_counter_bind_set(get_sdk_handle(), SX_ACCESS_CMD_BIND, *sx_counter, *sx_rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to bind router counter %d to rif %d - %s\n", *sx_counter, *sx_rif_id,
                   SX_STATUS_MSG(sx_status));
        goto out;
    }
    binded = true;

    status = mlnx_bmtor_rif_event_add(*sx_rif_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    SX_LOG_DBG("Created sx rif %d and counter %d\n", *sx_rif_id, *sx_counter);

    return SAI_STATUS_SUCCESS;
out:

    if (binded) {
        sx_status = sx_api_router_interface_counter_bind_set(get_sdk_handle(),
                                                             SX_ACCESS_CMD_UNBIND,
                                                             *sx_counter,
                                                             *sx_rif_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to unbind router counter %d to rif %d - %s\n", *sx_counter, *sx_rif_id,
                       SX_STATUS_MSG(sx_status));
        }
    }

    if (counter_created) {
        out_status = sx_api_router_counter_set(get_sdk_handle(), SX_ACCESS_CMD_DESTROY, sx_counter);
        if (SX_ERR(out_status)) {
            SX_LOG_ERR("Failed to destroy router counter - %s\n", SX_STATUS_MSG(out_status));
        }
    }

    if (rif_created) {
        out_status = sx_api_router_interface_set(get_sdk_handle(),
                                                 SX_ACCESS_CMD_DELETE,
                                                 vrf_id,
                                                 intf_params,
                                                 intf_attribs,
                                                 sx_rif_id);
        if (SX_ERR(out_status)) {
            SX_LOG_ERR("Failed to remove router interface - %s.\n", SX_STATUS_MSG(out_status));
        }
    }

    if (mlnx_rif_is_additional_mac_supported() && rif_mac_range_ref_updated) {
        assert(0 != g_sai_db_ptr->rif_mac_range_ref_counter);
        g_sai_db_ptr->rif_mac_range_ref_counter--;
        if (0 == g_sai_db_ptr->rif_mac_range_ref_counter) {
            memset(&g_sai_db_ptr->rif_mac_range_addr, 0, sizeof(g_sai_db_ptr->rif_mac_range_addr));
        }
    }

    return sdk_to_sai(sx_status);
}

sai_status_t mlnx_rif_sx_deinit(_In_ mlnx_rif_sx_data_t *sx_data)
{
    sai_status_t                status;
    sx_status_t                 sx_status;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_router_id_t              vrid;

    sx_status = sx_api_router_interface_get(get_sdk_handle(), sx_data->rif_id, &vrid, &intf_params, &intf_attribs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_interface_counter_bind_set(get_sdk_handle(),
                                                         SX_ACCESS_CMD_UNBIND,
                                                         sx_data->counter,
                                                         sx_data->rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to unbind router counter %d from rif %d - %s\n", sx_data->counter, sx_data->rif_id,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_counter_set(get_sdk_handle(), SX_ACCESS_CMD_DESTROY, &sx_data->counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove router counter %d - %s\n", sx_data->counter, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_bmtor_rif_event_del(sx_data->rif_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status =
        sx_api_router_interface_set(get_sdk_handle(),
                                    SX_ACCESS_CMD_DELETE,
                                    sx_data->vrf_id,
                                    NULL,
                                    NULL,
                                    &sx_data->rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (mlnx_rif_is_additional_mac_supported() && (intf_params.type != SX_L2_INTERFACE_TYPE_LOOPBACK)) {
        assert(0 != g_sai_db_ptr->rif_mac_range_ref_counter);
        g_sai_db_ptr->rif_mac_range_ref_counter--;
        if (0 == g_sai_db_ptr->rif_mac_range_ref_counter) {
            memset(&g_sai_db_ptr->rif_mac_range_addr, 0, sizeof(g_sai_db_ptr->rif_mac_range_addr));
        }
    }

    SX_LOG_DBG("Removed sx rif %d and counter %d\n", sx_data->rif_id, sx_data->counter);

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create router interface.
 *
 * Arguments:
 *    [out] rif_id - router interface id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_router_interface(_Out_ sai_object_id_t      *rif_id,
                                                 _In_ sai_object_id_t        switch_id,
                                                 _In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list)
{
    sx_router_interface_param_t  intf_params;
    sx_interface_attributes_t    intf_attribs;
    sx_vlan_id_t                 sx_vlan_id;
    sx_router_counter_id_t       sx_counter = 0;
    sx_port_log_id_t             sx_vport_id, sx_port_id = SX_INVALID_PORT;
    sx_status_t                  sx_status;
    sai_status_t                 status;
    mlnx_rif_type_t              rif_type = MLNX_RIF_TYPE_DEFAULT;
    mlnx_bridge_rif_t           *br_rif = NULL;
    mlnx_rif_db_t               *rif_db_data;
    mlnx_shm_rm_array_idx_t      db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    const sai_attribute_value_t *type, *vrid, *port = NULL, *vlan = NULL, *mtu, *mac, *adminv4, *adminv6, *mcastv4,
                                *mcastv6;
    const sai_attribute_value_t *loopback_action = NULL, *outer_vlan = NULL;
    uint32_t                     type_index, vrid_index, port_index, vlan_index, mtu_index, mac_index, adminv4_index,
                                 adminv6_index, vrid_data, acl_attr_index, loopback_action_index, attr_index,
                                 mcastv4_index, mcastv6_index;
    sx_router_interface_t        sdk_rif_id;
    sx_router_interface_state_t  rif_state;
    mlnx_port_config_t          *port_cfg;
    const sai_attribute_value_t *attr_ing_acl = NULL;
    const sai_attribute_value_t *attr_egr_acl = NULL;
    acl_index_t                  ing_acl_index = ACL_INDEX_INVALID, egr_acl_index = ACL_INDEX_INVALID;
    mlnx_object_id_t             vlan_obj;
    bool                         has_additional_mac = false;
    sx_mac_addr_t                additional_mac;
    bool                         is_ar_rif = false;

    SX_LOG_ENTER();

    status = check_attribs_on_create(attr_count, attr_list, SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_id);
    if (SAI_ERR(status)) {
        return status;
    }
    MLNX_LOG_ATTRS(attr_count, attr_list, SAI_OBJECT_TYPE_ROUTER_INTERFACE);

    memset(&intf_params, 0, sizeof(intf_params));
    memset(&intf_attribs, 0, sizeof(intf_attribs));
    memset(&rif_state, 0, sizeof(rif_state));
    intf_attribs.loopback_enable = true;

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_TYPE, &type, &type_index);
    assert(SAI_STATUS_SUCCESS == status);
    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, &vrid,
                                 &vrid_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(vrid->oid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &vrid_data, NULL))) {
        SX_LOG_EXIT();
        return status;
    }

    find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, &vlan, &vlan_index);

    find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_PORT_ID, &port, &port_index);

    find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, &outer_vlan, &attr_index);

    find_attrib_in_list(attr_count,
                        attr_list,
                        SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION,
                        &loopback_action,
                        &loopback_action_index);

    if (SAI_ROUTER_INTERFACE_TYPE_VLAN == type->s32) {
        if (!vlan) {
            SX_LOG_ERR("Missing mandatory attribute vlan id on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (port) {
            SX_LOG_ERR("Invalid attribute port id for rif vlan on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_VLAN, vlan->oid, &vlan_obj);
        if (SAI_ERR(status)) {
            return status;
        }

        intf_params.type = SX_L2_INTERFACE_TYPE_VLAN;
        intf_params.ifc.vlan.swid = DEFAULT_ETH_SWID;
        intf_params.ifc.vlan.vlan = vlan_obj.id.vlan_id;
    } else if (SAI_ROUTER_INTERFACE_TYPE_PORT == type->s32) {
        if (!port) {
            SX_LOG_ERR("Missing mandatory attribute port id on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }

        if (vlan) {
            SX_LOG_ERR("Invalid attribute vlan id for rif port on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + vlan_index;
        }

        status = mlnx_object_to_log_port(port->oid, &sx_port_id);
        if (SAI_ERR(status)) {
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }

        sai_db_read_lock();
        is_ar_rif = mlnx_find_ar_port_by_id(sx_port_id, NULL, NULL);
        sai_db_unlock();

        if (is_ar_rif) {
            SX_LOG_NTC("Creating rif based on adaptive routing enabled port log id %x.\n", sx_port_id);
            status = mlnx_bridge_sx_vport_create(sx_port_id, SX_VLAN_DEFAULT_VID, SX_UNTAGGED_MEMBER, &sx_vport_id);
            if (SAI_ERR(status)) {
                SX_LOG_EXIT();
                return status;
            }
            sx_status = sx_api_port_state_set(get_sdk_handle(), sx_vport_id, SX_PORT_ADMIN_STATUS_UP);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set port admin state - %s.\n", SX_STATUS_MSG(sx_status));
                SX_LOG_EXIT();
                return sdk_to_sai(sx_status);
            }

            intf_params.type = SX_L2_INTERFACE_TYPE_ADAPTIVE_ROUTING;
            intf_params.ifc.adaptive_routing.vport = sx_vport_id;
        } else {
            intf_params.type = SX_L2_INTERFACE_TYPE_PORT_VLAN;
            intf_params.ifc.port_vlan.port = sx_port_id;
            intf_params.ifc.port_vlan.vlan = 0;
        }
    } else if (SAI_ROUTER_INTERFACE_TYPE_LOOPBACK == type->s32) {
        if (port) {
            SX_LOG_ERR("Invalid attribute port id for loopback rif on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }

        if (vlan) {
            SX_LOG_ERR("Invalid attribute vlan id for loopback rif on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + vlan_index;
        }
        intf_params.type = SX_L2_INTERFACE_TYPE_LOOPBACK;
    } else if (SAI_ROUTER_INTERFACE_TYPE_BRIDGE == type->s32) {
        intf_params.type = SX_L2_INTERFACE_TYPE_BRIDGE;
        rif_type = MLNX_RIF_TYPE_BRIDGE;
    } else if (SAI_ROUTER_INTERFACE_TYPE_SUB_PORT == type->s32) {
        assert(outer_vlan);
        sx_vlan_id = outer_vlan->u16;

        status = mlnx_object_to_log_port(port->oid, &sx_port_id);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + port_index;
        }

        status = mlnx_bridge_sx_vport_create(sx_port_id, sx_vlan_id, SX_TAGGED_MEMBER, &sx_vport_id);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return status;
        }

        sx_status = sx_api_port_state_set(get_sdk_handle(), sx_vport_id, SX_PORT_ADMIN_STATUS_UP);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port admin state - %s.\n", SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }

        intf_params.type = SX_L2_INTERFACE_TYPE_VPORT;
        intf_params.ifc.vport.vport = sx_vport_id;
    } else {
        SX_LOG_ERR("Invalid router interface type %d\n", type->s32);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_MTU, &mtu, &mtu_index))) {
        intf_attribs.mtu = mtu->u32;
    } else {
        intf_attribs.mtu = DEFAULT_RIF_MTU;
    }

    sai_db_write_lock();
    acl_global_lock();

    if (port) {
        status = check_port_type_attr(&port->oid, 1, ATTR_PORT_IS_LAG_ENABLED,
                                      SAI_ROUTER_INTERFACE_ATTR_PORT_ID, port_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    /* do not fill src mac address for loop back interface */
    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, &mac,
                                 &mac_index))) {
        if (SAI_ROUTER_INTERFACE_TYPE_LOOPBACK == type->s32) {
            SX_LOG_ERR("src mac address is not valid for loopback router interface type\n");
            status = SAI_STATUS_INVALID_ATTRIBUTE_0 + mac_index;
            goto out;
        }

        if (mlnx_rif_is_additional_mac_supported()) {
            has_additional_mac = mlnx_rif_check_additional_mac(&mac->mac);
            if (has_additional_mac) {
                /* Get default mac from profile range */
                SX_LOG_DBG("Create with additional MAC\n");
                status = mlnx_rif_get_mac_in_profile_range(&intf_attribs.mac_addr);
                if (SAI_ERR(status)) {
                    goto out;
                }
                memcpy(&additional_mac, mac->mac, sizeof(additional_mac));
            } else {
                memcpy(&intf_attribs.mac_addr, mac->mac, sizeof(intf_attribs.mac_addr));
            }
        } else {
            memcpy(&intf_attribs.mac_addr, mac->mac, sizeof(intf_attribs.mac_addr));
        }
    } else {
        if (mlnx_rif_is_additional_mac_supported()) {
            /* get mac from the profile range */
            status = mlnx_rif_get_mac_in_profile_range(&intf_attribs.mac_addr);
            if (SAI_ERR(status)) {
                goto out;
            }
        } else {
            /* Get default mac from switch object */
            status = mlnx_switch_get_mac(&intf_attribs.mac_addr);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
    }

    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL,
                                     &attr_ing_acl,
                                     &acl_attr_index);
        if (status == SAI_STATUS_SUCCESS) {
            status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_ing_acl->oid,
                                                               MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE,
                                                               acl_attr_index,
                                                               &ing_acl_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL,
                                     &attr_egr_acl,
                                     &acl_attr_index);
        if (status == SAI_STATUS_SUCCESS) {
            status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_egr_acl->oid,
                                                               MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE,
                                                               acl_attr_index,
                                                               &egr_acl_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
    }

    if (loopback_action) {
        status = mlnx_rif_loopback_action_sai_to_sx(loopback_action, loopback_action_index, &intf_attribs);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    intf_attribs.multicast_ttl_threshold = DEFAULT_MULTICAST_TTL_THRESHOLD;
    /* Work according to global DSCP<->Prio (TC in SAI terms), SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP */
    intf_attribs.qos_mode = SX_ROUTER_QOS_MODE_NOP;

    /* disable learn for router port / sub port, as unlike interface vlan, router port holds one vector in FDB
     * as all neighbors always egress through the router port. Otherwise FDB events for router port generate
     * unsupported VID mode error. TODO : should be internal in SDK, clean this afterwards */
    if ((SAI_ROUTER_INTERFACE_TYPE_PORT == type->s32) || (SAI_ROUTER_INTERFACE_TYPE_SUB_PORT == type->s32)) {
        status = sx_api_fdb_port_learn_mode_set(get_sdk_handle(), sx_port_id, SX_FDB_LEARN_MODE_DONT_LEARN);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to set port learning mode disable for router port - %s.\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
    }

    /* We create a real bridge rif only while creation of .1D bridge port type router */
    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        status = mlnx_rif_db_alloc(&rif_db_data, &db_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("RIF Counter DB is full\n");
            goto out;
        }

        status = mlnx_rif_sx_init(vrid_data, &intf_params, &intf_attribs, &sdk_rif_id, &sx_counter);
        if (SAI_ERR(status)) {
            goto out;
        }
        if (SAI_ROUTER_INTERFACE_TYPE_PORT == type->s32) {
            status = mlnx_port_by_log_id(sx_port_id, &port_cfg);
            if (SAI_ERR(status)) {
                goto out;
            }
            status = sx_api_vlan_port_pvid_get(get_sdk_handle(), port_cfg->logical, &port_cfg->pvid_create_rif);
            if (SX_ERR(status)) {
                SX_LOG_ERR("Failed to get %x pvid - %s.\n", port_cfg->logical, SX_STATUS_MSG(status));
                status = sdk_to_sai(status);
                goto out;
            }
            SX_LOG_INF("Record the pvid %d of port 0x%x\n", port_cfg->pvid_create_rif, sx_port_id);
        }

        if (mlnx_rif_is_additional_mac_supported() && has_additional_mac) {
            sx_status = sx_api_router_interface_mac_set(get_sdk_handle(),
                                                        SX_ACCESS_CMD_ADD,
                                                        sdk_rif_id,
                                                        &additional_mac,
                                                        1);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set additional MAC - %s.\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(status);
                goto out;
            }

            rif_db_data->mac_data.additional_mac_is_used = has_additional_mac;
            memcpy(&rif_db_data->mac_data.additional_mac_addr, &additional_mac,
                   sizeof(rif_db_data->mac_data.additional_mac_addr));
        }

        rif_db_data->sx_data.rif_id = sdk_rif_id;
        rif_db_data->sx_data.counter = sx_counter;
        rif_db_data->sx_data.vrf_id = vrid_data;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, &adminv4,
                                 &adminv4_index))) {
        rif_state.ipv4_enable = adminv4->booldata;
    } else {
        rif_state.ipv4_enable = true;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, &adminv6,
                                 &adminv6_index))) {
        rif_state.ipv6_enable = adminv6->booldata;
    } else {
        rif_state.ipv6_enable = true;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE, &mcastv4,
                                 &mcastv4_index);
    if (!SAI_ERR(status)) {
        rif_state.ipv4_mc_enable = mcastv4->booldata;
    } else {
        rif_state.ipv4_mc_enable = false;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE, &mcastv6,
                                 &mcastv6_index);
    if (!SAI_ERR(status)) {
        rif_state.ipv6_mc_enable = mcastv6->booldata;
    } else {
        rif_state.ipv6_mc_enable = false;
    }
    if ((SAI_ROUTER_INTERFACE_TYPE_LOOPBACK != type->s32) && (SAI_ROUTER_INTERFACE_TYPE_BRIDGE != type->s32)) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_interface_state_set(get_sdk_handle(), sdk_rif_id, &rif_state))) {
            SX_LOG_ERR("Failed to set router interface state - %s.\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
    }

    if (rif_type == MLNX_RIF_TYPE_BRIDGE) {
        status = mlnx_bridge_rif_add((sx_router_id_t)vrid_data, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to allocate bridge rif entry\n");
            goto out;
        }

        memcpy(&br_rif->intf_attribs, &intf_attribs, sizeof(br_rif->intf_attribs));
        memcpy(&br_rif->intf_params, &intf_params, sizeof(br_rif->intf_params));
        memcpy(&br_rif->intf_state, &rif_state, sizeof(br_rif->intf_state));

        br_rif->mac_data.additional_mac_is_used = has_additional_mac;
        if (has_additional_mac) {
            memcpy(&br_rif->mac_data.additional_mac_addr, &additional_mac,
                   sizeof(br_rif->mac_data.additional_mac_addr));
        }
    }

    status = mlnx_rif_oid_create(rif_type, br_rif, db_idx, rif_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create rif oid\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        if (attr_ing_acl) {
            status = mlnx_acl_port_lag_rif_bind_point_set(*rif_id, MLNX_ACL_BIND_POINT_TYPE_INGRESS_ROUTER_INTERFACE,
                                                          ing_acl_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        if (attr_egr_acl) {
            status = mlnx_acl_port_lag_rif_bind_point_set(*rif_id, MLNX_ACL_BIND_POINT_TYPE_EGRESS_ROUTER_INTERFACE,
                                                          egr_acl_index);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
    }

    if ((SAI_ROUTER_INTERFACE_TYPE_PORT == type->s32) || (SAI_ROUTER_INTERFACE_TYPE_SUB_PORT == type->s32)) {
        status = mlnx_port_by_log_id(sx_port_id, &port_cfg);
        if (SAI_ERR(status)) {
            goto out;
        }
        port_cfg->rifs++;
    }

    MLNX_LOG_OID_CREATED(*rif_id);

out:
    if (SAI_ERR(status)) {
        mlnx_rif_db_free(db_idx);
    }
    acl_global_unlock();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove router interface
 *
 * Arguments:
 *    [in] rif_id - router interface id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_router_interface(_In_ sai_object_id_t rif_id)
{
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_port_log_id_t            sx_port_id, sx_vport_id;
    sx_vlan_id_t                sx_vlan_id;
    sx_status_t                 sx_status;
    sai_status_t                status;
    mlnx_rif_type_t             rif_type;
    uint32_t                    bridge_rif_idx;
    mlnx_shm_rm_array_idx_t     rif_db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_bridge_rif_t          *br_rif;
    mlnx_port_config_t         *port_cfg;
    bool                        is_port_or_sub_port = false, is_created;
    mlnx_bridge_port_t         *bport;
    sx_vid_t                    pvid;
    sx_vlan_ports_t             port_list;

    SX_LOG_ENTER();

    MLNX_LOG_OID_REMOVE(rif_id);

    sai_db_write_lock();

    status = mlnx_rif_oid_data_fetch(rif_id, &rif_type, &bridge_rif_idx, &rif_db_idx, &sx_data, &is_created);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        status = mlnx_acl_rif_bind_point_clear(rif_id);
        if (SAI_ERR(status)) {
            goto out;
        }

        sx_status = sx_api_router_interface_get(get_sdk_handle(), sx_data->rif_id, &sx_data->vrf_id, &intf_params,
                                                &intf_attribs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        status = mlnx_rif_sx_deinit(sx_data);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_rif_db_free(rif_db_idx);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (SX_L2_INTERFACE_TYPE_PORT_VLAN == intf_params.type) {
            is_port_or_sub_port = true;
            sx_port_id = intf_params.ifc.port_vlan.port;
            status = mlnx_port_by_log_id(sx_port_id, &port_cfg);
            if (SAI_ERR(status)) {
                goto out;
            }
            sx_status = sx_api_vlan_port_pvid_get(get_sdk_handle(), port_cfg->logical, &pvid);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get %x pvid - %s.\n", port_cfg->logical, SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
            SX_LOG_INF("Port/lag 0x%x pvid_create_rif %d, current pvid %d\n",
                       port_cfg->logical, port_cfg->pvid_create_rif, pvid);
            /* handle case of pvid change on router port
             * sdk tries to remove router port from current pvid
             * if pvid of router port has changed, need to remove router port
             * from the original pvid the time it was created, as sdk added it to
             * that vlan on creation
             */
            if (port_cfg->pvid_create_rif != pvid) {
                bport = 0;
                status = mlnx_bridge_1q_port_by_log(port_cfg->logical, &bport);
                if ((status != SAI_STATUS_SUCCESS) || !mlnx_vlan_port_is_set(port_cfg->pvid_create_rif, bport)) {
                    memset(&port_list, 0, sizeof(port_list));
                    port_list.log_port = port_cfg->logical;
                    sx_status = sx_api_vlan_ports_set(get_sdk_handle(),
                                                      SX_ACCESS_CMD_DELETE,
                                                      DEFAULT_ETH_SWID,
                                                      port_cfg->pvid_create_rif,
                                                      &port_list, 1);
                    if (SX_ERR(sx_status)) {
                        SX_LOG_ERR("Failed to delete port/lag 0x%x from vlan %d, current pvid %d - %s\n",
                                   port_cfg->logical, port_cfg->pvid_create_rif, pvid, SX_STATUS_MSG(sx_status));
                    }
                } else {
                    SX_LOG_INF("Port/lag 0x%x was in vlan %d before creating rif.\n",
                               port_cfg->logical, port_cfg->pvid_create_rif);
                }
            }
            port_cfg->pvid_create_rif = 0;
        }

        if (SX_L2_INTERFACE_TYPE_VPORT == intf_params.type) {
            is_port_or_sub_port = true;
            sx_vport_id = intf_params.ifc.vport.vport;

            sx_status = sx_api_port_vport_base_get(get_sdk_handle(), sx_vport_id, &sx_vlan_id, &sx_port_id);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get base port and vlan for vport %x - %s\n",
                           sx_vport_id,
                           SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }

            status = mlnx_bridge_sx_vport_delete(sx_port_id, sx_vlan_id, sx_vport_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        if (SX_L2_INTERFACE_TYPE_ADAPTIVE_ROUTING == intf_params.type) {
            is_port_or_sub_port = true;
            sx_vport_id = intf_params.ifc.adaptive_routing.vport;

            sx_status = sx_api_port_vport_base_get(get_sdk_handle(), sx_vport_id, &sx_vlan_id, &sx_port_id);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get base port and vlan for vport %x - %s\n",
                           sx_vport_id,
                           SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }

            status = mlnx_bridge_sx_vport_delete(sx_port_id, sx_vlan_id, sx_vport_id);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to delete vport 0x%x\n", sx_vport_id);
                goto out;
            }
        }

        if (is_port_or_sub_port) {
            sx_status = sx_api_fdb_port_learn_mode_set(get_sdk_handle(), sx_port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set port learning mode auto for removed router port - %s.\n",
                           SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }

            status = mlnx_port_by_log_id(sx_port_id, &port_cfg);
            if (SAI_ERR(status)) {
                goto out;
            }
            port_cfg->rifs--;
        }
    } else { /* SAI_ROUTER_INTERFACE_TYPE_BRIDGE */
        if (is_created) {
            SX_LOG_ERR("Failed to remove rif which is bound to the bridge\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = mlnx_bridge_rif_by_idx(bridge_rif_idx, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup mlnx bridge rif entry by idx %u\n", bridge_rif_idx);
            goto out;
        }

        status = mlnx_bridge_rif_del(br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to remove mlnx bridge rif entry\n");
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
 *    Set router interface attribute
 *
 * Arguments:
 *    [in] rif_id - router interface id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_router_interface_attribute(_In_ sai_object_id_t rif_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = rif_id };

    return sai_set_attribute(&key, SAI_OBJECT_TYPE_ROUTER_INTERFACE, attr);
}

/*
 * Routine Description:
 *    Get router interface attribute
 *
 * Arguments:
 *    [in] rif_id - router interface id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_router_interface_attribute(_In_ sai_object_id_t     rif_id,
                                                        _In_ uint32_t            attr_count,
                                                        _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = rif_id };

    return sai_get_attributes(&key, SAI_OBJECT_TYPE_ROUTER_INTERFACE, attr_count, attr_list);
}

sai_status_t mlnx_rif_loopback_action_sai_to_sx(_In_ const sai_attribute_value_t *loopback_action,
                                                _In_ uint32_t                     attr_index,
                                                _Out_ sx_interface_attributes_t  *intf_attribs)
{
    assert(loopback_action);
    assert(intf_attribs);

    if ((loopback_action->s32 != SAI_PACKET_ACTION_DROP) && (loopback_action->s32 != SAI_PACKET_ACTION_FORWARD)) {
        SX_LOG_ERR("Unsupported value for LOOPBACK_PACKET_ACTION - %d. Supported: "
                   "SAI_PACKET_ACTION_DROP, SAI_PACKET_ACTION_FORWARD\n", loopback_action->s32);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attr_index;
    }

    intf_attribs->loopback_enable = (loopback_action->s32 == SAI_PACKET_ACTION_FORWARD);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_rif_attr_to_sdk(sai_router_interface_attr_t  attr,
                                         const sai_attribute_value_t *value,
                                         sx_interface_attributes_t   *intf_attribs,
                                         sx_router_interface_param_t *intf_params,
                                         sx_router_interface_state_t *rif_state,
                                         bool                        *has_additional_mac)
{
    sai_status_t status;

    switch (attr) {
    case SAI_ROUTER_INTERFACE_ATTR_MTU:
        intf_attribs->mtu = (uint16_t)value->u32;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        /* Note, RIF admin has to be down when editing MAC */
        if (SX_L2_INTERFACE_TYPE_LOOPBACK == intf_params->type) {
            SX_LOG_ERR("src mac address cannot be set for loopback router interface\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if (mlnx_rif_is_additional_mac_supported()) {
            assert(NULL != has_additional_mac);
            *has_additional_mac = mlnx_rif_check_additional_mac(&value->mac);
            if (*has_additional_mac) {
                /* Get default mac from profile range */
                SX_LOG_DBG("Set additional MAC\n");
                status = mlnx_rif_get_mac_in_profile_range(&intf_attribs->mac_addr);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to get mac from profile range.\n");
                    SX_LOG_EXIT();
                    return status;
                }
            } else {
                memcpy(&intf_attribs->mac_addr, value->mac, sizeof(intf_attribs->mac_addr));
            }
        } else {
            memcpy(&intf_attribs->mac_addr, value->mac, sizeof(intf_attribs->mac_addr));
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
        rif_state->ipv4_enable = value->booldata;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        rif_state->ipv6_enable = value->booldata;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE:
        rif_state->ipv4_mc_enable = value->booldata;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE:
        rif_state->ipv6_mc_enable = value->booldata;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION:
        status = mlnx_rif_loopback_action_sai_to_sx(value, 0, intf_attribs);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    default:
        assert(false);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_sx_attrs_get(_In_ sai_object_id_t                rif_oid,
                                   _In_ bool                           is_admin_state,
                                   _Out_ mlnx_rif_type_t              *rif_type,
                                   _Out_ bool                         *is_created,
                                   _Out_ mlnx_rif_sx_data_t          **sx_data,
                                   _Out_ sx_router_interface_state_t **rif_state,
                                   _Out_ sx_router_interface_param_t **intf_params,
                                   _Out_ sx_interface_attributes_t   **intf_attribs)
{
    sx_status_t             sx_status;
    sai_status_t            status;
    sx_router_id_t          vrid;
    sx_router_interface_t   rif_id;
    mlnx_bridge_rif_t      *br_rif;
    uint32_t                bridge_rif_db_idx;
    mlnx_shm_rm_array_idx_t rif_db_idx;

    status = mlnx_rif_oid_data_fetch(rif_oid, rif_type, &bridge_rif_db_idx, &rif_db_idx, sx_data, is_created);
    if (SAI_ERR(status)) {
        return status;
    }

    rif_id = (*sx_data)->rif_id;
    vrid = (*sx_data)->vrf_id;

    if (*rif_type == MLNX_RIF_TYPE_BRIDGE) {
        status = mlnx_bridge_rif_by_idx(bridge_rif_db_idx, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif entry by idx %u\n", bridge_rif_db_idx);
            return status;
        }

        *rif_state = &br_rif->intf_state;
        *intf_params = &br_rif->intf_params;
        *intf_attribs = &br_rif->intf_attribs;
    } else {
        if (is_admin_state) {
            sx_status = sx_api_router_interface_state_get(get_sdk_handle(), rif_id, *rif_state);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get router interface state - %s.\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        } else {
            sx_status = sx_api_router_interface_get(get_sdk_handle(), rif_id, &vrid, *intf_params, *intf_attribs);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* MAC Address [sai_mac_t] */
/* MTU [uint32_t] */
/* Admin State V4, V6 [bool] */
/* Multicast V4 V6 enable [bool]*/
/* Multicast enabling is currently not supported */
#define RIF_SEC_MAC_MAX 100
static sai_status_t mlnx_rif_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sx_status_t                 sx_status;
    sx_router_id_t              vrid;
    sx_router_interface_state_t rif_state, *rif_state_ptr = &rif_state;
    sx_router_interface_param_t intf_params, *intf_params_ptr = &intf_params;
    sx_interface_attributes_t   intf_attribs, *intf_attribs_ptr = &intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id;
    bool                        is_admin_state;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_rif_type_t             rif_type;
    bool                        is_created;
    sai_router_interface_attr_t attr = (sai_router_interface_attr_t)arg;
    bool                        has_additional_mac;
    sx_mac_addr_t               additional_mac;
    sx_mac_addr_t               mac_addr_arr[RIF_SEC_MAC_MAX];
    uint32_t                    mac_addr_num = RIF_SEC_MAC_MAX;
    mlnx_rif_mac_data_t        *rif_mac_data;

    SX_LOG_ENTER();

    is_admin_state = attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE;

    sai_db_read_lock();

    status = mlnx_rif_sx_attrs_get(key->key.object_id, is_admin_state, &rif_type, &is_created, &sx_data,
                                   &rif_state_ptr, &intf_params_ptr, &intf_attribs_ptr);
    if (SAI_ERR(status)) {
        goto out;
    }

    if ((rif_type == MLNX_RIF_TYPE_BRIDGE) && (!is_created)) {
        SX_LOG_ERR("RIF %lx is not created yet. Bridge port of a type "
                   "SAI_BRIDGE_PORT_TYPE_1D_ROUTER needs to be created first\n", key->key.object_id);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_rif_attr_to_sdk(attr, value, intf_attribs_ptr, intf_params_ptr, rif_state_ptr, &has_additional_mac);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert rif params from SAI attr\n");
        goto out;
    }

    rif_id = sx_data->rif_id;
    vrid = sx_data->vrf_id;

    if (is_admin_state) {
        sx_status = sx_api_router_interface_state_set(get_sdk_handle(), rif_id, rif_state_ptr);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set router interface state - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    } else {
        if (mlnx_rif_is_additional_mac_supported() && has_additional_mac) {
            status = mlnx_rif_oid_to_mac_data(key->key.object_id, &rif_mac_data);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get mac data.\n");
                goto out;
            }
            rif_mac_data->additional_mac_is_used = has_additional_mac;

            sx_status = sx_api_router_interface_mac_get(get_sdk_handle(), rif_id, mac_addr_arr, &mac_addr_num);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get additional MAC - %s.\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
            if (mac_addr_num > 1) {
                SX_LOG_ERR("Got more than one additional MAC.\n");
                status = SAI_STATUS_FAILURE;
                goto out;
            }
            if (1 == mac_addr_num) {
                sx_status = sx_api_router_interface_mac_set(get_sdk_handle(),
                                                            SX_ACCESS_CMD_DELETE,
                                                            rif_id,
                                                            &mac_addr_arr[0],
                                                            1);
                if (SX_ERR(sx_status)) {
                    SX_LOG_ERR("Failed to delete old additional MAC - %s.\n", SX_STATUS_MSG(sx_status));
                    status = sdk_to_sai(sx_status);
                    goto out;
                }
                memset(&rif_mac_data->additional_mac_addr, 0, sizeof(rif_mac_data->additional_mac_addr));
            }
            memcpy(&additional_mac, value->mac, sizeof(additional_mac));
            sx_status =
                sx_api_router_interface_mac_set(get_sdk_handle(), SX_ACCESS_CMD_ADD, rif_id, &additional_mac, 1);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set new additional MAC - %s.\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
            memcpy(&rif_mac_data->additional_mac_addr, &additional_mac, sizeof(rif_mac_data->additional_mac_addr));
        } else {
            sx_status = sx_api_router_interface_set(get_sdk_handle(),
                                                    SX_ACCESS_CMD_EDIT,
                                                    vrid,
                                                    intf_params_ptr,
                                                    intf_attribs_ptr,
                                                    &rif_id);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        }
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* Virtual router id [sai_object_id_t] */
/* Type [sai_router_interface_type_t] */
/* Associated Port or Lag object id [sai_object_id_t] */
/* Associated Vlan [sai_vlan_id_t] */
/* MAC Address [sai_mac_t] */
/* MTU [uint32_t] */
/* Admin State V4, V6 [bool] */
/* Multicast V4 V6 enable [bool]*/
/* Multicast enabling is currently not supported */
static sai_status_t mlnx_rif_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sx_router_interface_state_t rif_state, *rif_state_ptr = &rif_state;
    sx_router_interface_param_t intf_params, *intf_params_ptr = &intf_params;
    sx_interface_attributes_t   intf_attribs, *intf_attribs_ptr = &intf_attribs;
    sx_status_t                 status;
    sx_port_log_id_t            sx_port_id = SX_INVALID_PORT;
    sx_vlan_id_t                sx_vlan_id = 0;
    bool                        is_admin_state;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_rif_type_t             rif_type;
    bool                        is_created;
    sai_router_interface_attr_t attr = (sai_router_interface_attr_t)arg;

    SX_LOG_ENTER();

    is_admin_state = attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE;

    sai_db_read_lock();

    status = mlnx_rif_sx_attrs_get(key->key.object_id, is_admin_state, &rif_type, &is_created, &sx_data,
                                   &rif_state_ptr, &intf_params_ptr, &intf_attribs_ptr);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    sai_db_unlock();

    if (SX_L2_INTERFACE_TYPE_VPORT == intf_params_ptr->type) {
        status = sx_api_port_vport_base_get(get_sdk_handle(),
                                            intf_params_ptr->ifc.vport.vport,
                                            &sx_vlan_id,
                                            &sx_port_id);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get base port and vlan for vport %x - %s\n",
                       intf_params_ptr->ifc.vport.vport,
                       SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else {
        sx_port_id = intf_params_ptr->ifc.port_vlan.port;
        sx_vlan_id = intf_params_ptr->ifc.vlan.vlan;
    }

    switch (attr) {
    case SAI_ROUTER_INTERFACE_ATTR_PORT_ID:
        if ((SX_L2_INTERFACE_TYPE_PORT_VLAN != intf_params_ptr->type) &&
            (SX_L2_INTERFACE_TYPE_VPORT != intf_params_ptr->type)) {
            SX_LOG_ERR("Can't get port id from interface whose type isn't port or sub-port\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }

        status = mlnx_log_port_to_object(sx_port_id, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_VLAN_ID:
        if (SX_L2_INTERFACE_TYPE_VLAN != intf_params_ptr->type) {
            SX_LOG_ERR("Can't get vlan id from interface whose type isn't vlan or sub-port\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }

        status = mlnx_vlan_oid_create(sx_vlan_id, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID:
        if (SX_L2_INTERFACE_TYPE_VPORT != intf_params_ptr->type) {
            SX_LOG_ERR("Can't get outer vlan id from interface whose type isn't sub-port\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }

        value->u16 = sx_vlan_id;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_MTU:
        value->u32 = intf_attribs_ptr->mtu;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        if (SX_L2_INTERFACE_TYPE_LOOPBACK == intf_params_ptr->type) {
            SX_LOG_ERR("src mac address is not valid for loopback router interface\n");
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_PARAMETER;
        }
        memcpy(value->mac, &intf_attribs_ptr->mac_addr, sizeof(intf_attribs_ptr->mac_addr));
        break;

    case SAI_ROUTER_INTERFACE_ATTR_TYPE:
        switch (intf_params_ptr->type) {
        case SX_L2_INTERFACE_TYPE_PORT_VLAN:
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;
            break;

        case SX_L2_INTERFACE_TYPE_VLAN:
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
            break;

        case SX_L2_INTERFACE_TYPE_LOOPBACK:
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_LOOPBACK;
            break;

        case SX_L2_INTERFACE_TYPE_BRIDGE:
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_BRIDGE;
            break;

        case SX_L2_INTERFACE_TYPE_VPORT:
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_SUB_PORT;
            break;

        default:
            SX_LOG_ERR("Unexpected router interface type %d\n", intf_params_ptr->type);
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID:
        status = mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, sx_data->vrf_id, NULL, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
        value->booldata = rif_state_ptr->ipv4_enable;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        value->booldata = rif_state_ptr->ipv6_enable;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION:
        value->s32 = intf_attribs_ptr->loopback_enable ? SAI_PACKET_ACTION_FORWARD : SAI_PACKET_ACTION_DROP;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE:
        value->booldata = rif_state_ptr->ipv4_mc_enable;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE:
        value->booldata = rif_state_ptr->ipv6_mc_enable;
        break;

    default:
        assert(false);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Get router interface statistics counters extended.
 *
 * @param[in] router_interface_id Router interface id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_get_router_interface_stats_ext(_In_ sai_object_id_t      router_interface_id,
                                                        _In_ uint32_t             number_of_counters,
                                                        _In_ const sai_stat_id_t *counter_ids,
                                                        _In_ sai_stats_mode_t     mode,
                                                        _Out_ uint64_t           *counters)
{
    sx_status_t             sx_status;
    sai_status_t            status;
    sx_access_cmd_t         sx_cmd;
    sx_router_counter_set_t sx_counter_set;
    sx_router_counter_id_t  sx_counter;
    uint32_t                ii;
    char                    key_str[MAX_KEY_STR_LEN];

    memset(&sx_counter_set, 0, sizeof(sx_counter_set));

    SX_LOG_ENTER();

    oid_to_str(router_interface_id, key_str);
    SX_LOG_DBG("Get stats %s\n", key_str);

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (mode > SAI_STATS_MODE_READ_AND_CLEAR) {
        SX_LOG_ERR("Invalid sai_stats_mode_t - %d\n", mode);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_cmd = (mode == SAI_STATS_MODE_READ) ? SX_ACCESS_CMD_READ : SX_ACCESS_CMD_READ_CLEAR;

    sai_db_read_lock();

    status = mlnx_rif_oid_counter_get(router_interface_id, &sx_counter);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    sx_status = sx_api_router_counter_get(get_sdk_handle(), sx_cmd, sx_counter, &sx_counter_set);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s sx counter %d - %s\n", SX_ACCESS_CMD_STR(sx_cmd), sx_counter,
                   SX_STATUS_MSG(sx_status));
        sai_db_unlock();
        SX_LOG_EXIT();
        return sdk_to_sai(sx_status);
    }

    sai_db_unlock();

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_ROUTER_INTERFACE_STAT_IN_OCTETS:
            counters[ii] = sx_counter_set.router_ingress_good_unicast_bytes +
                           sx_counter_set.router_ingress_good_multicast_bytes +
                           sx_counter_set.router_ingress_good_broadcast_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_IN_PACKETS:
            counters[ii] = sx_counter_set.router_ingress_good_unicast_packets +
                           sx_counter_set.router_ingress_good_multicast_packets +
                           sx_counter_set.router_ingress_good_broadcast_packets;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS:
            counters[ii] = sx_counter_set.router_egress_good_unicast_bytes +
                           sx_counter_set.router_egress_good_multicast_bytes +
                           sx_counter_set.router_egress_good_broadcast_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS:
            counters[ii] = sx_counter_set.router_egress_good_unicast_packets +
                           sx_counter_set.router_egress_good_multicast_packets +
                           sx_counter_set.router_egress_good_broadcast_packets;
            break;

        case SAI_ROUTER_INTERFACE_STAT_IN_ERROR_OCTETS:
            counters[ii] = sx_counter_set.router_ingress_error_bytes +
                           sx_counter_set.router_ingress_discard_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS:
            counters[ii] = sx_counter_set.router_ingress_error_packets +
                           sx_counter_set.router_ingress_discard_packets;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_OCTETS:
            counters[ii] = sx_counter_set.router_egress_error_bytes +
                           sx_counter_set.router_egress_discard_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS:
            counters[ii] = sx_counter_set.router_egress_error_packets +
                           sx_counter_set.router_egress_discard_packets;
            break;

        default:
            SX_LOG_ERR("Invalid sai_router_interface_stat_t - %d\n", counter_ids[ii]);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Get router interface statistics counters. Deprecated for backward compatibility.
 *
 * @param[in] router_interface_id Router interface id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_get_router_interface_stats(_In_ sai_object_id_t      router_interface_id,
                                                    _In_ uint32_t             number_of_counters,
                                                    _In_ const sai_stat_id_t *counter_ids,
                                                    _Out_ uint64_t           *counters)
{
    return mlnx_get_router_interface_stats_ext(router_interface_id,
                                               number_of_counters,
                                               counter_ids,
                                               SAI_STATS_MODE_READ,
                                               counters);
}

/**
 * @brief Clear router interface statistics counters.
 *
 * @param[in] router_interface_id Router interface id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_clear_router_interface_stats(_In_ sai_object_id_t      router_interface_id,
                                                      _In_ uint32_t             number_of_counters,
                                                      _In_ const sai_stat_id_t *counter_ids)
{
    sx_status_t             sx_status;
    sai_status_t            status;
    sx_router_counter_set_t sx_counter_set;
    sx_router_counter_id_t  sx_counter;
    uint32_t                ii;

    memset(&sx_counter_set, 0, sizeof(sx_counter_set));

    SX_LOG_ENTER();

    MLNX_LOG_OID("Clear stats", router_interface_id);

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        if (counter_ids[ii] > SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS) {
            SX_LOG_ERR("Invalid counter id - %d\n", counter_ids[ii]);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }
    }

    sai_db_read_lock();

    status = mlnx_rif_oid_counter_get(router_interface_id, &sx_counter);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_router_counter_clear_set(get_sdk_handle(), sx_counter, false);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to clear sx counter %d - %s\n", sx_counter, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_rif_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_debug_set_additional_mac_for_ptf(_In_ const char* value)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     rifs_exists;
    sx_status_t  sx_status;

    assert(NULL != value);

    if (!mlnx_chip_is_spc()) {
        SX_LOG_NTC("Additional mac is only supported by SPC1.\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sai_db_write_lock();
    sx_status = sx_api_router_interface_iter_get(get_sdk_handle(), SX_ACCESS_CMD_GET, NULL, NULL, NULL, &rifs_exists);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get count of router interfaces - %s\n", SX_STATUS_MSG(sx_status));
        sai_status = sdk_to_sai(sx_status);
        goto out;
    }

    if (0 != rifs_exists) {
        SX_LOG_ERR("Additional mac can only be enable/disable in clean state.\n");
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (atoi(value) > 0) {
        SX_LOG_NTC("Additional mac is enabled on live.\n");
        g_additional_mac_enabled = true;
    } else {
        SX_LOG_NTC("Additional mac is disabled on live.\n");
        g_additional_mac_enabled = false;
    }

out:
    sai_db_unlock();
    return sai_status;
}

bool mlnx_rif_is_ar_enabled(_In_ sai_object_id_t rif_id)
{
    mlnx_rif_type_t             rif_type;
    sai_status_t                status;
    sx_status_t                 sx_status;
    mlnx_rif_sx_data_t         *sx_data;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;

    status = mlnx_rif_oid_data_fetch(rif_id, &rif_type, NULL, NULL, &sx_data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fetch rif oid data from rif id - %" PRIx64 ".\n", rif_id);
        return false;
    }

    if (rif_type == MLNX_RIF_TYPE_DEFAULT) {
        sx_status = sx_api_router_interface_get(get_sdk_handle(), sx_data->rif_id, &sx_data->vrf_id, &intf_params,
                                                &intf_attribs);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            return false;
        }

        if (SX_L2_INTERFACE_TYPE_ADAPTIVE_ROUTING == intf_params.type) {
            return true;
        }
    }

    return false;
}

const sai_router_interface_api_t mlnx_router_interface_api = {
    mlnx_create_router_interface,
    mlnx_remove_router_interface,
    mlnx_set_router_interface_attribute,
    mlnx_get_router_interface_attribute,
    mlnx_get_router_interface_stats,
    mlnx_get_router_interface_stats_ext,
    mlnx_clear_router_interface_stats,
};
