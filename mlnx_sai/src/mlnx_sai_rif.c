/*
 *  Copyright (C) 2017. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

static sai_status_t check_attrs_port_type(_In_ const sai_object_key_t *key,
                                          _In_ uint32_t                count,
                                          _In_ const sai_attribute_t  *attrs)
{
    uint32_t ii;

    sai_db_read_lock();
    for (ii = 0; ii < count; ii++) {
        const sai_attribute_t *attr  = &attrs[ii];
        attr_port_type_check_t check = ATTR_PORT_IS_LAG_ENABLED;

        if (attr->id == SAI_ROUTER_INTERFACE_ATTR_PORT_ID) {
            sai_status_t status;

            status = check_port_type_attr(&attr->value.oid, 1, check, attr->id, ii);

            sai_db_unlock();
            return status;
        }
    }
    sai_db_unlock();

    return SAI_STATUS_SUCCESS;
}

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_rif_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_rif_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_rif_loopback_action_sai_to_sx(_In_ const sai_attribute_value_t *loopback_action,
                                                       _In_ uint32_t                     attr_index,
                                                       _Out_ sx_interface_attributes_t  *intf_attribs);
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
        SAI_PACKET_ACTION_FORWARD),
};
const mlnx_obj_type_attrs_info_t          mlnx_rif_obj_type_info =
{ rif_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(rif_enum_info)};
static void rif_key_to_str(_In_ sai_object_id_t rif_id, _Out_ char *key_str)
{
    const mlnx_object_id_t *mlnx_oid = (const mlnx_object_id_t*)&rif_id;
    bool                    is_bridge_rif;

    is_bridge_rif = (mlnx_oid->field.sub_type == MLNX_RIF_TYPE_BRIDGE);

    if (mlnx_oid->object_type != SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid rif");
    } else {
        if (is_bridge_rif) {
            snprintf(key_str, MAX_KEY_STR_LEN, "bridge rif idx %u", mlnx_oid->id.bridge_rif_idx);
        } else {
            snprintf(key_str, MAX_KEY_STR_LEN, "rif idx %u", mlnx_oid->id.rif_db_idx.idx);
        }
    }
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
    *rif   = (mlnx_rif_db_t*)data;

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

    mlnx_oid->object_type    = SAI_OBJECT_TYPE_ROUTER_INTERFACE;
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
    sx_router_interface_t rif    = *(const sx_router_interface_t*)data;

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

static sai_status_t mlnx_rif_oid_data_fetch(_In_ sai_object_id_t             rif_oid,
                                            _Out_ mlnx_rif_type_t           *rif_type,
                                            _Inout_ uint32_t                *bridge_rif_idx,
                                            _Inout_ mlnx_shm_rm_array_idx_t *rif_db_idx,
                                            _Out_ mlnx_rif_sx_data_t       **sx_data,
                                            _Out_ bool                      *is_created)
{
    sai_status_t        status;
    mlnx_object_id_t    mlnx_rif_obj = {0};
    mlnx_bridge_rif_t  *br_rif       = NULL;
    mlnx_rif_db_t      *rif_db       = NULL;
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

static sai_status_t mlnx_rif_oid_counter_get(_In_ sai_object_id_t rif_oid, _Out_ sx_router_counter_id_t *sx_counter)
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

sai_status_t mlnx_rif_sx_init(_In_ sx_router_id_t                     vrf_id,
                              _In_ const sx_router_interface_param_t *intf_params,
                              _In_ const sx_interface_attributes_t   *intf_attribs,
                              _Out_ sx_router_interface_t            *sx_rif_id,
                              _Out_ sx_router_counter_id_t           *sx_counter)
{
    sx_status_t sx_status;

    assert(sx_rif_id);
    assert(sx_counter);

    sx_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_ADD, vrf_id, intf_params, intf_attribs, sx_rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_counter_set(gh_sdk, SX_ACCESS_CMD_CREATE, sx_counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create router counter - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_interface_counter_bind_set(gh_sdk, SX_ACCESS_CMD_BIND, *sx_counter, *sx_rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to bind router counter %d to rif %d - %s\n", *sx_counter, *sx_rif_id,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("Created sx rif %d and counter %d\n", *sx_rif_id, *sx_counter);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_rif_sx_deinit(_In_ mlnx_rif_sx_data_t *sx_data)
{
    sx_status_t sx_status;

    sx_status = sx_api_router_interface_counter_bind_set(gh_sdk,
                                                         SX_ACCESS_CMD_UNBIND,
                                                         sx_data->counter,
                                                         sx_data->rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to unbind router counter %d from rif %d - %s\n", sx_data->counter, sx_data->rif_id,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_router_counter_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sx_data->counter);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove router counter %d - %s\n", sx_data->counter, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status =
        sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_data->vrf_id, NULL, NULL, &sx_data->rif_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete router interface - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
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
    mlnx_bridge_rif_t           *br_rif   = NULL;
    mlnx_rif_db_t               *rif_db_data;
    mlnx_shm_rm_array_idx_t      db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    const sai_attribute_value_t *type, *vrid, *port = NULL, *vlan = NULL, *mtu, *mac, *adminv4, *adminv6,
    *loopback_action = NULL;
    uint32_t type_index, vrid_index, port_index, vlan_index, mtu_index, mac_index, adminv4_index,
             adminv6_index, vrid_data, acl_attr_index, loopback_action_index;
    sx_router_interface_t        sdk_rif_id;
    sx_router_interface_state_t  rif_state;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    mlnx_port_config_t          *port_cfg;
    const sai_attribute_value_t *attr_ing_acl  = NULL;
    const sai_attribute_value_t *attr_egr_acl  = NULL;
    acl_index_t                  ing_acl_index = ACL_INDEX_INVALID, egr_acl_index = ACL_INDEX_INVALID;
    mlnx_object_id_t             vlan_obj;

    SX_LOG_ENTER();

    if (NULL == rif_id) {
        SX_LOG_ERR("NULL rif id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ROUTER_INTERFACE, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create rif, %s\n", list_str);

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

        intf_params.type          = SX_L2_INTERFACE_TYPE_VLAN;
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

        intf_params.type               = SX_L2_INTERFACE_TYPE_PORT_VLAN;
        intf_params.ifc.port_vlan.port = sx_port_id;
        intf_params.ifc.port_vlan.vlan = 0;
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
        rif_type         = MLNX_RIF_TYPE_BRIDGE;
    } else if (SAI_ROUTER_INTERFACE_TYPE_SUB_PORT == type->s32) {
        status = sai_object_to_vlan(vlan->oid, &sx_vlan_id);
        if (SAI_ERR(status)) {
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_index;
        }

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

        sx_status = sx_api_port_state_set(gh_sdk, sx_vport_id, SX_PORT_ADMIN_STATUS_UP);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port admin state - %s.\n", SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }

        intf_params.type            = SX_L2_INTERFACE_TYPE_VPORT;
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
        memcpy(&intf_attribs.mac_addr, mac->mac, sizeof(intf_attribs.mac_addr));
    } else {
        /* Get default mac from switch object */
        status = mlnx_switch_get_mac(&intf_attribs.mac_addr);
        if (SAI_ERR(status)) {
            goto out;
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
        status = sx_api_fdb_port_learn_mode_set(gh_sdk, sx_port_id, SX_FDB_LEARN_MODE_DONT_LEARN);
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

        rif_db_data->sx_data.rif_id  = sdk_rif_id;
        rif_db_data->sx_data.counter = sx_counter;
        rif_db_data->sx_data.vrf_id  = vrid_data;
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

    if ((SAI_ROUTER_INTERFACE_TYPE_LOOPBACK != type->s32) && (SAI_ROUTER_INTERFACE_TYPE_BRIDGE != type->s32)) {
        if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_set(gh_sdk, sdk_rif_id, &rif_state))) {
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

    rif_key_to_str(*rif_id, key_str);
    SX_LOG_NTC("Created rif %s\n", key_str);

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
    sx_status_t                 status;
    mlnx_rif_type_t             rif_type;
    uint32_t                    bridge_rif_idx;
    mlnx_shm_rm_array_idx_t     rif_db_idx = MLNX_SHM_RM_ARRAY_IDX_UNINITIALIZED;
    mlnx_rif_sx_data_t         *sx_data;
    mlnx_bridge_rif_t          *br_rif;
    char                        key_str[MAX_KEY_STR_LEN];
    mlnx_port_config_t         *port_cfg;
    bool                        is_port_or_sub_port = false, is_created;

    SX_LOG_ENTER();

    rif_key_to_str(rif_id, key_str);
    SX_LOG_NTC("Remove rif %s\n", key_str);

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

        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_api_router_interface_get(gh_sdk, sx_data->rif_id, &sx_data->vrf_id, &intf_params,
                                             &intf_attribs))) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
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
            sx_port_id          = intf_params.ifc.port_vlan.port;
        }

        if (SX_L2_INTERFACE_TYPE_VPORT == intf_params.type) {
            is_port_or_sub_port = true;
            sx_vport_id         = intf_params.ifc.vport.vport;

            status = sx_api_port_vport_base_get(gh_sdk, sx_vport_id, &sx_vlan_id, &sx_port_id);
            if (SX_ERR(status)) {
                SX_LOG_ERR("Failed to get base port and vlan for vport %x - %s\n", sx_vport_id, SX_STATUS_MSG(status));
                status = sdk_to_sai(status);
                goto out;
            }

            status = mlnx_bridge_sx_vport_delete(sx_port_id, sx_vlan_id, sx_vport_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        if (is_port_or_sub_port) {
            status = sx_api_fdb_port_learn_mode_set(gh_sdk, sx_port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
            if (SX_ERR(status)) {
                SX_LOG_ERR("Failed to set port learning mode auto for removed router port - %s.\n",
                           SX_STATUS_MSG(status));
                status = sdk_to_sai(status);
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
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    status = check_attrs_port_type(&key, 1, attr);
    if (SAI_ERR(status)) {
        return status;
    }

    rif_key_to_str(rif_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_vendor_attribs, attr);
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
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    rif_key_to_str(rif_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                              rif_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t mlnx_rif_loopback_action_sai_to_sx(_In_ const sai_attribute_value_t *loopback_action,
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
                                         sx_router_interface_state_t *rif_state)
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
        memcpy(&intf_attribs->mac_addr, value->mac, sizeof(intf_attribs->mac_addr));
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
        rif_state->ipv4_enable = value->booldata;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        rif_state->ipv6_enable = value->booldata;
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

static sai_status_t mlnx_rif_sx_attrs_get(_In_ sai_object_id_t                rif_oid,
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
    vrid   = (*sx_data)->vrf_id;

    if (*rif_type == MLNX_RIF_TYPE_BRIDGE) {
        status = mlnx_bridge_rif_by_idx(bridge_rif_db_idx, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif entry by idx %u\n", bridge_rif_db_idx);
            return status;
        }

        *rif_state    = &br_rif->intf_state;
        *intf_params  = &br_rif->intf_params;
        *intf_attribs = &br_rif->intf_attribs;
    } else {
        if (is_admin_state) {
            sx_status = sx_api_router_interface_state_get(gh_sdk, rif_id, *rif_state);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to get router interface state - %s.\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        } else {
            sx_status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, *intf_params, *intf_attribs);
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

    SX_LOG_ENTER();

    is_admin_state = attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE ||
                     attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;

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

    status = mlnx_rif_attr_to_sdk(attr, value, intf_attribs_ptr, intf_params_ptr, rif_state_ptr);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert rif params from SAI attr\n");
        goto out;
    }

    rif_id = sx_data->rif_id;
    vrid   = sx_data->vrf_id;

    if (is_admin_state) {
        sx_status = sx_api_router_interface_state_set(gh_sdk, rif_id, rif_state_ptr);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set router interface state - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    } else {
        sx_status = sx_api_router_interface_set(gh_sdk,
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

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* Virtual router id [sai_object_id_t] */
/* Type [sai_router_interface_type_t] */
/* Assosiated Port or Lag object id [sai_object_id_t] */
/* Assosiated Vlan [sai_vlan_id_t] */
/* MAC Address [sai_mac_t] */
/* MTU [uint32_t] */
/* Admin State V4, V6 [bool] */
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
                     attr == SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;

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
        status = sx_api_port_vport_base_get(gh_sdk, intf_params_ptr->ifc.vport.vport, &sx_vlan_id, &sx_port_id);
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
        if ((SX_L2_INTERFACE_TYPE_VLAN != intf_params_ptr->type) &&
            (SX_L2_INTERFACE_TYPE_VPORT != intf_params_ptr->type)) {
            SX_LOG_ERR("Can't get vlan id from interface whose type isn't vlan or sub-port\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }

        status = mlnx_vlan_oid_create(sx_vlan_id, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
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
static sai_status_t mlnx_get_router_interface_stats_ext(_In_ sai_object_id_t                    router_interface_id,
                                                        _In_ uint32_t                           number_of_counters,
                                                        _In_ const sai_stat_id_t               *counter_ids,
                                                        _In_ sai_stats_mode_t                   mode,
                                                        _Out_ uint64_t                         *counters)
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

    rif_key_to_str(router_interface_id, key_str);
    SX_LOG_DBG("Get rif stats %s\n", key_str);

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

    sx_status = sx_api_router_counter_get(gh_sdk, sx_cmd, sx_counter, &sx_counter_set);
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
            counters[ii] = sx_counter_set.router_ingress_bad_unicast_bytes +
                           sx_counter_set.router_ingress_bad_multicast_bytes +
                           sx_counter_set.router_ingress_error_bytes +
                           sx_counter_set.router_ingress_discard_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS:
            counters[ii] = sx_counter_set.router_ingress_bad_unicast_packets +
                           sx_counter_set.router_ingress_bad_multicast_packets +
                           sx_counter_set.router_ingress_error_packets +
                           sx_counter_set.router_ingress_discard_packets;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_OCTETS:
            counters[ii] = sx_counter_set.router_egress_bad_unicast_bytes +
                           sx_counter_set.router_egress_bad_multicast_bytes +
                           sx_counter_set.router_egress_error_bytes +
                           sx_counter_set.router_egress_discard_bytes;
            break;

        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS:
            counters[ii] = sx_counter_set.router_egress_bad_unicast_packets +
                           sx_counter_set.router_egress_bad_multicast_packets +
                           sx_counter_set.router_egress_error_packets +
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
static sai_status_t mlnx_get_router_interface_stats(_In_ sai_object_id_t                    router_interface_id,
                                                    _In_ uint32_t                           number_of_counters,
                                                    _In_ const sai_stat_id_t               *counter_ids,
                                                    _Out_ uint64_t                         *counters)
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
static sai_status_t mlnx_clear_router_interface_stats(_In_ sai_object_id_t                    router_interface_id,
                                                      _In_ uint32_t                           number_of_counters,
                                                      _In_ const sai_stat_id_t               *counter_ids)
{
    sx_status_t             sx_status;
    sai_status_t            status;
    sx_router_counter_set_t sx_counter_set;
    sx_router_counter_id_t  sx_counter;
    uint32_t                ii;
    char                    key_str[MAX_KEY_STR_LEN];

    memset(&sx_counter_set, 0, sizeof(sx_counter_set));

    SX_LOG_ENTER();

    rif_key_to_str(router_interface_id, key_str);
    SX_LOG_DBG("Clear rif stats %s\n", key_str);

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

    sx_status = sx_api_router_counter_clear_set(gh_sdk, sx_counter, false);
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

const sai_router_interface_api_t mlnx_router_interface_api = {
    mlnx_create_router_interface,
    mlnx_remove_router_interface,
    mlnx_set_router_interface_attribute,
    mlnx_get_router_interface_attribute,
    mlnx_get_router_interface_stats,
    mlnx_get_router_interface_stats_ext,
    mlnx_clear_router_interface_stats,
};
