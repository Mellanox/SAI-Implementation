/*
 *  Copyright (C) 2014. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#include "mlnx_sai.h"
#include "assert.h"
#include "sai.h"

#undef  __MODULE__
#define __MODULE__ SAI_BRIDGE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_bridge_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_bridge_port_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_bridge_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_bridge_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                          _In_ const sai_attribute_value_t *value,
                                                          void                             *arg);
static sai_status_t mlnx_bridge_learn_disable_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_bridge_learn_disable_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg);
static const sai_vendor_attribute_entry_t bridge_vendor_attribs[] = {
    { SAI_BRIDGE_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_type_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_ATTR_PORT_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_bridge_port_list_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_max_learned_addresses_get, NULL,
      mlnx_bridge_max_learned_addresses_set, NULL },
    { SAI_BRIDGE_ATTR_LEARN_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_learn_disable_get, NULL,
      mlnx_bridge_learn_disable_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static sai_status_t mlnx_bridge_port_type_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_bridge_port_lag_or_port_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_bridge_port_vlan_id_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_bridge_port_rif_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_bridge_port_tunnel_id_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_bridge_port_bridge_id_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_bridge_port_bridge_id_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg);
static sai_status_t mlnx_bridge_port_fdb_learning_mode_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg);
static sai_status_t mlnx_bridge_port_fdb_learning_mode_set(_In_ const sai_object_key_t      *key,
                                                           _In_ const sai_attribute_value_t *value,
                                                           void                             *arg);
static sai_status_t mlnx_bridge_port_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg);
static sai_status_t mlnx_bridge_port_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                               _In_ const sai_attribute_value_t *value,
                                                               void                             *arg);
static sai_status_t mlnx_bridge_port_admin_state_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_bridge_port_admin_state_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_bridge_port_admin_state_set_internal(_In_ mlnx_bridge_port_t *bridge_port, _In_ bool value);
static const sai_vendor_attribute_entry_t bridge_port_vendor_attribs[] = {
    { SAI_BRIDGE_PORT_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_port_type_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_port_lag_or_port_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_port_vlan_id_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_RIF_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_port_rif_id_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_TUNNEL_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_bridge_port_tunnel_id_get, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_BRIDGE_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_port_bridge_id_get, NULL,
      mlnx_bridge_port_bridge_id_set, NULL },
    { SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_port_fdb_learning_mode_get, NULL,
      mlnx_bridge_port_fdb_learning_mode_set, NULL },
    { SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_port_max_learned_addresses_get, NULL,
      mlnx_bridge_port_max_learned_addresses_set, NULL },
    { SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION,
      { true, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_ADMIN_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_bridge_port_admin_state_get, NULL,
      mlnx_bridge_port_admin_state_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

sx_bridge_id_t mlnx_bridge_default_1q(void)
{
    return g_sai_db_ptr->sx_bridge_id;
}

static sai_status_t mlnx_bridge_port_add(sx_bridge_id_t         bridge_id,
                                         sai_bridge_port_type_t port_type,
                                         mlnx_bridge_port_t   **port)
{
    mlnx_bridge_port_t *new_port;
    uint32_t            ii;

    for (ii = 0; ii < MAX_BRIDGE_PORTS; ii++) {
        if (!g_sai_db_ptr->bridge_ports_db[ii].is_present) {
            new_port = &g_sai_db_ptr->bridge_ports_db[ii];

            new_port->bridge_id  = bridge_id;
            new_port->port_type  = port_type;
            new_port->is_present = true;
            new_port->index      = ii;

            *port = new_port;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_TABLE_FULL;
}

static sai_status_t mlnx_bridge_port_del(mlnx_bridge_port_t *port)
{
    memset(port, 0, sizeof(*port));
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_port_by_idx(uint32_t idx, mlnx_bridge_port_t **port)
{
    if (idx >= MAX_BRIDGE_PORTS) {
        SX_LOG_ERR("Invalid bridge port idx - greater or equal than %u\n", MAX_BRIDGE_PORTS);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *port = &g_sai_db_ptr->bridge_ports_db[idx];
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_port_by_oid(sai_object_id_t oid, mlnx_bridge_port_t **port)
{
    mlnx_object_id_t mlnx_bport_id = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, oid, &mlnx_bport_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge port oid %" PRIx64 " to mlnx object id\n", oid);
        return status;
    }

    return mlnx_bridge_port_by_idx(mlnx_bport_id.id.u32, port);
}

sai_status_t mlnx_bridge_port_by_log(sx_port_log_id_t log, mlnx_bridge_port_t **port)
{
    mlnx_bridge_port_t *it;
    uint32_t            ii;

    mlnx_bridge_port_foreach(it, ii) {
        if (it->logical == log) {
            *port = it;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_INVALID_PORT_NUMBER;
}

sai_status_t mlnx_bridge_port_to_oid(mlnx_bridge_port_t *port, sai_object_id_t *oid)
{
    mlnx_object_id_t mlnx_bport_id = {0};

    mlnx_bport_id.id.u32 = port->index;

    return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_BRIDGE_PORT, &mlnx_bport_id, oid);
}

static bool mlnx_bridge_port_in_1q_by_log(sx_port_log_id_t log_id)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    status = mlnx_bridge_port_by_log(log_id, &port);
    if (SAI_ERR(status)) {
        return false;
    }

    return port->bridge_id == mlnx_bridge_default_1q();
}

sai_status_t mlnx_bridge_rif_add(sx_router_id_t vrf_id, mlnx_bridge_rif_t **rif)
{
    mlnx_bridge_rif_t *new_rif;
    uint32_t           ii;

    for (ii = 0; ii < MAX_BRIDGE_RIFS; ii++) {
        if (!g_sai_db_ptr->bridge_rifs_db[ii].is_used) {
            new_rif = &g_sai_db_ptr->bridge_rifs_db[ii];

            new_rif->vrf_id  = vrf_id;
            new_rif->is_used = true;
            new_rif->index   = ii;

            *rif = new_rif;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_TABLE_FULL;
}

sai_status_t mlnx_bridge_rif_del(mlnx_bridge_rif_t *rif)
{
    memset(rif, 0, sizeof(*rif));
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_rif_by_idx(uint32_t idx, mlnx_bridge_rif_t **rif)
{
    if (idx >= MAX_BRIDGE_RIFS) {
        SX_LOG_ERR("Invalid bridge rif idx - greater or equal than %u\n", MAX_BRIDGE_RIFS);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *rif = &g_sai_db_ptr->bridge_rifs_db[idx];
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_rif_to_oid(mlnx_bridge_rif_t *rif, sai_object_id_t *oid)
{
    mlnx_object_id_t mlnx_rif_obj = {0};

    mlnx_rif_obj.field.sub_type = MLNX_RIF_TYPE_BRIDGE;
    mlnx_rif_obj.id.u32         = rif->index;

    return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_ROUTER_INTERFACE, &mlnx_rif_obj, oid);
}

static sai_status_t check_attrs_port_type(_In_ const sai_object_key_t *key,
                                          _In_ uint32_t                count,
                                          _In_ const sai_attribute_t  *attrs)
{
    uint32_t ii;

    for (ii = 0; ii < count; ii++) {
        attr_port_type_check_t check = ATTR_PORT_IS_ENABLED | ATTR_PORT_IS_LAG_ENABLED;
        const sai_attribute_t *attr  = &attrs[ii];
        sai_status_t           status;

        switch (attr->id) {
        case SAI_BRIDGE_PORT_ATTR_PORT_ID:
            status = check_port_type_attr(&attr->value.oid, 1, check, attr->id, ii);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Check port attr type failed port oid %" PRIx64 "\n", attr->value.oid);
                return status;
            }

            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_port_is_in_bridge(const mlnx_port_config_t *port)
{
    mlnx_bridge_port_t *bridge_port;

    return mlnx_bridge_port_by_log(port->logical, &bridge_port) == SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_bridge_object(sai_bridge_type_t sai_br_type,
                                       sx_bridge_id_t    sx_br_id,
                                       sai_object_id_t  *bridge_oid)
{
    mlnx_object_id_t mlnx_bridge_id = {0};

    mlnx_bridge_id.ext.bridge.type = sai_br_type;
    mlnx_bridge_id.id.bridge_id    = sx_br_id;

    return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_BRIDGE, &mlnx_bridge_id, bridge_oid);
}

sai_status_t mlnx_bridge_oid_to_id(sai_object_id_t oid, sx_bridge_id_t *bridge_id)
{
    mlnx_object_id_t mlnx_obj_id = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, oid, &mlnx_obj_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to parse bridge oid\n");
        return status;
    }

    *bridge_id = mlnx_obj_id.id.bridge_id;
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_port_sai_to_log_port(sai_object_id_t oid, sx_port_log_id_t *log_port)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(oid, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", oid);
        goto out;
    }

    if ((port->port_type != SAI_BRIDGE_PORT_TYPE_PORT) && (port->port_type != SAI_BRIDGE_PORT_TYPE_SUB_PORT)) {
        SX_LOG_ERR("Invalid bridge port type %u - should be port or sub-port\n", port->port_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    *log_port = port->logical;
out:
    sai_db_unlock();
    return status;
}

sai_status_t mlnx_bridge_port_to_vlan_port(sai_object_id_t oid, sx_port_log_id_t *log_port)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    assert(log_port);

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(oid, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", oid);
        goto out;
    }

    if (port->port_type != SAI_BRIDGE_PORT_TYPE_PORT) {
        SX_LOG_ERR("Invalid bridge port type %u - should be port\n", port->port_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    *log_port = port->logical;
out:
    sai_db_unlock();
    return status;
}

/* Used in case the log_port is a bridge port in .1Q bridge (actually regular log port) or vport */
sai_status_t mlnx_log_port_to_sai_bridge_port(sx_port_log_id_t log_port, sai_object_id_t *oid)
{
    sai_status_t status;

    status = mlnx_log_port_to_sai_bridge_port_soft(log_port, oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed lookup bridge port by logical id %x\n", log_port);
    }

    return status;
}

/* The same as mlnx_log_port_to_sai_bridge_port but without error message */
sai_status_t mlnx_log_port_to_sai_bridge_port_soft(sx_port_log_id_t log_port, sai_object_id_t *oid)
{
    sai_status_t        status;
    mlnx_bridge_port_t *port;

    sai_db_read_lock();

    status = mlnx_bridge_port_by_log(log_port, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_bridge_port_to_oid(port, oid);

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_bridge_sx_vport_set(_In_ sx_port_log_id_t   sx_port,
                                             _In_ sx_vlan_id_t       sx_vlan_id,
                                             _In_ bool               is_create,
                                             _Out_ sx_port_log_id_t *sx_vport)
{
    sx_status_t     sx_status;
    sx_vlan_ports_t vlan_port_list;

    assert(sx_vport);

    memset(&vlan_port_list, 0, sizeof(vlan_port_list));

    vlan_port_list.log_port    = sx_port;
    vlan_port_list.is_untagged = SX_TAGGED_MEMBER;

    /*
     * vport_set and vlan_ports_set are called in different order to prevent a packet getting to .1Q bridge.
     * It can happent when port is in the vlan but vport is not created/removed
     */
    if (is_create) {
        sx_status = sx_api_port_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_port, sx_vlan_id, sx_vport);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create vport {%x : %d} - %s\n", sx_port, sx_vlan_id, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, sx_vlan_id, &vlan_port_list, 1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add port %x to vlan %d - %s\n", sx_port, sx_vlan_id, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        SX_LOG_DBG("Create vport {%x : %d}\n", sx_port, sx_vlan_id);
    } else {
        sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, sx_vlan_id, &vlan_port_list, 1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to remove port %x from vlan %d - %s\n", sx_port, sx_vlan_id, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_port_vport_set(gh_sdk, SX_ACCESS_CMD_DELETE, sx_port, sx_vlan_id, sx_vport);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete vport {%x : %d} - %s\n", sx_port, sx_vlan_id, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        SX_LOG_DBG("Removed vport {%x : %d}\n", sx_port, sx_vlan_id);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_sx_vport_create(_In_ sx_port_log_id_t   sx_port,
                                         _In_ sx_vlan_id_t       sx_vlan_id,
                                         _Out_ sx_port_log_id_t *sx_vport)
{
    return mlnx_bridge_sx_vport_set(sx_port, sx_vlan_id, true, sx_vport);
}

sai_status_t mlnx_bridge_sx_vport_delete(_In_ sx_port_log_id_t  sx_port,
                                         _In_ sx_vlan_id_t      sx_vlan_id,
                                         _In_ sx_port_log_id_t  sx_vport)
{
    return mlnx_bridge_sx_vport_set(sx_port, sx_vlan_id, false, &sx_vport);
}

/**
 * @brief Bridge type
 *
 * @type sai_bridge_type_t
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 */
static sai_status_t mlnx_bridge_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    mlnx_object_id_t mlnx_bridge_id = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, key->key.object_id, &mlnx_bridge_id);
    if (SAI_ERR(status)) {
        return status;
    }

    value->s32 = mlnx_bridge_id.ext.bridge.type;
    return status;
}

/**
 * @brief List of bridge ports associated to this bridge
 *
 * @type sai_object_list_t
 * @objects SAI_OBJECT_TYPE_BRIDGE_PORT
 * @flags READ_ONLY
 */
static sai_status_t mlnx_bridge_port_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    mlnx_object_id_t    mlnx_bridge_id = {0};
    sx_bridge_id_t      bridge_id;
    uint32_t            ii, jj = 0;
    sai_status_t        status;
    sai_object_id_t    *ports = NULL;
    uint32_t            count = 0;
    mlnx_bridge_port_t *port;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, key->key.object_id, &mlnx_bridge_id);
    if (SAI_ERR(status)) {
        return status;
    }
    bridge_id = mlnx_bridge_id.id.bridge_id;

    sai_db_read_lock();

    mlnx_bridge_port_foreach(port, ii) {
        if (port->bridge_id != bridge_id) {
            continue;
        }

        count++;
    }

    ports = calloc(count, sizeof(*ports));
    if (!ports) {
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    mlnx_bridge_port_foreach(port, ii) {
        if (port->bridge_id != bridge_id) {
            continue;
        }

        status = mlnx_bridge_port_to_oid(port, &ports[jj++]);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert bridge port to oid\n");
            goto out;
        }
    }

    status = mlnx_fill_objlist(ports, count, &value->objlist);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill bridge port list\n");
    }

out:
    sai_db_unlock();
    free(ports);

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Maximum number of learned MAC addresses
 *
 * Zero means learning limit disable
 *
 * @type sai_uint32_t
 * @flags CREATE_AND_SET
 * @default 0
 */
static sai_status_t mlnx_bridge_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sx_bridge_id_t sx_bridge_id;

    SX_LOG_ENTER();

    status = mlnx_bridge_oid_to_id(key->key.object_id, &sx_bridge_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (sx_bridge_id == mlnx_bridge_default_1q()) {
        value->u32 = MLNX_FDB_LEARNING_NO_LIMIT_VALUE;
        goto out;
    }

    status = mlnx_vlan_bridge_max_learned_addresses_get(sx_bridge_id, &value->u32);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Maximum number of learned MAC addresses
 *
 * Zero means learning limit disable
 *
 * @type sai_uint32_t
 * @flags CREATE_AND_SET
 * @default 0
 */
static sai_status_t mlnx_bridge_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                          _In_ const sai_attribute_value_t *value,
                                                          void                             *arg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sx_bridge_id_t sx_bridge_id;
    uint32_t       limit;

    SX_LOG_ENTER();

    status = mlnx_bridge_oid_to_id(key->key.object_id, &sx_bridge_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    limit = value->u32;

    if (sx_bridge_id == mlnx_bridge_default_1q()) {
        if (MLNX_FDB_IS_LEARNING_LIMIT_EXISTS(limit)) {
            SX_LOG_ERR("Unsupported value for the default .1Q Bridge. The only supported is %d (no limit)\n",
                       MLNX_FDB_LEARNING_NO_LIMIT_VALUE);
            status = SAI_STATUS_NOT_SUPPORTED;
        } else {
            status = SAI_STATUS_SUCCESS;
        }

        goto out;
    }

    status = mlnx_max_learned_addresses_value_validate(limit, 0);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_vlan_bridge_max_learned_addresses_set(sx_bridge_id, limit);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief To disable learning on a bridge
 *
 * @type bool
 * @flags CREATE_AND_SET
 * @default false
 */
static sai_status_t mlnx_bridge_learn_disable_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    SX_LOG_ENTER();
    value->booldata = false;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief To disable learning on a bridge
 *
 * @type bool
 * @flags CREATE_AND_SET
 * @default false
 */
static sai_status_t mlnx_bridge_learn_disable_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static void bridge_key_to_str(_In_ sai_object_id_t bridge_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_bridge = {0};
    sai_status_t     status;
    const char      *br_type_name;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, bridge_id, &mlnx_bridge);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge");
    } else {
        br_type_name = (mlnx_bridge.ext.bridge.type == SAI_BRIDGE_TYPE_1D) ? "1d" : "1q";

        snprintf(key_str, MAX_KEY_STR_LEN, "bridge %u (.%s)", mlnx_bridge.id.bridge_id, br_type_name);
    }
}


/**
 * @brief Create bridge
 *
 * @param[out] bridge_id Bridge ID
 * @param[in] switch_id Switch object id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_bridge(_Out_ sai_object_id_t     * bridge_id,
                                       _In_ sai_object_id_t        switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_bridge_id_t               sx_bridge_id;
    sx_status_t                  sx_status;
    const sai_attribute_value_t *attr_val, *max_learned_addresses = NULL;
    uint32_t                     attr_idx, max_learned_addresses_index;
    sai_status_t                 status;

    SX_LOG_ENTER();

    if (NULL == bridge_id) {
        SX_LOG_ERR("NULL bridge ID param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_BRIDGE, bridge_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        goto out;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_BRIDGE, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create bridge, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_ATTR_TYPE, &attr_val, &attr_idx);
    assert(!SAI_ERR(status));

    if (attr_val->s32 != SAI_BRIDGE_TYPE_1D) {
        SX_LOG_ERR("Not supported bridge type %d\n", attr_val->s32);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES,
                                 &max_learned_addresses, &max_learned_addresses_index);
    if (!SAI_ERR(status)) {
        status = mlnx_max_learned_addresses_value_validate(max_learned_addresses->u32, max_learned_addresses_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sx_status = sx_api_bridge_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sx_bridge_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create .1D bridge - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (max_learned_addresses) {
        status = mlnx_vlan_bridge_max_learned_addresses_set(sx_bridge_id, max_learned_addresses->u32);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_create_bridge_object(SAI_BRIDGE_TYPE_1D, sx_bridge_id, bridge_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create bridge oid\n");
        goto out;
    }

    bridge_key_to_str(*bridge_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove bridge
 *
 * @param[in] bridge_id Bridge ID
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_bridge(_In_ sai_object_id_t bridge_id)
{
    mlnx_object_id_t    mlnx_bridge_id = {0};
    sx_bridge_id_t      sx_bridge_id;
    bool                has_ports = false;
    sx_status_t         sx_status;
    sai_status_t        status;
    mlnx_bridge_port_t *port;
    uint32_t            ii;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, bridge_id, &mlnx_bridge_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }
    sx_bridge_id = mlnx_bridge_id.id.bridge_id;

    sai_db_read_lock();

    if (sx_bridge_id == mlnx_bridge_default_1q()) {
        SX_LOG_ERR("Could not remove default .1Q bridge\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    mlnx_bridge_port_foreach(port, ii) {
        if (port->bridge_id == sx_bridge_id) {
            has_ports = true;
            break;
        }
    }

    if (has_ports) {
        SX_LOG_ERR("Failed to remove bridge which has ports\n");
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    sx_status = sx_api_bridge_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sx_bridge_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to remove .1D bridge - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    SX_LOG_NTC("Removed bridge id %" PRIx64 "\n", bridge_id);

out:
    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set attribute for bridge
 *
 * @param[in] bridge_id Bridge ID
 * @param[in] attr attribute to set
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_bridge_attribute(_In_ sai_object_id_t bridge_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = bridge_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    bridge_key_to_str(bridge_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_BRIDGE, bridge_vendor_attribs, attr);
}

/**
 * @brief Get attributes of bridge
 *
 * @param[in] bridge_id Bridge ID
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_bridge_attribute(_In_ sai_object_id_t     bridge_id,
                                              _In_ uint32_t            attr_count,
                                              _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = bridge_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    bridge_key_to_str(bridge_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_BRIDGE,
                              bridge_vendor_attribs,
                              attr_count,
                              attr_list);
}

/**
 * @brief Bridge port type
 *
 * @type sai_bridge_port_type_t
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 */
static sai_status_t mlnx_bridge_port_type_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    value->s32 = port->port_type;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Associated Port or Lag object id
 *
 * @type sai_object_id_t
 * @objects SAI_OBJECT_TYPE_PORT, SAI_OBJECT_TYPE_LAG
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 * @condition SAI_BRIDGE_PORT_ATTR_TYPE == SAI_BRIDGE_PORT_TYPE_PORT or SAI_BRIDGE_PORT_ATTR_TYPE == SAI_BRIDGE_PORT_TYPE_SUB_PORT
 */
static sai_status_t mlnx_bridge_port_lag_or_port_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sx_port_log_id_t    log_port;
    sai_status_t        status;
    mlnx_bridge_port_t *port;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 " \n", key->key.object_id);
        goto out;
    }

    if (port->port_type == SAI_BRIDGE_PORT_TYPE_PORT) {
        log_port = port->logical;
    } else if (port->port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        log_port = port->parent;
    } else {
        SX_LOG_ERR("Invalid port type - %d\n", port->port_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_log_port_to_object(log_port, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert log port %x to port oid\n", port->logical);
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Associated Vlan
 *
 * @type sai_uint16_t
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 * @condition SAI_BRIDGE_PORT_ATTR_TYPE == SAI_BRIDGE_PORT_TYPE_SUB_PORT
 * @isvlan true
 */
static sai_status_t mlnx_bridge_port_vlan_id_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (port->port_type != SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        SX_LOG_ERR("Invalid bridge port type %d, must be SAI_BRIDGE_PORT_TYPE_SUB_PORT\n", port->port_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    value->u16 = port->vlan_id;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Associated router inerface object id
 * Please note that for SAI_BRIDGE_PORT_TYPE_1Q_ROUTER,
 * all vlan interfaces are auto bounded for the bridge port.
 *
 * @type sai_object_id_t
 * @objects SAI_OBJECT_TYPE_ROUTER_INTERFACE
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 * @condition SAI_BRIDGE_PORT_ATTR_TYPE == SAI_BRIDGE_PORT_TYPE_1D_ROUTER
 */
static sai_status_t mlnx_bridge_port_rif_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    mlnx_bridge_rif_t  *bridge_rif;
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (port->port_type != SAI_BRIDGE_PORT_TYPE_1D_ROUTER) {
        SX_LOG_ERR("Invalid bridge port type %d, SAI_BRIDGE_PORT_TYPE_1D_ROUTER is only supported\n",
                   port->port_type);

        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_bridge_rif_by_idx(port->rif_index, &bridge_rif);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge rif by index %u\n", port->rif_index);
        goto out;
    }

    status = mlnx_bridge_rif_to_oid(bridge_rif, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert rif to oid\n");
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Associated tunnel id
 *
 * @type sai_object_id_t
 * @objects SAI_OBJECT_TYPE_TUNNEL
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
 * @condition SAI_BRIDGE_PORT_ATTR_TYPE == SAI_BRIDGE_PORT_TYPE_TUNNEL
 */
static sai_status_t mlnx_bridge_port_tunnel_id_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (port->port_type != SAI_BRIDGE_PORT_TYPE_TUNNEL) {
        SX_LOG_ERR("Invalid bridge port type %d, SAI_BRIDGE_PORT_TYPE_TUNNEL is only supported\n",
                   port->port_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, port->tunnel_id, NULL, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Associated bridge id
 *
 * @type sai_object_id_t
 * @objects SAI_OBJECT_TYPE_BRIDGE
 * @flags CREATE_AND_SET
 * @default SAI_NULL_OBJECT_ID
 * @allownull true
 */
static sai_status_t mlnx_bridge_port_bridge_id_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    sai_bridge_type_t   br_type;
    sai_status_t        status;
    mlnx_bridge_port_t *port;

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port object by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    /* Just a trick as we do not allow to create .1Q bridge */
    if (port->bridge_id == mlnx_bridge_default_1q()) {
        br_type = SAI_BRIDGE_TYPE_1Q;
    } else {
        br_type = SAI_BRIDGE_TYPE_1D;
    }

    status = mlnx_create_bridge_object(br_type, port->bridge_id, &value->oid);

out:
    sai_db_unlock();
    return status;
}

/**
 * @brief Associated bridge id
 *
 * @type sai_object_id_t
 * @objects SAI_OBJECT_TYPE_BRIDGE
 * @flags CREATE_AND_SET
 * @default SAI_NULL_OBJECT_ID
 * @allownull true
 */
static sai_status_t mlnx_bridge_port_bridge_id_set(_In_ const sai_object_key_t      *key,
                                                   _In_ const sai_attribute_value_t *value,
                                                   void                             *arg)
{
    mlnx_object_id_t    mlnx_bridge_id = {0};
    sx_bridge_id_t      sx_bridge_id;
    sx_status_t         sx_status;
    sai_bridge_type_t   br_type;
    sai_status_t        status;
    mlnx_bridge_port_t *port;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, value->oid, &mlnx_bridge_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge oid %" PRIx64 " to sx bridge id\n", value->oid);
        return status;
    }
    sx_bridge_id = mlnx_bridge_id.id.bridge_id;
    br_type      = mlnx_bridge_id.ext.bridge.type;

    if (br_type != SAI_BRIDGE_TYPE_1D) {
        SX_LOG_ERR("Only .1D bridge is supported\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port object by oid %" PRIx64 "\n", key->key.object_id);
        goto out;
    }

    if (port->port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        /* Vport admin state needs to be down before deleting from a bridge */
        if (port->admin_state) {
            sx_status = sx_api_port_state_set(gh_sdk, port->logical, SX_PORT_ADMIN_STATUS_DOWN);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set vport %x admin state down - %s.\n", port->logical, SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        }

        sx_status = sx_api_bridge_vport_set(gh_sdk, SX_ACCESS_CMD_DELETE, port->bridge_id, port->logical);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to del vport %x from bridge %x - %s\n", port->logical, port->bridge_id,
                       SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_bridge_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, sx_bridge_id, port->logical);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add vport %x to bridge %x - %s\n", port->logical, sx_bridge_id,
                       SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        if (port->admin_state) {
            sx_status = sx_api_port_state_set(gh_sdk, port->logical, SX_PORT_ADMIN_STATUS_UP);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set vport %x admin state up - %s.\n", port->logical, SX_STATUS_MSG(sx_status));
                status = sdk_to_sai(sx_status);
                goto out;
            }
        }
    } else if (port->port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER) {
        mlnx_bridge_rif_t *br_rif;

        status = mlnx_bridge_rif_by_idx(port->rif_index, &br_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif by index %u\n", port->rif_index);
            goto out;
        }

        br_rif->intf_params.ifc.bridge.bridge = sx_bridge_id;

        sx_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_EDIT, br_rif->vrf_id,
                                                &br_rif->intf_params, &br_rif->intf_attribs, &br_rif->rif_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(sx_status));
            /* Reset to the old bridge id which is stored also in mlnx_bridge_port_t */
            br_rif->intf_params.ifc.bridge.bridge = port->bridge_id;
            status                                = sdk_to_sai(sx_status);
            goto out;
        }
    } else {
        SX_LOG_ERR("Bridge port set is only supported for sub-port or .1D router port type\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    port->bridge_id = sx_bridge_id;

out:
    sai_db_unlock();
    return status;
}

/**
 * @brief FDB Learning mode
 *
 * @type sai_bridge_port_fdb_learning_mode_t
 * @flags CREATE_AND_SET
 * @default SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW
 */
static sai_status_t mlnx_bridge_port_fdb_learning_mode_get(_In_ const sai_object_key_t   *key,
                                                           _Inout_ sai_attribute_value_t *value,
                                                           _In_ uint32_t                  attr_index,
                                                           _Inout_ vendor_cache_t        *cache,
                                                           void                          *arg)
{
    sx_fdb_learn_mode_t learn_mode;
    sx_port_log_id_t    log_port;
    sx_status_t         sx_status;
    sai_status_t        status;

    SX_LOG_ENTER();

    status = mlnx_bridge_port_sai_to_log_port(key->key.object_id, &log_port);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_fdb_port_learn_mode_get(gh_sdk, log_port, &learn_mode);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get port learning mode - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_FDB_LEARN_MODE_DONT_LEARN == learn_mode) {
        value->s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE;
    } else if (SX_FDB_LEARN_MODE_CONTROL_LEARN == learn_mode) {
        value->s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_CPU_LOG;
    } else {
        value->s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief FDB Learning mode
 *
 * @type sai_bridge_port_fdb_learning_mode_t
 * @flags CREATE_AND_SET
 * @default SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW
 */
static sai_status_t mlnx_bridge_port_fdb_learning_mode_set(_In_ const sai_object_key_t      *key,
                                                           _In_ const sai_attribute_value_t *value,
                                                           void                             *arg)
{
    sx_fdb_learn_mode_t learn_mode;
    sx_port_log_id_t    port_id;
    sx_status_t         sx_status;
    sai_status_t        status;

    SX_LOG_ENTER();

    status = mlnx_bridge_port_sai_to_log_port(key->key.object_id, &port_id);
    if (SAI_ERR(status)) {
        return status;
    }

    switch (value->s32) {
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE:
        learn_mode = SX_FDB_LEARN_MODE_DONT_LEARN;
        break;

    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW:
        learn_mode = SX_FDB_LEARN_MODE_AUTO_LEARN;
        break;

    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_CPU_LOG:
        learn_mode = SX_FDB_LEARN_MODE_CONTROL_LEARN;
        break;

    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DROP:
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_CPU_TRAP:
        return SAI_STATUS_NOT_IMPLEMENTED;

    default:
        SX_LOG_ERR("Invalid port fdb learning mode %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id, learn_mode);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port learning mode - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Maximum number of learned MAC addresses
 *
 * @type sai_uint32_t
 * @flags CREATE_AND_SET
 * @default 0
 */
static sai_status_t mlnx_bridge_port_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                               _Inout_ sai_attribute_value_t *value,
                                                               _In_ uint32_t                  attr_index,
                                                               _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sx_status_t      sx_status;
    sx_port_log_id_t sx_log_port_id;
    uint32_t         sx_limit = 0;

    SX_LOG_ENTER();

    status = mlnx_bridge_port_sai_to_log_port(key->key.object_id, &sx_log_port_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_fdb_uc_limit_port_get(gh_sdk, sx_log_port_id, &sx_limit);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get FDB learning limit for port %x - %s\n", sx_log_port_id, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(status);
        goto out;
    }

    value->u32 = MLNX_FDB_LIMIT_SX_TO_SAI(sx_limit);

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_port_max_learned_addresses_set(_In_ sx_port_log_id_t sx_port,
                                                        _In_ uint32_t         limit)
{
    sx_status_t sx_status;
    uint32_t    sx_limit;

    sx_limit = MLNX_FDB_LIMIT_SAI_TO_SX(limit);

    sx_status = sx_api_fdb_uc_limit_port_set(gh_sdk, SX_ACCESS_CMD_SET, sx_port, sx_limit);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set FDB learning limit for port %x - %s\n", sx_port, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Maximum number of learned MAC addresses
 *
 * @type sai_uint32_t
 * @flags CREATE_AND_SET
 * @default 0
 */
static sai_status_t mlnx_bridge_port_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                               _In_ const sai_attribute_value_t *value,
                                                               void                             *arg)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sx_port_log_id_t sx_log_port_id;

    SX_LOG_ENTER();

    status = mlnx_bridge_port_sai_to_log_port(key->key.object_id, &sx_log_port_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_max_learned_addresses_value_validate(value->u32, 0);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_port_max_learned_addresses_set(sx_log_port_id, value->u32);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Admin Mode.
 *
 * Before removing a bridge port, need to disable it by setting admin mode
 * to false, then flush the FDB entries, and then remove it.
 *
 * @type bool
 * @flags CREATE_AND_SET
 * @default false
 */
static sai_status_t mlnx_bridge_port_admin_state_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    mlnx_bridge_port_t *port;
    sai_status_t        status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->booldata = port->admin_state;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_bridge_port_admin_state_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bridge_port;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_bridge_port_by_oid(key->key.object_id, &bridge_port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_bridge_port_admin_state_set_internal(bridge_port, value->booldata);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * SAI DB should be loocked
 */
static sai_status_t mlnx_bridge_port_admin_state_set_internal(_In_ mlnx_bridge_port_t *bridge_port, _In_ bool value)
{
    sai_status_t        status;
    sx_status_t         sx_status;
    sx_port_log_id_t    sx_port_id;
    mlnx_port_config_t *port_config;
    bool                sdk_state;

    assert(bridge_port);

    bridge_port->admin_state = value;

    if ((bridge_port->port_type == SAI_BRIDGE_PORT_TYPE_PORT) ||
        (bridge_port->port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT)) {
        sx_port_id = bridge_port->logical;
        sdk_state  = value;

        /* Try to lookup phy port by same logical id as bridge port, which means that
         * port is bridged with SAI_BRIDGE_PORT_TYPE_PORT via .1Q bridge, if it is bridged then
         * we set a "real" admin state only in case the both ports are set in 'true'. */
        status = mlnx_port_by_log_id_soft(sx_port_id, &port_config);
        if (!SAI_ERR(status)) {
            sdk_state = port_config->admin_state && bridge_port->admin_state;
        }

        sx_status = sx_api_port_state_set(gh_sdk,
                                          sx_port_id,
                                          sdk_state ? SX_PORT_ADMIN_STATUS_UP : SX_PORT_ADMIN_STATUS_DOWN);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port admin state - %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static void bridge_port_key_to_str(_In_ sai_object_id_t bridge_port_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_bridge_port = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_id, &mlnx_bridge_port);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge port");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "bridge port idx %x", mlnx_bridge_port.id.u32);
    }
}

/**
 * @brief Create bridge port
 *
 * @param[out] bridge_port_id Bridge port ID
 * @param[in] switch_id Switch object id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_bridge_port(_Out_ sai_object_id_t     * bridge_port_id,
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status = SAI_STATUS_NOT_IMPLEMENTED;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    mlnx_object_id_t             mlnx_bridge_id = {0};
    mlnx_object_id_t             mlnx_obj_id    = {0};
    mlnx_bridge_port_t          *bridge_port    = NULL;
    mlnx_bridge_rif_t           *bridge_rif;
    sx_bridge_id_t               bridge_id;
    sx_status_t                  sx_status;
    sx_port_log_id_t             log_port;
    sx_port_log_id_t             vport_id = 0;
    sx_vlan_id_t                 vlan_id  = 0;
    sx_vlan_ports_t              vlan_port_list;
    const uint32_t               vlan_port_cnt = 1;
    const sai_attribute_value_t *attr_val, *max_learned_addresses = NULL;
    uint32_t                     attr_idx, max_learned_addresses_index;
    bool                         admin_state;

    SX_LOG_ENTER();

    if (NULL == bridge_port_id) {
        SX_LOG_ERR("NULL bridge port ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    status = check_attrs_port_type(NULL, attr_count, attr_list);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attrs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_BRIDGE_PORT, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create bridge port, %s\n", list_str);

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, &attr_val, &attr_idx);
    if (!SAI_ERR(status)) {
        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, attr_val->oid, &mlnx_bridge_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed parse bridge id %" PRIx64 "\n", attr_val->oid);
            goto out;
        }

        bridge_id = mlnx_bridge_id.id.bridge_id;
    } else {
        bridge_id = mlnx_bridge_default_1q();
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES,
                                 &max_learned_addresses, &max_learned_addresses_index);
    if (!SAI_ERR(status)) {
        status = mlnx_max_learned_addresses_value_validate(max_learned_addresses->u32, max_learned_addresses_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_TYPE, &attr_val, &attr_idx);
    assert(!SAI_ERR(status));

    if (max_learned_addresses &&
            ((attr_val->s32 != SAI_BRIDGE_PORT_TYPE_PORT) && (attr_val->s32 != SAI_BRIDGE_PORT_TYPE_SUB_PORT))) {
        SX_LOG_ERR("The SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES is only supported for PORT and SUB_PORT\n");
        status = SAI_STATUS_ATTR_NOT_SUPPORTED_0 + max_learned_addresses_index;
        goto out;
    }

    status = mlnx_bridge_port_add(bridge_id, attr_val->s32, &bridge_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to allocate bridge port entry\n");
        goto out;
    }

    switch (attr_val->s32) {
    case SAI_BRIDGE_PORT_TYPE_PORT:
        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_PORT_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_PORT_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        status = mlnx_object_to_log_port(attr_val->oid, &log_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert port oid %" PRIx64 " to log port\n", attr_val->oid);
            goto out;
        }

        if (mlnx_log_port_is_cpu(log_port)) {
            SX_LOG_ERR("Invalid port id - CPU port\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
            goto out;
        }

        if (mlnx_bridge_port_in_1q_by_log(log_port)) {
            SX_LOG_ERR("Port is already in .1Q bridge\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        bridge_port->logical = log_port;
        break;

    case SAI_BRIDGE_PORT_TYPE_SUB_PORT:
        if (bridge_id == mlnx_bridge_default_1q()) {
            SX_LOG_ERR("Bridge sub-port requires .1D bridge port\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_PORT_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_PORT_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        status = mlnx_object_to_log_port(attr_val->oid, &log_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert port oid %" PRIx64 " to log port\n", attr_val->oid);
            goto out;
        }

        if (mlnx_bridge_port_in_1q_by_log(log_port)) {
            SX_LOG_ERR("Port is already in .1Q bridge\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        if (mlnx_log_port_is_cpu(log_port)) {
            SX_LOG_ERR("Invalid port id - CPU port\n");
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
            goto out;
        }

        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_VLAN_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_VLAN_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }
        vlan_id = attr_val->u16;

        memset(&vlan_port_list, 0, sizeof(vlan_port_list));

        vlan_port_list.log_port = log_port;
        vlan_port_list.is_untagged = SX_TAGGED_MEMBER;

        sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vlan_id, &vlan_port_list, vlan_port_cnt);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add port to vlan - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_port_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, log_port, vlan_id, &vport_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create vport - %s\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_bridge_vport_set(gh_sdk, SX_ACCESS_CMD_ADD, bridge_id, vport_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add vport %x to bridge %x - %s\n", vport_id, bridge_id, SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        bridge_port->logical = vport_id;
        bridge_port->parent  = log_port;
        bridge_port->vlan_id = vlan_id;
        break;

    case SAI_BRIDGE_PORT_TYPE_TUNNEL:
        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_TUNNEL_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_TUNNEL_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_TUNNEL, attr_val->oid, &mlnx_obj_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert oid to mlnx object id\n");
            goto out;
        }

        bridge_port->tunnel_id = mlnx_obj_id.id.u32;
        break;

    case SAI_BRIDGE_PORT_TYPE_1D_ROUTER:
        if (bridge_id == mlnx_bridge_default_1q()) {
            SX_LOG_ERR("Bridge port .1D router requires .1D bridge\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_RIF_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_RIF_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ROUTER_INTERFACE, attr_val->oid, &mlnx_obj_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert oid to mlnx object id\n");
            goto out;
        }

        if (mlnx_obj_id.field.sub_type != MLNX_RIF_TYPE_BRIDGE) {
            SX_LOG_ERR("Invalid rif type - only router interface type bridge is supported\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        bridge_port->rif_index = mlnx_obj_id.id.u32;

        status = mlnx_bridge_rif_by_idx(bridge_port->rif_index, &bridge_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif by index %u\n", bridge_port->rif_index);
            goto out;
        }

        bridge_rif->intf_params.ifc.bridge.swid = DEFAULT_ETH_SWID;
        bridge_rif->intf_params.ifc.bridge.bridge = bridge_id;

        sx_status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_ADD, bridge_rif->vrf_id,
                                                &bridge_rif->intf_params, &bridge_rif->intf_attribs,
                                                &bridge_rif->rif_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set bridge router interface - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_router_interface_state_set(gh_sdk, bridge_rif->rif_id, &bridge_rif->intf_state);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set bridge router interface state - %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        bridge_rif->is_created = true;
        break;

    default:
        SX_LOG_ERR("Unsupported bridge port type %d\n", attr_val->s32);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_ADMIN_STATE, &attr_val, &attr_idx);
    if (SAI_ERR(status)) {
        admin_state = false;
    } else {
        admin_state = attr_val->booldata;
    }

    if (max_learned_addresses) {
        status = mlnx_port_max_learned_addresses_set(bridge_port->logical, max_learned_addresses->u32);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_bridge_port_admin_state_set_internal(bridge_port, admin_state);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_bridge_port_to_oid(bridge_port, bridge_port_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge port to oid\n");
        goto out;
    }

    bridge_port_key_to_str(*bridge_port_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

out:
    /* rollback */
    if (SAI_ERR(status)) {
        if (bridge_port) {
            mlnx_bridge_port_del(bridge_port);
        }
        if (vport_id) {
            sx_api_port_vport_set(gh_sdk, SX_ACCESS_CMD_DELETE, log_port, vlan_id, &vport_id);
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static bool mlnx_bridge_port_in_use_check(mlnx_bridge_port_t *port)
{
    if (port->vlans) {
        SX_LOG_ERR("Failed remove bridge port - is used by VLAN members (%u)\n", port->vlans);
        return SAI_STATUS_OBJECT_IN_USE;
    }
    if (port->fdbs) {
        SX_LOG_ERR("Failed remove bridge port - is used by FDB actions (%u)\n", port->fdbs);
        return SAI_STATUS_OBJECT_IN_USE;
    }
    if (port->stps) {
        SX_LOG_ERR("Failed remove bridge port - is used by STP ports (%u)\n", port->stps);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove bridge port
 *
 * @param[in] bridge_port_id Bridge port ID
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_bridge_port(_In_ sai_object_id_t bridge_port_id)
{
    char                key_str[MAX_KEY_STR_LEN];
    sx_status_t         sx_status;
    sai_status_t        status;
    mlnx_bridge_rif_t  *bridge_rif;
    mlnx_bridge_port_t *port;

    SX_LOG_ENTER();

    bridge_port_key_to_str(bridge_port_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    sai_db_write_lock();

    status = mlnx_bridge_port_by_oid(bridge_port_id, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port\n");
        goto out;
    }

    status = mlnx_bridge_port_in_use_check(port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Bridge port is in use\n");
        goto out;
    }

    switch (port->port_type) {
    case SAI_BRIDGE_PORT_TYPE_SUB_PORT:
        sx_status = sx_api_bridge_vport_set(gh_sdk, SX_ACCESS_CMD_DELETE, port->bridge_id, port->logical);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to del vport %x from bridge %x - %s\n", port->logical, port->bridge_id,
                       SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        status = mlnx_bridge_sx_vport_delete(port->parent, port->vlan_id, port->logical);
        if (SAI_ERR(status)) {
            goto out;
        }
        break;

    case SAI_BRIDGE_PORT_TYPE_1D_ROUTER:
        status = mlnx_bridge_rif_by_idx(port->rif_index, &bridge_rif);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge rif by index %u\n", port->rif_index);
            goto out;
        }

        status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, bridge_rif->vrf_id,
                                             &bridge_rif->intf_params, &bridge_rif->intf_attribs,
                                             &bridge_rif->rif_id);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to remove bridge router interface - %s.\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        bridge_rif->intf_params.ifc.bridge.bridge = SX_BRIDGE_ID_INVALID;
        bridge_rif->is_created                    = false;
        bridge_rif->rif_id                        = 0;
        break;

    default:
        break;
    }

    status = mlnx_bridge_port_del(port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove bridge port\n");
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set attribute for bridge port
 *
 * @param[in] bridge_port_id Bridge port ID
 * @param[in] attr attribute to set
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_bridge_port_attribute(_In_ sai_object_id_t        bridge_port_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = bridge_port_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    bridge_port_key_to_str(bridge_port_id, key_str);

    status = check_attrs_port_type(&key, 1, attr);
    if (SAI_ERR(status)) {
        return status;
    }

    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_vendor_attribs, attr);
}

/**
 * @brief Get attributes of bridge port
 *
 * @param[in] bridge_port_id Bridge port ID
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_bridge_port_attribute(_In_ sai_object_id_t     bridge_port_id,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = bridge_port_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    bridge_port_key_to_str(bridge_port_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_vendor_attribs,
                              attr_count, attr_list);
}

sai_status_t mlnx_bridge_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_bridge_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

sai_status_t mlnx_bridge_init(void)
{
    mlnx_bridge_port_t *router_port;
    sx_bridge_id_t      bridge_id;
    mlnx_port_config_t *port;
    sx_status_t         sx_status;
    sai_status_t        status;
    uint32_t            ii;

    sai_db_write_lock();

    sx_status = sx_api_bridge_set(gh_sdk, SX_ACCESS_CMD_CREATE, &bridge_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create default .1Q bridge - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    mlnx_port_phy_foreach(port, ii) {
        mlnx_bridge_port_t *bridge_port;

        status = mlnx_bridge_port_add(bridge_id, SAI_BRIDGE_PORT_TYPE_PORT, &bridge_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to add port %x to default bridge\n", port->logical);
            goto out;
        }

        bridge_port->logical     = port->logical;
        bridge_port->admin_state = true;

        status = mlnx_vlan_port_add(DEFAULT_VLAN, SAI_VLAN_TAGGING_MODE_UNTAGGED, bridge_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to add bridge port to default vlan\n");
            goto out;
        }
    }

    status = mlnx_bridge_port_add(bridge_id, SAI_BRIDGE_PORT_TYPE_1Q_ROUTER, &router_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create router .1Q bridge port\n");
        goto out;
    }
    router_port->admin_state = true;

    g_sai_db_ptr->sx_bridge_id = bridge_id;

out:
    sai_db_unlock();
    return status;
}

const sai_bridge_api_t mlnx_bridge_api = {
    mlnx_create_bridge,
    mlnx_remove_bridge,
    mlnx_set_bridge_attribute,
    mlnx_get_bridge_attribute,
    mlnx_create_bridge_port,
    mlnx_remove_bridge_port,
    mlnx_set_bridge_port_attribute,
    mlnx_get_bridge_port_attribute,
};
