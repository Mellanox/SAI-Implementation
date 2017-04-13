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
static const sai_attribute_entry_t        bridge_attribs[] = {
    { SAI_BRIDGE_ATTR_TYPE, true, true, false, true,
      "Bridge type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_BRIDGE_ATTR_PORT_LIST, false, false, false, true,
      "Bridge port list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES, false, true, true, true,
      "Bridge max learned addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_BRIDGE_ATTR_LEARN_DISABLE, false, true, true, true,
      "Bridge learn disable", SAI_ATTR_VAL_TYPE_BOOL },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
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
      mlnx_bridge_learn_disable_set, NULL }
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
static const sai_attribute_entry_t        bridge_port_attribs[] = {
    { SAI_BRIDGE_PORT_ATTR_TYPE, true, true, false, true,
      "Bridge port type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_BRIDGE_PORT_ATTR_PORT_ID, false, true, false, true,
      "Bridge port or lag", SAI_ATTR_VAL_TYPE_OID },
    { SAI_BRIDGE_PORT_ATTR_VLAN_ID, false, true, false, true,
      "Bridge port vlan id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_BRIDGE_PORT_ATTR_RIF_ID, false, true, false, true,
      "Bridge port rif id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_BRIDGE_PORT_ATTR_TUNNEL_ID, false, true, false, true,
      "Bridge port tunnel id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, false, true, true, true,
      "Bridge port bridge id", SAI_ATTR_VAL_TYPE_OID },
    { SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, false, true, true, true,
      "Bridge port fdb learning mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES, false, true, true, true,
      "Bridge port fdb max learned addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION, false, true, true, true,
      "Bridge port fdb learning limit action", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
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
      { true, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION,
      { true, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL },
};
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
    return port->bridge_id != SX_BRIDGE_ID_INVALID;
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

sai_status_t mlnx_bridge_port_sai_to_log_port(sai_object_id_t oid, sx_port_log_id_t *log_port)
{
    mlnx_object_id_t mlnx_port_id = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, oid, &mlnx_port_id);
    if (SAI_ERR(status)) {
        return status;
    }

    *log_port = mlnx_port_id.id.log_port_id;
    return status;
}

/* DB read lock is required */
sai_status_t mlnx_bridge_port_sai_to_port(sai_object_id_t bridge_port_id, sai_object_id_t *port_id)
{
    sx_port_log_id_t    log_port;
    sai_status_t        status;
    mlnx_port_config_t *port;

    status = mlnx_bridge_port_sai_to_log_port(bridge_port_id, &log_port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_port_by_log_id(log_port, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!mlnx_port_is_in_bridge(port)) {
        SX_LOG_ERR("Invalid bridge port %" PRIx64 "\n", bridge_port_id);
        return SAI_STATUS_INVALID_PORT_NUMBER;
    }

    return mlnx_log_port_to_object(log_port, port_id);
}

sai_status_t mlnx_log_port_to_sai_bridge_port(sx_port_log_id_t log_port, sai_object_id_t *oid)
{
    mlnx_object_id_t mlnx_port_id = {0};
    sai_status_t     status;

    mlnx_port_id.id.log_port_id       = log_port;
    mlnx_port_id.ext.bridge_port.type = SAI_BRIDGE_PORT_TYPE_PORT;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_BRIDGE_PORT, &mlnx_port_id, oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed convert log port %x to bridge port\n", log_port);
        return status;
    }

    return status;
}

sai_status_t mlnx_tunnel_idx_to_sai_bridge_port(uint32_t tunnel_idx, sai_object_id_t *oid)
{
    mlnx_object_id_t mlnx_port_id = {0};
    sai_status_t     status;

    mlnx_port_id.id.u32               = tunnel_idx;
    mlnx_port_id.ext.bridge_port.type = SAI_BRIDGE_PORT_TYPE_TUNNEL;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_BRIDGE_PORT, &mlnx_port_id, oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed convert tunnel idx %d to bridge port\n", tunnel_idx);
        return status;
    }

    return status;
}

sai_status_t mlnx_bridge_phy_port_add(sx_bridge_id_t bridge_id, mlnx_port_config_t *port)
{
    sai_status_t status;

    if (mlnx_port_is_in_bridge(port)) {
        SX_LOG_ERR("Port is already under bridge\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_vlan_port_add(DEFAULT_VLAN, SAI_VLAN_TAGGING_MODE_UNTAGGED, port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add bridge port %" PRIx64 "to default vlan\n", port->saiport);
        return status;
    }

    port->bridge_id = bridge_id;

    return status;
}

sai_status_t mlnx_bridge_phy_port_del(mlnx_port_config_t *port)
{
    sai_status_t status;

    status = mlnx_vlan_port_del(DEFAULT_VLAN, port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove port from the default vlan %u\n", DEFAULT_VLAN);
    }

    port->bridge_id = SX_BRIDGE_ID_INVALID;

    return status;
}

sai_status_t mlnx_bridge_tunnel_port_add(sx_bridge_id_t bridge_id, uint32_t tunnel_idx)
{
    tunnel_db_entry_t *tun;

    tun = &g_sai_db_ptr->tunnel_db[tunnel_idx];
    if (tun->bridge_id != SX_BRIDGE_ID_INVALID) {
        SX_LOG_ERR("Tunnel is already under bridge\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO: Probably here must be a logic which created mapper for the VXLAN */
    tun->bridge_id = bridge_id;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bridge_tunnel_port_del(uint32_t tunnel_idx)
{
    tunnel_db_entry_t *tun;

    tun = &g_sai_db_ptr->tunnel_db[tunnel_idx];
    if (tun->bridge_id == SX_BRIDGE_ID_INVALID) {
        SX_LOG_ERR("Tunnel is not under bridge\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    tun->bridge_id = SX_BRIDGE_ID_INVALID;

    return SAI_STATUS_SUCCESS;
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
    mlnx_object_id_t    mlnx_router_bport_id = {0};
    mlnx_object_id_t    mlnx_bridge_id       = {0};
    uint32_t            ii, jj = 0;
    sai_status_t        status;
    sai_object_id_t    *ports = NULL;
    uint32_t            count = 0;
    mlnx_port_config_t *port;
    tunnel_db_entry_t  *tun;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, key->key.object_id, &mlnx_bridge_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    mlnx_port_not_in_lag_foreach(port, ii) {
        if (port->bridge_id != mlnx_bridge_id.id.bridge_id) {
            continue;
        }

        count++;
    }
    mlnx_vxlan_exist_foreach(tun, ii) {
        if (tun->bridge_id != mlnx_bridge_id.id.bridge_id) {
            continue;
        }

        count++;
    }

    /* +1 for SAI_BRIDGE_PORT_TYPE_1Q_ROUTER */
    count++;
    ports = calloc(count, sizeof(*ports));

    mlnx_port_not_in_lag_foreach(port, ii) {
        if (port->bridge_id != mlnx_bridge_id.id.bridge_id) {
            continue;
        }

        status = mlnx_log_port_to_sai_bridge_port(port->logical, &ports[jj++]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }
    mlnx_vxlan_exist_foreach(tun, ii) {
        if (tun->bridge_id != mlnx_bridge_id.id.bridge_id) {
            continue;
        }

        status = mlnx_tunnel_idx_to_sai_bridge_port(ii, &ports[jj++]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    mlnx_router_bport_id.ext.bridge_port.type = SAI_BRIDGE_PORT_TYPE_1Q_ROUTER;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_BRIDGE_PORT, &mlnx_router_bport_id, &ports[jj++]);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create router bridge port oid\n");
        goto out;
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
    SX_LOG_ENTER();
    value->u32 = 0;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static void bridge_key_to_str(_In_ sai_object_id_t bridge_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_bridge = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE, bridge_id, &mlnx_bridge);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "bridge %u", mlnx_bridge.id.bridge_id);
    }
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
    return sai_set_attribute(&key, key_str, bridge_attribs, bridge_vendor_attribs, attr);
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
                              bridge_attribs,
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
    mlnx_object_id_t mlnx_port_id = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, key->key.object_id, &mlnx_port_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed convert sai bridge port to mlnx id\n");
        goto out;
    }

    value->s32 = mlnx_port_id.ext.bridge_port.type;

out:
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
    mlnx_object_id_t mlnx_bport_id = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, key->key.object_id, &mlnx_bport_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert oid to object id\n");
        return status;
    }

    if (mlnx_bport_id.ext.bridge_port.type != SAI_BRIDGE_PORT_TYPE_PORT) {
        SX_LOG_ERR("Invalid bridge port type %d, SAI_BRIDGE_PORT_TYPE_PORT is only supported\n",
                   mlnx_bport_id.ext.bridge_port.type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_log_port_to_object(mlnx_bport_id.id.log_port_id, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert log port %x to port oid\n", mlnx_bport_id.id.log_port_id);
    }

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
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    mlnx_object_id_t mlnx_bport_id = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, key->key.object_id, &mlnx_bport_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert oid to object id\n");
        return status;
    }

    if (mlnx_bport_id.ext.bridge_port.type != SAI_BRIDGE_PORT_TYPE_TUNNEL) {
        SX_LOG_ERR("Invalid bridge port type %d, SAI_BRIDGE_PORT_TYPE_TUNNEL is only supported\n",
                   mlnx_bport_id.ext.bridge_port.type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, mlnx_bport_id.id.u32, NULL, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

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
    mlnx_object_id_t    mlnx_id = {0};
    sai_status_t        status;
    mlnx_port_config_t *port;

    sai_db_read_lock();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, key->key.object_id, &mlnx_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_port_by_log_id(mlnx_id.id.log_port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!mlnx_port_is_in_bridge(port)) {
        SX_LOG_ERR("Invalid bridge port bridge id\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_create_bridge_object(SAI_BRIDGE_TYPE_1Q, port->bridge_id, &value->oid);

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
    return SAI_STATUS_NOT_IMPLEMENTED;
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

static void bridge_port_key_to_str(_In_ sai_object_id_t bridge_port_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_bridge_port = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_id, &mlnx_bridge_port);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge port");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "bridge port %x", mlnx_bridge_port.id.u32);
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
    mlnx_object_id_t             mlnx_port_id   = {0};
    sx_bridge_id_t               bridge_id;
    const sai_attribute_value_t *attr_val;
    uint32_t                     attr_idx;
    sx_port_log_id_t             log_port;
    mlnx_port_config_t          *port;

    SX_LOG_ENTER();

    if (NULL == bridge_port_id) {
        SX_LOG_ERR("NULL bridge port ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, bridge_port_attribs, bridge_port_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    status = check_attrs_port_type(NULL, attr_count, attr_list);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, bridge_port_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
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
        bridge_id = g_sai_db_ptr->sx_bridge_id;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_TYPE, &attr_val, &attr_idx);
    assert(!SAI_ERR(status));

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

        status = mlnx_port_by_log_id(log_port, &port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_bridge_phy_port_add(bridge_id, port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed add bridge port to bridge %x\n", bridge_id);
            goto out;
        }

        status = mlnx_log_port_to_sai_bridge_port(port->logical, bridge_port_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert log port %x to bridge port\n", port->logical);
            goto out;
        }
        break;

    case SAI_BRIDGE_PORT_TYPE_TUNNEL:
        status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_PORT_ATTR_TUNNEL_ID, &attr_val, &attr_idx);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing mandatory SAI_BRIDGE_PORT_ATTR_TUNNEL_ID attr\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_TUNNEL, attr_val->oid, &mlnx_port_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert oid to mlnx object id\n");
            goto out;
        }

        status = mlnx_bridge_tunnel_port_add(bridge_id, mlnx_port_id.id.u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed add tunnel %d to bridge %x\n", mlnx_port_id.id.u32,  bridge_id);
            goto out;
        }

        status = mlnx_tunnel_idx_to_sai_bridge_port(mlnx_port_id.id.u32, bridge_port_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert tunnel idx %d to bridge port oid\n", mlnx_port_id.id.u32);
            goto out;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported bridge port type %d\n", attr_val->s32);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_idx;
        goto out;
    }

    bridge_port_key_to_str(*bridge_port_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static bool mlnx_bridge_port_in_use_check(mlnx_port_config_t *port)
{
    if (port->vlans) {
        SX_LOG_ERR("Failed remove bridge port oid %" PRIx64 " - is a VLAN member\n", port->saiport);
        return SAI_STATUS_OBJECT_IN_USE;
    }
    if (port->fdbs) {
        SX_LOG_ERR("Failed remove bridge port oid %" PRIx64 " - is in FDB action\n", port->saiport);
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
    mlnx_object_id_t    mlnx_port_id = {0};
    sai_status_t        status;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    bridge_port_key_to_str(bridge_port_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_id, &mlnx_port_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    if (mlnx_port_id.ext.bridge_port.type == SAI_BRIDGE_PORT_TYPE_PORT) {
        status = mlnx_port_by_log_id(mlnx_port_id.id.log_port_id, &port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_bridge_port_in_use_check(port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_bridge_phy_port_del(port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed remove port from the bridge\n");
            goto out;
        }
    } else if (mlnx_port_id.ext.bridge_port.type == SAI_BRIDGE_PORT_TYPE_TUNNEL) {
        status = mlnx_bridge_tunnel_port_del(mlnx_port_id.id.u32);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed remove tunnel from the bridge\n");
        }
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

    return sai_set_attribute(&key, key_str, bridge_port_attribs, bridge_port_vendor_attribs, attr);
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
    return sai_get_attributes(&key, key_str, bridge_port_attribs, bridge_port_vendor_attribs,
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
