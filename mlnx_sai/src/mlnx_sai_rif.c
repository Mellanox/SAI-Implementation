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
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"

#undef  __MODULE__
#define __MODULE__ SAI_RIF

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t rif_attribs[] = {
    { SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, true, true, false, true,
      "Router interface virtual router ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ROUTER_INTERFACE_ATTR_TYPE, true, true, false, true,
      "Router interface type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_ROUTER_INTERFACE_ATTR_PORT_ID, false, true, false, true,
      "Router interface port ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, false, true, false, true,
      "Router interface vlan ID", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, false, true, true, true,
      "Router interface source MAC address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, false, true, true, true,
      "Router interface admin v4 state", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, false, true, true, true,
      "Router interface admin v6 state", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_ROUTER_INTERFACE_ATTR_MTU, false, true, true, true,
      "Router interface mtu", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_ROUTER_INTERFACE_ATTR_NEIGHBOR_MISS_PACKET_ACTION, false, true, true, true,
      "Router interface neighbor miss action", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_rif_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_rif_admin_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg);
static sai_status_t mlnx_rif_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_rif_admin_set(_In_ const sai_object_key_t      *key,
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
    { SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_admin_get, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
      mlnx_rif_admin_set, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE },
    { SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_admin_get, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
      mlnx_rif_admin_set, (void*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE },
    { SAI_ROUTER_INTERFACE_ATTR_MTU,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_rif_attrib_get, (void*)SAI_ROUTER_INTERFACE_ATTR_MTU,
      mlnx_rif_attrib_set, (void*)SAI_ROUTER_INTERFACE_ATTR_MTU },
    { SAI_ROUTER_INTERFACE_ATTR_NEIGHBOR_MISS_PACKET_ACTION,
      { false, false, false, false },
      { true, false, true, true },
      NULL, NULL,
      NULL, NULL }
};
static void rif_key_to_str(_In_ sai_object_id_t rif_id, _Out_ char *key_str)
{
    uint32_t rifid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(rif_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rifid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid rif");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "rif %u", rifid);
    }
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
                                                 _In_ uint32_t               attr_count,
                                                 _In_ const sai_attribute_t *attr_list)
{
    sx_router_interface_param_t  intf_params;
    sx_interface_attributes_t    intf_attribs;
    sai_status_t                 status;
    const sai_attribute_value_t *type, *vrid, *port, *vlan, *mtu, *mac, *adminv4, *adminv6;
    uint32_t                     type_index, vrid_index, port_index, vlan_index, mtu_index, mac_index, adminv4_index,
                                 adminv6_index, vrid_data, port_data;
    sx_router_interface_t       sdk_rif_id = 0;
    sx_router_interface_state_t rif_state;
    char                        list_str[MAX_LIST_VALUE_STR_LEN];
    char                        key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == rif_id) {
        SX_LOG_ERR("NULL rif id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, rif_attribs, rif_vendor_attribs, SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, rif_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create rif, %s\n", list_str);

    memset(&intf_params, 0, sizeof(intf_params));
    memset(&intf_attribs, 0, sizeof(intf_attribs));
    memset(&rif_state, 0, sizeof(rif_state));

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_TYPE, &type, &type_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, &vrid,
                               &vrid_index));
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(vrid->oid, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, &vrid_data, NULL))) {
        return status;
    }

    if (SAI_ROUTER_INTERFACE_TYPE_VLAN == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, &vlan, &vlan_index))) {
            SX_LOG_ERR("Missing mandatory attribute vlan id on create\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_PORT_ID, &port, &port_index))) {
            SX_LOG_ERR("Invalid attribute port id for rif vlan on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }

        intf_params.type          = SX_L2_INTERFACE_TYPE_VLAN;
        intf_params.ifc.vlan.swid = DEFAULT_ETH_SWID;
        intf_params.ifc.vlan.vlan = vlan->u16;
    } else if (SAI_ROUTER_INTERFACE_TYPE_PORT == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_PORT_ID, &port, &port_index))) {
            SX_LOG_ERR("Missing mandatory attribute port id on create\n");
            return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, &vlan, &vlan_index))) {
            SX_LOG_ERR("Invalid attribute vlan id for rif port on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + vlan_index;
        }

        if (SAI_OBJECT_TYPE_PORT == sai_object_type_query(port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_PORT, &port_data, NULL))) {
                return status;
            }
        } else if (SAI_OBJECT_TYPE_LAG == sai_object_type_query(port->oid)) {
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_object_to_type(port->oid, SAI_OBJECT_TYPE_LAG, &port_data, NULL))) {
                return status;
            }
        } else {
            SX_LOG_ERR("Invalid router interface port ID type %s\n", SAI_TYPE_STR(sai_object_type_query(port->oid)));
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + port_index;
        }

        intf_params.type               = SX_L2_INTERFACE_TYPE_PORT_VLAN;
        intf_params.ifc.port_vlan.port = port_data;
        intf_params.ifc.port_vlan.vlan = 0;
    } else {
        SX_LOG_ERR("Invalid router interface type %d\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_MTU, &mtu, &mtu_index))) {
        intf_attribs.mtu = mtu->u32;
    } else {
        intf_attribs.mtu = DEFAULT_RIF_MTU;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, &mac,
                                 &mac_index))) {
        memcpy(&intf_attribs.mac_addr, mac->mac, sizeof(intf_attribs.mac_addr));
    } else {
        /* Get default mac from switch object. Use switch first port, and zero down lower 6 bits port part (64 ports) */
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_phys_addr_get(gh_sdk, FIRST_PORT, &intf_attribs.mac_addr))) {
            SX_LOG_ERR("Failed to get port address - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
        intf_attribs.mac_addr.ether_addr_octet[5] &= PORT_MAC_BITMASK;
    }

    intf_attribs.multicast_ttl_threshold = DEFAULT_MULTICAST_TTL_THRESHOLD;
    /* Work according to global DSCP<->Prio (TC in SAI terms), SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP */
    intf_attribs.qos_mode = SX_ROUTER_QOS_MODE_NOP;

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_ADD, (sx_router_id_t)vrid_data,
                                         &intf_params, &intf_attribs, &sdk_rif_id))) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
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

    if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_set(gh_sdk, sdk_rif_id, &rif_state))) {
        SX_LOG_ERR("Failed to set router interface state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdk_rif_id, NULL, rif_id))) {
        return status;
    }
    rif_key_to_str(*rif_id, key_str);
    SX_LOG_NTC("Created rif %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       sdk_rif_id;
    uint32_t                    data;
    char                        key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    rif_key_to_str(rif_id, key_str);
    SX_LOG_NTC("Remove rif %s\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(rif_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
        return status;
    }
    sdk_rif_id = (sx_router_interface_t)data;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, sdk_rif_id, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid, &intf_params, &intf_attribs,
                                         &sdk_rif_id))) {
        SX_LOG_ERR("Failed to delete router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
    const sai_object_key_t key = { .object_id = rif_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    rif_key_to_str(rif_id, key_str);
    return sai_set_attribute(&key, key_str, rif_attribs, rif_vendor_attribs, attr);
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
    const sai_object_key_t key = { .object_id = rif_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    rif_key_to_str(rif_id, key_str);
    return sai_get_attributes(&key, key_str, rif_attribs, rif_vendor_attribs, attr_count, attr_list);
}

/* MAC Address [sai_mac_t] */
/* MTU [uint32_t] */
static sai_status_t mlnx_rif_attrib_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id;
    uint32_t                    data;

    SX_LOG_ENTER();

    assert((SAI_ROUTER_INTERFACE_ATTR_MTU == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
        return status;
    }
    rif_id = (sx_router_interface_t)data;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_ROUTER_INTERFACE_ATTR_MTU == (long)arg) {
        intf_attribs.mtu = (uint16_t)value->u32;
    } else if (SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS == (long)arg) {
        /* Note, RIF admin has to be down when editing MAC */
        memcpy(&intf_attribs.mac_addr, value->mac, sizeof(intf_attribs.mac_addr));
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_EDIT, vrid, &intf_params, &intf_attribs, &rif_id))) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Admin State V4, V6 [bool] */
static sai_status_t mlnx_rif_admin_set(_In_ const sai_object_key_t      *key,
                                       _In_ const sai_attribute_value_t *value,
                                       void                             *arg)
{
    sx_status_t                 status;
    sx_router_interface_t       rif_id;
    sx_router_interface_state_t rif_state;
    uint32_t                    data;

    SX_LOG_ENTER();

    assert((SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
        return status;
    }
    rif_id = (sx_router_interface_t)data;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_get(gh_sdk, rif_id, &rif_state))) {
        SX_LOG_ERR("Failed to get router interface state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == (long)arg) {
        rif_state.ipv4_enable = value->booldata;
    } else {
        rif_state.ipv6_enable = value->booldata;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_set(gh_sdk, rif_id, &rif_state))) {
        SX_LOG_ERR("Failed to set router interface state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Virtual router id [sai_object_id_t] */
/* Type [sai_router_interface_type_t] */
/* Assosiated Port or Lag object id [sai_object_id_t] */
/* Assosiated Vlan [sai_vlan_id_t] */
/* MAC Address [sai_mac_t] */
/* MTU [uint32_t] */
static sai_status_t mlnx_rif_attrib_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id;
    uint32_t                    data;

    SX_LOG_ENTER();

    assert((SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_TYPE == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_PORT_ID == (long)arg) || (SAI_ROUTER_INTERFACE_ATTR_VLAN_ID == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_MTU == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
        return status;
    }
    rif_id = (sx_router_interface_t)data;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch ((long)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_PORT_ID:
        if (SX_L2_INTERFACE_TYPE_PORT_VLAN != intf_params.type) {
            SX_LOG_ERR("Can't get port id from interface whose type isn't port\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        if (SX_PORT_TYPE_LAG == SX_PORT_TYPE_ID_GET(intf_params.ifc.port_vlan.port)) {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG,
                                                                   intf_params.ifc.port_vlan.port, NULL,
                                                                   &value->oid))) {
                return status;
            }
        } else {
            if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                                   intf_params.ifc.port_vlan.port, NULL,
                                                                   &value->oid))) {
                return status;
            }
        }

        break;

    case SAI_ROUTER_INTERFACE_ATTR_VLAN_ID:
        if (SX_L2_INTERFACE_TYPE_VLAN != intf_params.type) {
            SX_LOG_ERR("Can't get vlan id from interface whose type isn't vlan\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
        }
        value->u16 = intf_params.ifc.vlan.vlan;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_MTU:
        value->u32 = intf_attribs.mtu;
        break;

    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        memcpy(value->mac, &intf_attribs.mac_addr, sizeof(intf_attribs.mac_addr));
        break;

    case SAI_ROUTER_INTERFACE_ATTR_TYPE:
        if (SX_L2_INTERFACE_TYPE_PORT_VLAN == intf_params.type) {
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;
        } else if (SX_L2_INTERFACE_TYPE_VLAN == intf_params.type) {
            value->s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
        } else {
            SX_LOG_ERR("Unexpected router intrerface type %d\n", intf_params.type);
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, vrid, NULL, &value->oid))) {
            return status;
        }
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Admin State V4, V6 [bool] */
static sai_status_t mlnx_rif_admin_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    sai_status_t                status;
    sx_router_interface_t       rif_id;
    sx_router_interface_state_t rif_state;
    uint32_t                    data;

    SX_LOG_ENTER();

    assert((SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == (long)arg) ||
           (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &data, NULL))) {
        return status;
    }
    rif_id = (sx_router_interface_t)data;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_get(gh_sdk, rif_id, &rif_state))) {
        SX_LOG_ERR("Failed to get router interface state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    if (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == (long)arg) {
        value->booldata = rif_state.ipv4_enable;
    } else {
        value->booldata = rif_state.ipv6_enable;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
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
};
