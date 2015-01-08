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

#undef  __MODULE__
#define __MODULE__ SAI_RIF

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Create router interface. Interface is created in DOWN mode.
 *    After all the required attributes are set and at least one ip address is
 *    added, it can be brought UP.
 *
 * Arguments:
 *    [in] vr_id - virtual router id
 *    [in] interface_type - interface type (port, VLAN)
 *    [in] attachment_id - Id of the corresponding port or VLAN
 *                         according to the interface type
 *    [in] src_mac - source mac address
 *    [out] interface_id - router interface id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_router_interface(_Inout_ sai_router_interface_id_t* router_interface_id,
                                          _In_ sai_vr_id_t                   vr_id,
                                          _In_ sai_router_interface_type_t   router_interface_type,
                                          _In_ uint32_t                      attachment_id,
                                          _In_ sai_mac_t                     src_mac)
{
    sx_router_id_t              vrid = (sx_router_id_t)vr_id;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id = 0;

    SX_LOG_ENTER();

    if (NULL == router_interface_id) {
        SX_LOG_ERR("NULL router interface id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_ROUTER_INTERFACE_TYPE_PORT == router_interface_type) {
        intf_params.type = SX_L2_INTERFACE_TYPE_PORT_VLAN;
        intf_params.ifc.port_vlan.port = attachment_id;
        intf_params.ifc.port_vlan.vlan = 0;

        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_swid_bind_set(gh_sdk, attachment_id, SX_SWID_ID_DISABLED))) {
            SX_LOG_ERR("Failed to unbind router port - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    } else if (SAI_ROUTER_INTERFACE_TYPE_VLAN == router_interface_type) {
        intf_params.type = SX_L2_INTERFACE_TYPE_VLAN;
        intf_params.ifc.vlan.swid = DEFAULT_ETH_SWID;
        intf_params.ifc.vlan.vlan = attachment_id;
    } else {
        SX_LOG_ERR("Invalid router interface type %d.\n", router_interface_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&intf_attribs.mac_addr, src_mac, sizeof(intf_attribs.mac_addr));
    intf_attribs.mtu = 1500;
    intf_attribs.multicast_ttl_threshold = 1;
    intf_attribs.qos_mode = SX_ROUTER_QOS_MODE_PRIO_FROM_DSCP;

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_ADD, vrid, &intf_params, &intf_attribs, &rif_id))) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    *router_interface_id = rif_id;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Delete router interface
 *
 * Arguments:
 *    [in] interface_id - router interface id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_router_interface(_In_ sai_router_interface_id_t interface_id)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id = interface_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_DELETE, vrid, &intf_params, &intf_attribs, &rif_id))) {
        SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_L2_INTERFACE_TYPE_PORT_VLAN == intf_params.type) {
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_port_swid_bind_set(gh_sdk, intf_params.ifc.port_vlan.port, DEFAULT_ETH_SWID))) {
            SX_LOG_ERR("Failed to bind router port - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Set router interface attribute value
 *
 * Arguments:
 *    [in] interface_id - router interface id
 *    [in] attribute - router interface attribute
 *    [in] value - router interface attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_router_interface_attribute(_In_ sai_router_interface_id_t   interface_id,
                                                 _In_ sai_router_interface_attr_t attribute,
                                                 _In_ uint64_t                    value)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id = interface_id;
    sx_router_interface_state_t rif_state;

    SX_LOG_ENTER();

    switch (attribute) {
    case SAI_ROUTER_INTERFACE_ATTR_MTU:
    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SAI_ROUTER_INTERFACE_ATTR_MTU == attribute) {
            intf_attribs.mtu = (uint16_t)value;
        }
        if (SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS == attribute) {
            memcpy(&intf_attribs.mac_addr, &value, sizeof(intf_attribs.mac_addr));
        }

        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_api_router_interface_set(gh_sdk, SX_ACCESS_CMD_EDIT, vrid, &intf_params, &intf_attribs, &rif_id))) {
            SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_get(gh_sdk, rif_id, &rif_state))) {
            SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == attribute) {
            rif_state.ipv4_enable = (boolean_t)value;
        } else {
            rif_state.ipv6_enable = (boolean_t)value;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_set(gh_sdk, rif_id, &rif_state))) {
            SX_LOG_ERR("Failed to set router interface - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        return SAI_STATUS_SUCCESS;

    default:
        SX_LOG_ERR("Invalid router interface attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}

/*
 * Routine Description:
 *    Get router interface attribute value
 *
 * Arguments:
 *    [in] router_interface_id - router interface id
 *    [in] attribute - router interface attribute
 *    [out] value - router interface attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_router_interface_attribute(_In_ sai_router_interface_id_t   interface_id,
                                                 _In_ sai_router_interface_attr_t attribute,
                                                 _Out_ uint64_t                 * value)
{
    sx_router_id_t              vrid;
    sx_router_interface_param_t intf_params;
    sx_interface_attributes_t   intf_attribs;
    sx_status_t                 status;
    sx_router_interface_t       rif_id = interface_id;
    sx_router_interface_state_t rif_state;

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif_id, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (attribute) {
    case SAI_ROUTER_INTERFACE_ATTR_PORT_ID:
        if (SX_L2_INTERFACE_TYPE_PORT_VLAN != intf_params.type) {
            SX_LOG_ERR("Can't get port id from interface whose type isn't port\n");
            return SAI_STATUS_FAILURE;
        }
        *value = intf_params.ifc.port_vlan.port;
        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_MTU:
        *value = intf_attribs.mtu;
        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        memcpy(value, &intf_attribs.mac_addr, sizeof(intf_attribs.mac_addr));
        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_TYPE:
        if (SX_L2_INTERFACE_TYPE_PORT_VLAN == intf_params.type) {
            *value = SAI_ROUTER_INTERFACE_TYPE_PORT;
        } else if (SX_L2_INTERFACE_TYPE_VLAN == intf_params.type) {
            *value = SAI_ROUTER_INTERFACE_TYPE_VLAN;
        } else {
            SX_LOG_ERR("Unexpected router intrerface type %d\n", intf_params.type);
            return SAI_STATUS_FAILURE;
        }
        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_VLAN_ID:
        if (SX_L2_INTERFACE_TYPE_VLAN != intf_params.type) {
            SX_LOG_ERR("Can't get vlan id from interface whose type isn't vlan\n");
            return SAI_STATUS_FAILURE;
        }
        *value = intf_params.ifc.vlan.vlan;
        return SAI_STATUS_SUCCESS;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        if (SX_STATUS_SUCCESS != (status = sx_api_router_interface_state_get(gh_sdk, rif_id, &rif_state))) {
            SX_LOG_ERR("Failed to get router interface state - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
        if (SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE == attribute) {
            *value = rif_state.ipv4_enable;
        } else {
            *value = rif_state.ipv6_enable;
        }
        return SAI_STATUS_SUCCESS;

    default:
        SX_LOG_ERR("Invalid router interface attribute %d.\n", attribute);
        return SAI_STATUS_FAILURE;
    }
}


#ifdef _WIN32

/*
 * Routine Description:
 *    Add IP address to router interface
 *
 * Arguments:
 *    [in] router_interface_id - router interface id
 *    [in] address - IP address (IPv4 or IPv6)
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_add_router_interface_address(_In_ sai_router_interface_id_t interface_id,
                                               _In_ PSOCKADDR_INET            address)
{
    UNREFERENCED_PARAMETER(interface_id);
    UNREFERENCED_PARAMETER(address);

    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Remove IP address from router interface
 *
 * Arguments:
 *    [in] router_interface_id - router interface id
 *    [in] address - IP address (IPv4 or IPv6)
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_router_interface_address(_In_ sai_router_interface_id_t interface_id,
                                                  _In_ PSOCKADDR_INET            address)
{
    UNREFERENCED_PARAMETER(interface_id);
    UNREFERENCED_PARAMETER(address);

    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

#endif

/*
 * Routine Description:
 *   Enable/disable statistics counters for router interface.
 *
 * Arguments:
 *    [in] router_interface_id - router interface id
 *    [in] counter_set_id - specifies the counter set
 *    [in] enable - TRUE to enable, FALSE to disable
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlnx_ctl_router_interface_stats(_In_ sai_router_interface_id_t interface_id,
                                             _In_ uint32_t                  counter_set_id,
                                             _In_ bool                      enable)
{
    UNREFERENCED_PARAMETER(interface_id);
    UNREFERENCED_PARAMETER(counter_set_id);
    UNREFERENCED_PARAMETER(enable);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Get router interface statistics counters.
 *
 * Arguments:
 *    [in] router_interface_id - router interface id
 *    [in] counter_set_id - specifies the counter set
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    S_OK        on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_router_interface_stats(_In_ sai_router_interface_id_t router_interface_id,
                                             _In_ uint32_t                  counter_set_id,
                                             _In_ uint32_t                  number_of_counters,
                                             _Out_ uint64_t               * counters)
{
    UNREFERENCED_PARAMETER(router_interface_id);
    UNREFERENCED_PARAMETER(counter_set_id);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

#ifdef _WIN32
const sai_router_interface_api_t router_interface_api = {
    mlnx_create_router_interface,
    mlnx_delete_router_interface,
    mlnx_set_router_interface_attribute,
    mlnx_get_router_interface_attribute,
    mlnx_add_router_interface_address,
    mlnx_delete_router_interface_address,
    mlnx_ctl_router_interface_stats,
    mlnx_get_router_interface_stats
};
#else
const sai_router_interface_api_t router_interface_api = {
    mlnx_create_router_interface,
    mlnx_delete_router_interface,
    mlnx_set_router_interface_attribute,
    mlnx_get_router_interface_attribute,
    NULL,
    NULL,
    mlnx_ctl_router_interface_stats,
    mlnx_get_router_interface_stats
};
#endif
