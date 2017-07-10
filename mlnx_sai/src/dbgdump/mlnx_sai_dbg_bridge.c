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

#include "mlnx_sai.h"
#include <sx/utils/dbg_utils.h>
#include "assert.h"

static void SAI_dump_bridge_port_getdb(_Out_ mlnx_bridge_port_t *mlnx_bridge_port_db)
{
    assert(NULL != mlnx_bridge_port_db);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_bridge_port_db,
           g_sai_db_ptr->bridge_ports_db,
           MAX_BRIDGE_PORTS * sizeof(mlnx_bridge_port_t));

    sai_db_unlock();
}

static void SAI_dump_bridge_rif_getdb(_Out_ mlnx_bridge_rif_t *mlnx_bridge_rif_db)
{
    assert(NULL != mlnx_bridge_rif_db);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_bridge_rif_db,
           g_sai_db_ptr->bridge_rifs_db,
           MAX_BRIDGE_RIFS * sizeof(mlnx_bridge_rif_t));

    sai_db_unlock();
}

static void SAI_dump_bridge_port_type_enum_to_str(_In_ sai_bridge_port_type_t type, _Out_ char                  *str)
{
    assert(str);

    switch (type) {
    case SAI_BRIDGE_PORT_TYPE_PORT:
        strncpy(str, "PORT", LINE_LENGTH);
        break;

    case SAI_BRIDGE_PORT_TYPE_SUB_PORT:
        strncpy(str, "SUB_PORT", LINE_LENGTH);
        break;

    case SAI_BRIDGE_PORT_TYPE_1Q_ROUTER:
        strncpy(str, "1Q_ROUTER", LINE_LENGTH);
        break;

    case SAI_BRIDGE_PORT_TYPE_1D_ROUTER:
        strncpy(str, "1D_ROUTER", LINE_LENGTH);
        break;

    case SAI_BRIDGE_PORT_TYPE_TUNNEL:
        strncpy(str, "TUNNEL", LINE_LENGTH);
        break;

    default:
        strncpy(str, "invalid", LINE_LENGTH);
        break;
    }
}

static void SAI_dump_bridge_port_print(_In_ FILE *file, _In_ const mlnx_bridge_port_t *mlnx_bridge_port_db)
{
    mlnx_bridge_port_t        cur_bridge_port;
    char                      bridge_port_type_str[LINE_LENGTH];
    uint32_t                  ii;
    dbg_utils_table_columns_t bridge_port_clmns[] = {
        {"db idx",       7, PARAM_UINT32_E, &ii},
        {"admin_state", 12, PARAM_UINT16_E, &cur_bridge_port.admin_state},
        {"parent",      12, PARAM_HEX_E, &cur_bridge_port.parent},
        {"logical",     12, PARAM_HEX_E, &cur_bridge_port.logical},
        {"tunnel_id",   12, PARAM_UINT32_E, &cur_bridge_port.tunnel_id},
        {"bridge_id",   12, PARAM_UINT32_E, &cur_bridge_port.bridge_id},
        {"port_type",   12, PARAM_STRING_E, bridge_port_type_str},
        {"rif_index",   12, PARAM_UINT32_E, &cur_bridge_port.rif_index},
        {"vlan_id",     12, PARAM_UINT16_E, &cur_bridge_port.vlan_id},
        {"vlan_refs",   12, PARAM_UINT16_E, &cur_bridge_port.vlans},
        {"fdb_refs",    12, PARAM_UINT32_E, &cur_bridge_port.fdbs},
        {"stp_refs",    12, PARAM_UINT16_E, &cur_bridge_port.stps},
        {NULL,           0,              0, NULL}
    };

    assert(file);
    assert(mlnx_bridge_port_db);

    dbg_utils_print_general_header(file, "Bridge ports");

    dbg_utils_print_table_headline(file, bridge_port_clmns);

    for (ii = 0; ii < MAX_BRIDGE_PORTS; ii++) {
        if (mlnx_bridge_port_db[ii].is_present) {
            memcpy(&cur_bridge_port, &mlnx_bridge_port_db[ii], sizeof(mlnx_bridge_port_t));

            SAI_dump_bridge_port_type_enum_to_str(cur_bridge_port.port_type, bridge_port_type_str);

            dbg_utils_print_table_data_line(file, bridge_port_clmns);
        }
    }
}

static void SAI_dump_bridge_rif_sx_intf_attrs_print(_In_ FILE *file, _In_ sx_interface_attributes_t intf_attribs)
{
    sx_router_qos_mode_t      qos_mode;
    char                      qos_mode_str[LINE_LENGTH];
    dbg_utils_table_columns_t sx_if_clmns[] = {
        {"intf_mac",         17, PARAM_MAC_ADDR_E, &intf_attribs.mac_addr},
        {"mtu",               6, PARAM_UINT16_E,   &intf_attribs.mtu},
        {"qos_mode",         15, PARAM_STRING_E,   qos_mode_str},
        {"mc_ttl_threshold", 17, PARAM_UINT8_E,    &intf_attribs.multicast_ttl_threshold},
        {"loopback_enable",  17, PARAM_UINT8_E,    &intf_attribs.loopback_enable},
        {NULL,                0,              0,   NULL}
    };

    assert(file);

    qos_mode = intf_attribs.qos_mode;

    if (SX_ROUTER_QOS_MODE_CHECK_RANGE((int)qos_mode)) {
        strncpy(qos_mode_str, sx_router_qos_mode_type_str[qos_mode], LINE_LENGTH);
        qos_mode_str[LINE_LENGTH - 1] = 0;
    } else {
        strncpy(qos_mode_str, "invalid", LINE_LENGTH);
    }

    dbg_utils_print_table_headline(file, sx_if_clmns);

    dbg_utils_print_table_data_line(file, sx_if_clmns);
}

static void SAI_dump_bridge_rif_sx_rif_param_print(_In_ FILE *file, _In_ sx_router_interface_param_t intf_params)
{
    assert(file);

    dbg_utils_print_field(file, "Type: ", SX_ROUTER_RIF_TYPE_STR(intf_params.type), PARAM_STRING_E);

    switch (intf_params.type) {
    case SX_L2_INTERFACE_TYPE_VLAN:
        dbg_utils_print_field(file, "swid: ", &intf_params.ifc.vlan.swid, PARAM_UINT16_E);
        dbg_utils_print_field(file, "vlan: ", &intf_params.ifc.vlan.vlan, PARAM_UINT16_E);
        break;

    case SX_L2_INTERFACE_TYPE_PORT_VLAN:
        dbg_utils_print_field(file, "port: ", &intf_params.ifc.port_vlan.port, PARAM_HEX_E);
        dbg_utils_print_field(file, "vlan: ", &intf_params.ifc.port_vlan.vlan, PARAM_UINT16_E);
        break;

    case SX_L2_INTERFACE_TYPE_BRIDGE:
        dbg_utils_print_field(file, "swid: ", &intf_params.ifc.bridge.swid, PARAM_UINT16_E);
        dbg_utils_print_field(file, "bridge: ", &intf_params.ifc.bridge.bridge, PARAM_UINT16_E);
        break;

    case SX_L2_INTERFACE_TYPE_LOOPBACK:
        break;

    default:
        break;
    }
}

static void SAI_dump_bridge_rif_sx_rif_state_print(_In_ FILE *file, _In_ sx_router_interface_state_t intf_state)
{
    assert(file);

    dbg_utils_table_columns_t sx_rif_state_clmns[] = {
        {"ipv4_enable",         13, PARAM_UINT8_E, &intf_state.ipv4_enable},
        {"ipv6_enable",         13, PARAM_UINT8_E, &intf_state.ipv6_enable},
        {"ipv4_mc_enable",      15, PARAM_UINT8_E, &intf_state.ipv4_mc_enable},
        {"ipv6_mc_enable",      15, PARAM_UINT8_E, &intf_state.ipv6_mc_enable},
        {"mpls_enable",         13, PARAM_UINT8_E, &intf_state.mpls_enable},
        {NULL,                0,              0, NULL}
    };

    dbg_utils_print_table_headline(file, sx_rif_state_clmns);

    dbg_utils_print_table_data_line(file, sx_rif_state_clmns);
}

static void SAI_dump_bridge_rif_sx_data_print(_In_ FILE *file, _In_ mlnx_bridge_rif_t mlnx_bridge_rif)
{
    assert(file);

    SAI_dump_bridge_rif_sx_intf_attrs_print(file, mlnx_bridge_rif.intf_attribs);

    SAI_dump_bridge_rif_sx_rif_param_print(file, mlnx_bridge_rif.intf_params);

    SAI_dump_bridge_rif_sx_rif_state_print(file, mlnx_bridge_rif.intf_state);
}

static void SAI_dump_bridge_rif_print(_In_ FILE *file, _In_ const mlnx_bridge_rif_t *mlnx_bridge_rif_db)
{
    mlnx_bridge_rif_t         cur_bridge_rif;
    uint32_t                  ii;
    dbg_utils_table_columns_t bridge_rif_clmns[] = {
        {"db idx",      7,  PARAM_UINT32_E, &ii},
        {"index",       7,  PARAM_UINT32_E, &cur_bridge_rif.index},
        {"is_created",  12, PARAM_UINT8_E, &cur_bridge_rif.is_created},
        {"bridge_id",   12, PARAM_UINT16_E, &cur_bridge_rif.bridge_id},
        {"rif_id",      12, PARAM_UINT32_E, &cur_bridge_rif.rif_id},
        {"vrf_id",      12, PARAM_UINT32_E, &cur_bridge_rif.vrf_id},
        {NULL,           0,              0, NULL}
    };

    assert(file);
    assert(mlnx_bridge_rif_db);

    dbg_utils_print_general_header(file, "Bridge rifs");

    dbg_utils_print_table_headline(file, bridge_rif_clmns);

    for (ii = 0; ii < MAX_BRIDGE_RIFS; ii++) {
        if (mlnx_bridge_rif_db[ii].is_used) {
            memcpy(&cur_bridge_rif, &mlnx_bridge_rif_db[ii], sizeof(mlnx_bridge_rif_t));

            dbg_utils_print_table_data_line(file, bridge_rif_clmns);

            SAI_dump_bridge_rif_sx_data_print(file, cur_bridge_rif);
        }
    }
}

void SAI_dump_bridge(_In_ FILE *file)
{
    mlnx_bridge_port_t *mlnx_bridge_port_db = NULL;
    mlnx_bridge_rif_t  *mlnx_bridge_rifs_db = NULL;

    mlnx_bridge_port_db = calloc(MAX_BRIDGE_PORTS, sizeof(mlnx_bridge_port_t));
    if (!mlnx_bridge_port_db) {
        goto out;
    }

    mlnx_bridge_rifs_db = calloc(MAX_BRIDGE_RIFS, sizeof(mlnx_bridge_rif_t));
    if (!mlnx_bridge_rifs_db) {
        goto out;
    }

    SAI_dump_bridge_port_getdb(mlnx_bridge_port_db);
    SAI_dump_bridge_rif_getdb(mlnx_bridge_rifs_db);

    dbg_utils_print_module_header(file, "SAI Bridge DB");

    SAI_dump_bridge_port_print(file, mlnx_bridge_port_db);
    SAI_dump_bridge_rif_print(file, mlnx_bridge_rifs_db);

out:
    free(mlnx_bridge_port_db);
    free(mlnx_bridge_rifs_db);
}
