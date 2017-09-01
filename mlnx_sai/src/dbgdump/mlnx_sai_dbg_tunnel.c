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

static void SAI_dump_tunnel_getdb(_Out_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry,
                                  _Out_ mlnx_tunnel_map_t       *mlnx_tunnel_map,
                                  _Out_ tunnel_db_entry_t       *tunnel_db,
                                  _Out_ mlnx_tunneltable_t      *mlnx_tunneltable,
                                  _Out_ sx_bridge_id_t          *sx_bridge_id)
{
    assert(NULL != mlnx_tunnel_map_entry);
    assert(NULL != mlnx_tunnel_map);
    assert(NULL != tunnel_db);
    assert(NULL != mlnx_tunneltable);
    assert(NULL != sx_bridge_id);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_tunnel_map_entry,
           g_sai_db_ptr->mlnx_tunnel_map_entry,
           MLNX_TUNNEL_MAP_ENTRY_MAX * sizeof(mlnx_tunnel_map_entry_t));

    memcpy(mlnx_tunnel_map,
           g_sai_db_ptr->mlnx_tunnel_map,
           MLNX_TUNNEL_MAP_MAX * sizeof(mlnx_tunnel_map_t));

    memcpy(tunnel_db,
           g_sai_db_ptr->tunnel_db,
           MAX_TUNNEL_DB_SIZE * sizeof(tunnel_db_entry_t));

    memcpy(mlnx_tunneltable,
           g_sai_db_ptr->mlnx_tunneltable,
           MLNX_TUNNELTABLE_SIZE * sizeof(mlnx_tunneltable_t));

    *sx_bridge_id = g_sai_db_ptr->sx_bridge_id;

    sai_db_unlock();
}

static void SAI_dump_tunnel_map_type_enum_to_str(_In_ sai_tunnel_map_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
        strcpy(str, "oecn2uecn");
        break;

    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
        strcpy(str, "uoecn2oecn");
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
        strcpy(str, "vni2vlan");
        break;

    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
        strcpy(str, "vlan2vni");
        break;

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
        strcpy(str, "vni2bridgeif");
        break;

    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
        strcpy(str, "bridgeif2vni");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_tunnel_map_entry_print(_In_ FILE *file, _In_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_tunnel_map_entry_t   curr_mlnx_tunnel_map_entry;
    char                      type_str[LINE_LENGTH];
    dbg_utils_table_columns_t tunnelmapentry_clmns[] = {
        {"sai oid",                   16, PARAM_UINT64_E, &obj_id},
        {"db idx",                    7,  PARAM_UINT32_E, &ii},
        {"type",                      12, PARAM_STRING_E, &type_str},
        {"map id",                    12, PARAM_UINT64_E, &curr_mlnx_tunnel_map_entry.tunnel_map_id},
        {"oecn key",                  12, PARAM_UINT8_E,  &curr_mlnx_tunnel_map_entry.oecn_key},
        {"oecn value",                12, PARAM_UINT8_E,  &curr_mlnx_tunnel_map_entry.oecn_value},
        {"uecn key",                  12, PARAM_UINT8_E,  &curr_mlnx_tunnel_map_entry.uecn_key},
        {"uecn value",                12, PARAM_UINT8_E,  &curr_mlnx_tunnel_map_entry.uecn_value},
        {"vlan key",                  12, PARAM_UINT16_E, &curr_mlnx_tunnel_map_entry.vlan_id_key},
        {"vlan value",                12, PARAM_UINT16_E, &curr_mlnx_tunnel_map_entry.vlan_id_value},
        {"vni key",                   12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.vni_id_key},
        {"vni value",                 12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.vni_id_value},
        {"bridge if key",             12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.bridge_id_key},
        {"bridge if value",           12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.bridge_id_value},
        {"prev tunnel map entry idx", 12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.prev_tunnel_map_entry_idx},
        {"next tunnel map entry idx", 12, PARAM_UINT32_E, &curr_mlnx_tunnel_map_entry.next_tunnel_map_entry_idx},
        {NULL,                        0,  0,              NULL}
    };

    assert(NULL != mlnx_tunnel_map_entry);

    dbg_utils_print_general_header(file, "Tunnel map entry");

    dbg_utils_print_secondary_header(file, "mlnx_tunnel_map_entry");

    dbg_utils_print_table_headline(file, tunnelmapentry_clmns);

    for (ii = 0; ii < MLNX_TUNNEL_MAP_ENTRY_MAX; ii++) {
        if (mlnx_tunnel_map_entry[ii].in_use) {
            memcpy(&curr_mlnx_tunnel_map_entry, &mlnx_tunnel_map_entry[ii], sizeof(mlnx_tunnel_map_entry_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            SAI_dump_tunnel_map_type_enum_to_str(mlnx_tunnel_map_entry[ii].tunnel_map_type,
                                                 type_str);
            dbg_utils_print_table_data_line(file, tunnelmapentry_clmns);
        }
    }
}

static void SAI_dump_tunnel_map_print(_In_ FILE                    *file,
                                      _In_ mlnx_tunnel_map_t       *mlnx_tunnel_map,
                                      _In_ mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry)
{
    uint32_t                  ii           = 0, jj = 0;
    sai_object_id_t           obj_id       = SAI_NULL_OBJECT_ID;
    sai_object_id_t           bridge_if_id = SAI_NULL_OBJECT_ID;
    mlnx_tunnel_map_t         curr_mlnx_tunnel_map;
    sai_tunnel_map_t          curr_sai_tunnel_map;
    uint32_t                  tunnel_map_entry_idx = MLNX_TUNNEL_MAP_ENTRY_INVALID;
    char                      type_str[LINE_LENGTH];
    dbg_utils_table_columns_t tunnelmap_clmns[] = {
        {"sai oid",                   16, PARAM_UINT64_E, &obj_id},
        {"db idx",                    7,  PARAM_UINT32_E, &ii},
        {"type",                      12, PARAM_STRING_E, &type_str},
        {"map list cnt",              12, PARAM_UINT32_E, &curr_mlnx_tunnel_map.tunnel_map_list_count},
        {"tunnel cnt",                10, PARAM_UINT32_E, &curr_mlnx_tunnel_map.tunnel_cnt},
        {"tunnel map entry cnt",      20, PARAM_UINT32_E, &curr_mlnx_tunnel_map.tunnel_map_entry_cnt},
        {"tunnel map entry head idx", 25, PARAM_UINT32_E, &curr_mlnx_tunnel_map.tunnel_map_entry_head_idx},
        {"tunnel map entry tail idx", 25, PARAM_UINT32_E, &curr_mlnx_tunnel_map.tunnel_map_entry_tail_idx},
        {NULL,                        0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_oecn2uecn_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key oecn",             8,  PARAM_UINT8_E,  &curr_sai_tunnel_map.key.oecn},
        {"val uecn",             8,  PARAM_UINT8_E,  &curr_sai_tunnel_map.value.uecn},
        {NULL,                   0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_uecnoecn2oecn_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key oecn",             8,  PARAM_UINT8_E,  &curr_sai_tunnel_map.key.oecn},
        {"key uecn",             8,  PARAM_UINT8_E,  &curr_sai_tunnel_map.key.uecn},
        {"val oecn",             8,  PARAM_UINT8_E,  &curr_sai_tunnel_map.value.oecn},
        {NULL,                   0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_vni2vlan_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key vni",              11, PARAM_UINT32_E, &curr_sai_tunnel_map.key.vni_id},
        {"val vlan",             8,  PARAM_UINT16_E, &curr_sai_tunnel_map.value.vlan_id},
        {NULL,                   0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_vlan2vni_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key vlan",             8,  PARAM_UINT16_E, &curr_sai_tunnel_map.key.vlan_id},
        {"val vni",              11, PARAM_UINT32_E, &curr_sai_tunnel_map.value.vni_id},
        {NULL,                   0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_vni2bridgeif_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key vni",              11, PARAM_UINT32_E, &curr_sai_tunnel_map.key.vni_id},
        {"val bridge if",        13, PARAM_UINT64_E, &bridge_if_id},
        {NULL,                   0,  0,              NULL}
    };
    dbg_utils_table_columns_t sai_tunnelmap_bridgeif2vni_clmns[] = {
        {"db idx",               7,  PARAM_UINT32_E, &ii},
        {"tunnel map entry idx", 20, PARAM_UINT32_E, &tunnel_map_entry_idx},
        {"key bridge if",        8,  PARAM_UINT64_E, &bridge_if_id},
        {"val vni",              11, PARAM_UINT32_E, &curr_sai_tunnel_map.value.vni_id},
        {NULL,                   0,  0,              NULL}
    };

    assert(NULL != mlnx_tunnel_map);

    dbg_utils_print_general_header(file, "Tunnel map");

    dbg_utils_print_secondary_header(file, "mlnx_tunnel_map");

    dbg_utils_print_table_headline(file, tunnelmap_clmns);

    for (ii = 0; ii < MLNX_TUNNEL_MAP_MAX; ii++) {
        if (mlnx_tunnel_map[ii].in_use) {
            memcpy(&curr_mlnx_tunnel_map, &mlnx_tunnel_map[ii], sizeof(mlnx_tunnel_map_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_MAP, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            SAI_dump_tunnel_map_type_enum_to_str(mlnx_tunnel_map[ii].tunnel_map_type,
                                                 type_str);
            dbg_utils_print_table_data_line(file, tunnelmap_clmns);
        }
    }

    dbg_utils_print_secondary_header(file, "sai_tunnel_map");

    for (ii = 0; ii < MLNX_TUNNEL_MAP_MAX; ii++) {
        if (mlnx_tunnel_map[ii].in_use) {
            switch (mlnx_tunnel_map[ii].tunnel_map_type) {
            case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                dbg_utils_print_table_headline(file, sai_tunnelmap_oecn2uecn_clmns);
                break;

            case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                dbg_utils_print_table_headline(file, sai_tunnelmap_uecnoecn2oecn_clmns);
                break;

            case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                dbg_utils_print_table_headline(file, sai_tunnelmap_vni2vlan_clmns);
                break;

            case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                dbg_utils_print_table_headline(file, sai_tunnelmap_vlan2vni_clmns);
                break;

            case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
                dbg_utils_print_table_headline(file, sai_tunnelmap_vni2bridgeif_clmns);
                break;

            case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
                dbg_utils_print_table_headline(file, sai_tunnelmap_bridgeif2vni_clmns);
                break;

            default:
                break;
            }

            if (0 != mlnx_tunnel_map[ii].tunnel_map_list_count) {
                for (jj = 0; jj < mlnx_tunnel_map[ii].tunnel_map_list_count; jj++) {
                    memcpy(&curr_sai_tunnel_map,
                           &mlnx_tunnel_map[ii].tunnel_map_list[jj],
                           sizeof(sai_tunnel_map_t));

                    switch (mlnx_tunnel_map[ii].tunnel_map_type) {
                    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_oecn2uecn_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_uecnoecn2oecn_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_vni2vlan_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_vlan2vni_clmns);
                        break;

                    default:
                        break;
                    }
                }
            } else {
                for (jj = mlnx_tunnel_map[ii].tunnel_map_entry_head_idx;
                     jj != MLNX_TUNNEL_MAP_ENTRY_INVALID;
                     jj = mlnx_tunnel_map_entry[jj].next_tunnel_map_entry_idx) {
                    tunnel_map_entry_idx = jj;

                    switch (mlnx_tunnel_map[ii].tunnel_map_type) {
                    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
                        curr_sai_tunnel_map.key.oecn   = mlnx_tunnel_map_entry[jj].oecn_key;
                        curr_sai_tunnel_map.value.uecn = mlnx_tunnel_map_entry[jj].uecn_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_oecn2uecn_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN:
                        curr_sai_tunnel_map.key.oecn   = mlnx_tunnel_map_entry[jj].oecn_key;
                        curr_sai_tunnel_map.key.uecn   = mlnx_tunnel_map_entry[jj].uecn_key;
                        curr_sai_tunnel_map.value.oecn = mlnx_tunnel_map_entry[jj].oecn_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_uecnoecn2oecn_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID:
                        curr_sai_tunnel_map.key.vni_id    = mlnx_tunnel_map_entry[jj].vni_id_key;
                        curr_sai_tunnel_map.value.vlan_id = mlnx_tunnel_map_entry[jj].vlan_id_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_vni2vlan_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI:
                        curr_sai_tunnel_map.key.vlan_id  = mlnx_tunnel_map_entry[jj].vlan_id_key;
                        curr_sai_tunnel_map.value.vni_id = mlnx_tunnel_map_entry[jj].vni_id_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_vlan2vni_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
                        curr_sai_tunnel_map.key.vni_id = mlnx_tunnel_map_entry[jj].vni_id_key;
                        bridge_if_id                   = mlnx_tunnel_map_entry[jj].bridge_id_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_vni2bridgeif_clmns);
                        break;

                    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
                        bridge_if_id                     = mlnx_tunnel_map_entry[jj].bridge_id_key;
                        curr_sai_tunnel_map.value.vni_id = mlnx_tunnel_map_entry[jj].vni_id_value;
                        dbg_utils_print_table_data_line(file, sai_tunnelmap_bridgeif2vni_clmns);

                    default:
                        break;
                    }
                }
            }
        }
    }
}

static void SAI_dump_tunnel_print(_In_ FILE *file, _In_ tunnel_db_entry_t *tunnel_db)
{
    uint32_t                  ii     = 0, jj = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    tunnel_db_entry_t         curr_tunnel_db;
    dbg_utils_table_columns_t tunnel_clmns[] = {
        {"sai oid",       16, PARAM_UINT64_E, &obj_id},
        {"db idx",        7,  PARAM_UINT32_E, &ii},
        {"sx tunnel id",  12, PARAM_UINT32_E, &curr_tunnel_db.sx_tunnel_id},
        {"vxlan o if",    16, PARAM_UINT64_E, &curr_tunnel_db.sai_vxlan_overlay_rif},
        {"vxlan u if",    16, PARAM_UINT64_E, &curr_tunnel_db.sai_underlay_rif},
        {"encap map cnt", 13, PARAM_UINT32_E, &curr_tunnel_db.sai_tunnel_map_encap_cnt},
        {"decap map cnt", 13, PARAM_UINT32_E, &curr_tunnel_db.sai_tunnel_map_decap_cnt},
        {NULL,            0,  0,              NULL}
    };
    dbg_utils_table_columns_t tunnel_encap_map_clmns[] = {
        {"db idx",       7,  PARAM_UINT32_E, &ii},
        {"encap map id", 16, PARAM_UINT64_E, &obj_id},
        {NULL,           0,  0,              NULL}
    };
    dbg_utils_table_columns_t tunnel_decap_map_clmns[] = {
        {"db idx",       7,  PARAM_UINT32_E, &ii},
        {"decap map id", 16, PARAM_UINT64_E, &obj_id},
        {NULL,           0,  0,              NULL}
    };

    assert(NULL != tunnel_db);

    dbg_utils_print_general_header(file, "Tunnel");

    dbg_utils_print_secondary_header(file, "tunnel_db");

    dbg_utils_print_table_headline(file, tunnel_clmns);

    for (ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        if (tunnel_db[ii].is_used) {
            memcpy(&curr_tunnel_db, &tunnel_db[ii], sizeof(tunnel_db_entry_t));
            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            dbg_utils_print_table_data_line(file, tunnel_clmns);
        }
    }

    dbg_utils_print_secondary_header(file, "tunnel encap map");

    dbg_utils_print_table_headline(file, tunnel_encap_map_clmns);

    for (ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        if (tunnel_db[ii].is_used) {
            for (jj = 0; jj < tunnel_db[ii].sai_tunnel_map_encap_cnt; jj++) {
                obj_id = tunnel_db[ii].sai_tunnel_map_encap_id_array[jj];
                dbg_utils_print_table_data_line(file, tunnel_encap_map_clmns);
            }
        }
    }

    dbg_utils_print_secondary_header(file, "tunnel decap map");

    dbg_utils_print_table_headline(file, tunnel_decap_map_clmns);

    for (ii = 0; ii < MAX_TUNNEL_DB_SIZE; ii++) {
        if (tunnel_db[ii].is_used) {
            for (jj = 0; jj < tunnel_db[ii].sai_tunnel_map_decap_cnt; jj++) {
                obj_id = tunnel_db[ii].sai_tunnel_map_decap_id_array[jj];
                dbg_utils_print_table_data_line(file, tunnel_decap_map_clmns);
            }
        }
    }
}

static void SAI_dump_sdk_tunnel_type_enum_to_str(_In_ sx_tunnel_type_e type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_IPV4:
        strcpy(str, "ipinip");
        break;

    case SX_TUNNEL_TYPE_IPINIP_P2P_IPV4_IN_GRE:
        strcpy(str, "ipinip gre");
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN:
        strcpy(str, "vxlan");
        break;

    case SX_TUNNEL_TYPE_NVE_VXLAN_GPE:
        strcpy(str, "vxlan gpe");
        break;

    case SX_TUNNEL_TYPE_NVE_GENEVE:
        strcpy(str, "geneve");
        break;

    case SX_TUNNEL_TYPE_NVE_NVGRE:
        strcpy(str, "nvgre");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_sdk_tunnel_table_type_enum_to_str(_In_ sx_tunnel_decap_key_fields_type_e type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP:
        strcpy(str, "dip");
        break;

    case SX_TUNNEL_DECAP_KEY_FIELDS_TYPE_DIP_SIP:
        strcpy(str, "dip sip");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_tunnel_table_print(_In_ FILE *file, _In_ mlnx_tunneltable_t *mlnx_tunneltable)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_tunneltable_t        curr_mlnx_tunneltable;
    char                      tunnel_type_str[LINE_LENGTH];
    char                      field_type_str[LINE_LENGTH];
    dbg_utils_table_columns_t tunneltable_clmns[] = {
        {"sai obj id",  11, PARAM_UINT64_E, &obj_id},
        {"db idx",      8,  PARAM_UINT32_E, &ii},
        {"tunnel type", 11, PARAM_STRING_E, &tunnel_type_str},
        {"field type",  10, PARAM_STRING_E, &field_type_str},
        {"u vrid",      10, PARAM_STRING_E, &curr_mlnx_tunneltable.sdk_tunnel_decap_key.underlay_vrid},
        {"u dipv4",     15, PARAM_IPV4_E,   &curr_mlnx_tunneltable.sdk_tunnel_decap_key.underlay_dip.addr.ipv4},
        {"u dipv6",     15, PARAM_IPV6_E,   &curr_mlnx_tunneltable.sdk_tunnel_decap_key.underlay_dip.addr.ipv6},
        {"u sipv4",     15, PARAM_IPV4_E,   &curr_mlnx_tunneltable.sdk_tunnel_decap_key.underlay_sip.addr.ipv4},
        {"u sipv6",     15, PARAM_IPV6_E,   &curr_mlnx_tunneltable.sdk_tunnel_decap_key.underlay_sip.addr.ipv6},
        {NULL,          0,  0,              NULL}
    };

    assert(NULL != mlnx_tunneltable);

    dbg_utils_print_general_header(file, "Tunnel table");

    dbg_utils_print_secondary_header(file, "mlnx_tunneltable");

    dbg_utils_print_table_headline(file, tunneltable_clmns);

    for (ii = 0; ii < MLNX_TUNNELTABLE_SIZE; ii++) {
        if (mlnx_tunneltable[ii].in_use) {
            memcpy(&curr_mlnx_tunneltable, &mlnx_tunneltable[ii], sizeof(mlnx_tunneltable_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            SAI_dump_sdk_tunnel_type_enum_to_str(mlnx_tunneltable[ii].sdk_tunnel_decap_key.tunnel_type,
                                                 tunnel_type_str);
            SAI_dump_sdk_tunnel_table_type_enum_to_str(mlnx_tunneltable[ii].sdk_tunnel_decap_key.type,
                                                       field_type_str);

            dbg_utils_print_table_data_line(file, tunneltable_clmns);
        }
    }
}

static void SAI_dump_bridge_print(_In_ FILE *file, _In_ sx_bridge_id_t *sx_bridge_id)
{
    assert(NULL != sx_bridge_id);

    dbg_utils_print_general_header(file, "Bridge");

    dbg_utils_print_field(file, "sx bridge id", sx_bridge_id, PARAM_UINT16_E);
    dbg_utils_print(file, "\n");
}

void SAI_dump_tunnel(_In_ FILE *file)
{
    mlnx_tunnel_map_entry_t *mlnx_tunnel_map_entry = NULL;
    mlnx_tunnel_map_t       *mlnx_tunnel_map       = NULL;
    tunnel_db_entry_t       *tunnel_db             = NULL;
    mlnx_tunneltable_t      *mlnx_tunneltable      = NULL;
    sx_bridge_id_t           sx_bridge_id          = 0;

    mlnx_tunnel_map_entry =
        (mlnx_tunnel_map_entry_t*)calloc(MLNX_TUNNEL_MAP_ENTRY_MAX, sizeof(mlnx_tunnel_map_entry_t));
    mlnx_tunnel_map  = (mlnx_tunnel_map_t*)calloc(MLNX_TUNNEL_MAP_MAX, sizeof(mlnx_tunnel_map_t));
    tunnel_db        = (tunnel_db_entry_t*)calloc(MAX_TUNNEL_DB_SIZE, sizeof(tunnel_db_entry_t));
    mlnx_tunneltable = (mlnx_tunneltable_t*)calloc(MLNX_TUNNELTABLE_SIZE, sizeof(mlnx_tunneltable_t));
    if ((!mlnx_tunnel_map_entry) || (!mlnx_tunnel_map) || (!tunnel_db) || (!mlnx_tunneltable)) {
        if (mlnx_tunnel_map_entry) {
            free(mlnx_tunnel_map_entry);
        }
        if (mlnx_tunnel_map) {
            free(mlnx_tunnel_map);
        }
        if (tunnel_db) {
            free(tunnel_db);
        }
        if (mlnx_tunneltable) {
            free(mlnx_tunneltable);
        }
        return;
    }

    SAI_dump_tunnel_getdb(mlnx_tunnel_map_entry,
                          mlnx_tunnel_map,
                          tunnel_db,
                          mlnx_tunneltable,
                          &sx_bridge_id);
    dbg_utils_print_module_header(file, "SAI Tunnel");
    SAI_dump_tunnel_map_entry_print(file, mlnx_tunnel_map_entry);
    SAI_dump_tunnel_map_print(file, mlnx_tunnel_map, mlnx_tunnel_map_entry);
    SAI_dump_tunnel_print(file, tunnel_db);
    SAI_dump_tunnel_table_print(file, mlnx_tunneltable);
    SAI_dump_bridge_print(file, &sx_bridge_id);

    free(mlnx_tunnel_map_entry);
    free(mlnx_tunnel_map);
    free(tunnel_db);
    free(mlnx_tunneltable);
}
