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

acl_group_db_t* sai_acl_db_group_ptr(_In_ uint32_t group_index);
acl_group_bound_to_t* sai_acl_db_group_bount_to(_In_ uint32_t group_index);
static void SAI_dump_acl_getdb(_Out_ acl_table_db_t       *acl_table_db,
                               _Out_ acl_entry_db_t       *acl_entry_db,
                               _Out_ acl_setting_tbl_t    *acl_settings_tbl,
                               _Out_ acl_pbs_map_entry_t  *acl_pbs_map_db,
                               _Out_ acl_bind_points_db_t *acl_bind_points,
                               _Out_ acl_group_db_t       *acl_group_db,
                               _Out_ acl_vlan_group_t     *acl_vlan_group,
                               _Out_ acl_group_bound_to_t *acl_group_bound_to)
{
    assert(NULL != acl_table_db);
    assert(NULL != acl_entry_db);
    assert(NULL != acl_settings_tbl);
    assert(NULL != acl_pbs_map_db);
    assert(NULL != acl_bind_points);
    assert(NULL != acl_group_db);
    assert(NULL != acl_vlan_group);
    assert(NULL != acl_group_bound_to);
    assert(NULL != g_sai_acl_db_ptr);

    acl_global_lock();

    memcpy(acl_table_db,
           g_sai_acl_db_ptr->acl_table_db,
           ACL_TABLE_DB_SIZE * sizeof(acl_table_db_t));

    memcpy(acl_entry_db,
           g_sai_acl_db_ptr->acl_entry_db,
           ACL_ENTRY_DB_SIZE * sizeof(acl_entry_db_t));

    memcpy(acl_settings_tbl,
           g_sai_acl_db_ptr->acl_settings_tbl,
           sizeof(acl_setting_tbl_t));

    memcpy(acl_pbs_map_db,
           g_sai_acl_db_ptr->acl_pbs_map_db,
           sizeof(acl_pbs_map_entry_t) *
           (ACL_PBS_MAP_PREDEF_REG_SIZE + g_sai_acl_db_pbs_map_size));

    memcpy(acl_bind_points,
           g_sai_acl_db_ptr->acl_bind_points,
           sizeof(acl_bind_points_db_t) + sizeof(acl_bind_point_t) * ACL_RIF_COUNT);

    memcpy(acl_group_db,
           g_sai_acl_db_ptr->acl_groups_db,
           (sizeof(acl_group_db_t) + sizeof(acl_group_member_t) * ACL_GROUP_SIZE) * ACL_GROUP_NUMBER);

    memcpy(acl_vlan_group,
           g_sai_acl_db_ptr->acl_vlan_groups_db,
           sizeof(acl_vlan_group_t) * ACL_VLAN_GROUP_COUNT);

    memcpy(acl_group_bound_to,
           g_sai_acl_db_ptr->acl_group_bound_to_db,
           (sizeof(acl_group_bound_to_t) + (sizeof(acl_bind_point_index_t) * SAI_ACL_MAX_BIND_POINT_BOUND))
           * ACL_GROUP_NUMBER);

    acl_global_unlock();
}

static void SAI_dump_acl_stage_enum_to_str(_In_ sai_acl_stage_t stage_type, _Out_ char *str)
{
    assert(NULL != str);

    switch (stage_type) {
    case SAI_ACL_STAGE_INGRESS:
        strcpy(str, "ingress");
        break;

    case SAI_ACL_STAGE_EGRESS:
        strcpy(str, "egress");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_table_group_type_enum_to_str(_In_ sai_acl_table_group_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL:
        strcpy(str, "sequential");
        break;

    case SAI_ACL_TABLE_GROUP_TYPE_PARALLEL:
        strcpy(str, "parallel");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_key_type_enum_to_str(_In_ sx_acl_key_type_t key_type, _Out_ char *str)
{
    assert(NULL != str);

    switch (key_type) {
    case SX_ACL_KEY_TYPE_IPV4_FULL:
        strcpy(str, "ipv4");
        break;

    case SX_ACL_KEY_TYPE_IPV6_FULL:
        strcpy(str, "ipv6");
        break;

    case SX_ACL_KEY_TYPE_MAC_FULL:
        strcpy(str, "mac");
        break;

    case SX_ACL_KEY_TYPE_MAC_IPV4_FULL:
        strcpy(str, "mac ipv4");
        break;

    case SX_ACL_KEY_TYPE_FCOE_FULL:
        strcpy(str, "fcoe");
        break;

    case SX_ACL_KEY_TYPE_MAC_SHORT:
        strcpy(str, "mac short");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_range_type_enum_to_str(_In_ sai_acl_range_type_t range_type, _Out_ char *str)
{
    assert(NULL != str);

    switch (range_type) {
    case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
        strcpy(str, "l4 src port range");
        break;

    case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
        strcpy(str, "l4 dst port range");
        break;

    case SAI_ACL_RANGE_TYPE_OUTER_VLAN:
        strcpy(str, "outer vlan");
        break;

    case SAI_ACL_RANGE_TYPE_INNER_VLAN:
        strcpy(str, "inner vlan");
        break;

    case SAI_ACL_RANGE_TYPE_PACKET_LENGTH:
        strcpy(str, "packet length");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_table_print(_In_ FILE *file, _In_ acl_table_db_t *acl_table_db)
{
    uint32_t                  ii     = 0;
    uint32_t                  jj     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    acl_table_db_t            curr_acl_table_db;
    char                      stage_str[LINE_LENGTH];
    char                      key_type_str[LINE_LENGTH];
    char                      range_type_str[LINE_LENGTH];
    char                      group_type_str[LINE_LENGTH];
    dbg_utils_table_columns_t acl_table_clmns[] = {
        {"sai oid",           16, PARAM_UINT64_E, &obj_id},
        {"db idx",            13, PARAM_UINT32_E, &ii},
        {"is lock inited",    14, PARAM_UINT8_E,  &curr_acl_table_db.is_lock_inited},
        {"queued",            13, PARAM_UINT32_E, &curr_acl_table_db.queued},
        {"group type",        13, PARAM_STRING_E, &group_type_str},
        {"group refs",        13, PARAM_UINT32_E, &curr_acl_table_db.group_references},
        {"table id",          13, PARAM_UINT32_E, &curr_acl_table_db.table_id},
        {"stage",             14, PARAM_STRING_E, &stage_str},
        {"region id",         13, PARAM_UINT32_E, &curr_acl_table_db.region_id},
        {"region size",       13, PARAM_UINT32_E, &curr_acl_table_db.region_size},
        {"key type",          9,  PARAM_STRING_E, &key_type_str},
        {"is dynamic sized",  16, PARAM_UINT8_E,   &curr_acl_table_db.is_dynamic_sized},
        {"created entry cnt", 16, PARAM_UINT32_E, &curr_acl_table_db.created_entry_count},
        {"psort handle",      16, PARAM_UINT32_E, &curr_acl_table_db.psort_handle},
        {"range type count",  16, PARAM_UINT32_E, &curr_acl_table_db.range_type_count},
        {"bind type count",   16, PARAM_UINT32_E, &curr_acl_table_db.bind_point_types.count},
        {"wrap group created", 16, PARAM_UINT8_E,   &curr_acl_table_db.wrapping_group.created},
        {"wrap group sx id",  16, PARAM_UINT32_E, &curr_acl_table_db.wrapping_group.sx_group_id},
        {"def_rules_offset",  16, PARAM_UINT16_E, &curr_acl_table_db.def_rules_offset},
        {"def_rule_key",      16, PARAM_UINT32_E, &curr_acl_table_db.def_rule_key},
        {NULL,                0,  0,              NULL}
    };
    dbg_utils_table_columns_t range_types_clmns[] = {
        {"db idx",     13, PARAM_UINT32_E, &jj},
        {"range type", 17, PARAM_STRING_E, &range_type_str},
        {NULL,         0,  0,              NULL}
    };

    assert(NULL != acl_table_db);

    dbg_utils_print_general_header(file, "ACL table");

    dbg_utils_print_secondary_header(file, "acl_table_db");

    dbg_utils_print_table_headline(file, acl_table_clmns);

    for (ii = 0; ii < ACL_TABLE_DB_SIZE; ii++) {
        if (acl_table_db[ii].is_used) {
            memcpy(&curr_acl_table_db, &acl_table_db[ii], sizeof(acl_table_db_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            SAI_dump_acl_stage_enum_to_str(acl_table_db[ii].stage, stage_str);

            SAI_dump_acl_key_type_enum_to_str(acl_table_db[ii].key_type, key_type_str);

            SAI_dump_acl_table_group_type_enum_to_str(acl_table_db[ii].group_type, group_type_str);

            dbg_utils_print_table_data_line(file, acl_table_clmns);

            dbg_utils_print_secondary_header(file, "acl table %d range types", ii);

            dbg_utils_print_table_headline(file, range_types_clmns);

            for (jj = 0; jj < acl_table_db[ii].range_type_count; jj++) {
                SAI_dump_acl_range_type_enum_to_str(acl_table_db[ii].range_types[jj],
                                                    range_type_str);

                dbg_utils_print_table_data_line(file, range_types_clmns);
            }
        }
    }
}

static void SAI_dump_acl_sx_direction_type_enum_to_str(_In_ sx_acl_direction_t sx_direction, _Out_ char *str)
{
    assert(NULL != str);

    switch (sx_direction) {
    case SX_ACL_DIRECTION_INGRESS:
        strcpy(str, "INGRESS");
        break;

    case SX_ACL_DIRECTION_EGRESS:
        strcpy(str, "EGRESS");
        break;

    case SX_ACL_DIRECTION_RIF_INGRESS:
        strcpy(str, "RIF_INGRESS");
        break;

    case SX_ACL_DIRECTION_RIF_EGRESS:
        strcpy(str, "RIF_EGRESS");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_bind_point_type_enum_to_str(_In_ sai_acl_bind_point_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SAI_ACL_BIND_POINT_TYPE_PORT:
        strcpy(str, "PORT");
        break;

    case SAI_ACL_BIND_POINT_TYPE_LAG:
        strcpy(str, "LAG");
        break;

    case SAI_ACL_BIND_POINT_TYPE_VLAN:
        strcpy(str, "VLAN");
        break;

    case SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF:
        strcpy(str, "ROUTER_INTF");
        break;

    case SAI_ACL_BIND_POINT_TYPE_SWITCH:
        strcpy(str, "SWITCH");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_acl_entry_print(_In_ FILE *file, _In_ acl_entry_db_t *acl_entry_db)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    acl_entry_db_t            curr_acl_entry_db;
    dbg_utils_table_columns_t acl_entry_clmns[] = {
        {"sai obj id",           13, PARAM_UINT64_E, &obj_id},
        {"db idx",               11, PARAM_UINT32_E, &ii},
        {"offset",               6,  PARAM_UINT16_E, &curr_acl_entry_db.offset},
        {"sx prio",              13, PARAM_UINT16_E, &curr_acl_entry_db.sx_prio},
        {"pbs index",            13, PARAM_UINT16_E, &curr_acl_entry_db.pbs_index},
        {NULL,                   0,  0,              NULL}
    };

    assert(NULL != acl_entry_db);

    dbg_utils_print_general_header(file, "ACL entry");

    dbg_utils_print_secondary_header(file, "acl_entry_db");

    dbg_utils_print_table_headline(file, acl_entry_clmns);

    for (ii = 0; ii < ACL_ENTRY_DB_SIZE; ii++) {
        if (acl_entry_db[ii].is_used) {
            memcpy(&curr_acl_entry_db, &acl_entry_db[ii], sizeof(acl_entry_db_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_ACL_ENTRY, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            dbg_utils_print_table_data_line(file, acl_entry_clmns);
        }
    }
}

static void SAI_dump_acl_settings_tbl_print(_In_ FILE *file, _In_ acl_setting_tbl_t *acl_setting_tbl)
{
    acl_setting_tbl_t         curr_acl_setting_tbl;
    dbg_utils_table_columns_t acl_settings_clmns[] = {
        {"initialized",                  11, PARAM_UINT8_E,   &curr_acl_setting_tbl.lazy_initialized},
        {"psort_thread_start_flag",      27, PARAM_UINT8_E,   &curr_acl_setting_tbl.psort_thread_start_flag},
        {"rpc_thread_start_flag",        21, PARAM_UINT8_E,   &curr_acl_setting_tbl.rpc_thread_start_flag},
        {"psort_thread_stop_flag",       7,  PARAM_UINT8_E,   &curr_acl_setting_tbl.psort_thread_stop_flag},
        {"rpc_thread_stop_flag",         7,  PARAM_UINT8_E,   &curr_acl_setting_tbl.rpc_thread_stop_flag},
        {"psort_thread_suspended",       7,  PARAM_UINT8_E,   &curr_acl_setting_tbl.psort_thread_suspended},
        {"port lists count",             16, PARAM_UINT32_E, &curr_acl_setting_tbl.port_lists_count},
        {NULL,                           0,  0,              NULL}
    };

    assert(NULL != acl_setting_tbl);

    dbg_utils_print_general_header(file, "ACL settings");

    dbg_utils_print_secondary_header(file, "acl_setting_tbl");

    dbg_utils_print_table_headline(file, acl_settings_clmns);

    memcpy(&curr_acl_setting_tbl, acl_setting_tbl, sizeof(acl_setting_tbl_t));

    dbg_utils_print_table_data_line(file, acl_settings_clmns);
}

static void SAI_dump_acl_pbs_entry_type_get(_In_ acl_pbs_index_t pbs_index, _Out_ char          *type)
{
    if (ACL_PBS_FLOOD_PBS_INDEX == pbs_index) {
        strcpy(type, "flood");
        return;
    }

    if (ACL_PBS_INDEX_IS_TRIVIAL(pbs_index)) {
        strcpy(type, "single port");
        return;
    }

    strcpy(type, "regular");
}

static void SAI_dump_acl_pbs_entry_key_str_get(_In_ const acl_pbs_map_key_t *key,
                                               _Out_ char                   *key_str)
{
    uint32_t ii;

    assert(key);
    assert(key_str);

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (array_bit_test(key->data, ii)) {
            key_str[ii] = '1';
        } else {
            key_str[ii] = '0';
        }
    }

    key_str[ii] = '\0';
}

static void SAI_dump_acl_pbs_map_db_print(_In_ FILE *file, _In_ acl_pbs_map_entry_t *pbs_map_db)
{
    acl_pbs_map_entry_t       curr_pbs_entry;
    acl_pbs_index_t           ii;
    char                      pbs_entry_type[LINE_LENGTH]   = {0};
    char                      pbs_key[MAX_PORTS_DB * 2 + 1] = {0};
    dbg_utils_table_columns_t acl_pbs_map_clmns[]           = {
        {"idx",               7, PARAM_UINT16_E, &ii},
        {"type",             13, PARAM_STRING_E, &pbs_entry_type},
        {"key",  MAX_PORTS_DB * 2, PARAM_STRING_E, &pbs_key},
        {"sx id",            10, PARAM_UINT32_E, &curr_pbs_entry.pbs_id},
        {"refs",             10, PARAM_UINT32_E, &curr_pbs_entry.ref_counter},
        {NULL,               0,               0, NULL}
    };

    assert(pbs_map_db);

    dbg_utils_print_general_header(file, "ACL PBS DB");

    dbg_utils_print_table_headline(file, acl_pbs_map_clmns);

    for (ii = 0; ii < ACL_PBS_MAP_PREDEF_REG_SIZE + g_sai_acl_db_pbs_map_size; ii++) {
        if (g_sai_acl_db_ptr->acl_pbs_map_db[ii].ref_counter > 0) {
            memcpy(&curr_pbs_entry, &g_sai_acl_db_ptr->acl_pbs_map_db[ii], sizeof(curr_pbs_entry));

            SAI_dump_acl_pbs_entry_type_get(ii, pbs_entry_type);
            SAI_dump_acl_pbs_entry_key_str_get(&curr_pbs_entry.key, pbs_key);

            dbg_utils_print_table_data_line(file, acl_pbs_map_clmns);
        }
    }
}

static bool SAI_dump_acl_bind_point_data_is_set(_In_ const acl_bind_point_data_t *curr_acl_bind_point_data)
{
    if ((false == curr_acl_bind_point_data->is_object_set) &&
        (false == curr_acl_bind_point_data->is_sx_group_created)) {
        return false;
    }

    return true;
}

static bool SAI_dump_acl_bind_point_is_set(_In_ const acl_bind_point_t *curr_acl_bind_point)
{
    return (SAI_dump_acl_bind_point_data_is_set(&curr_acl_bind_point->ingress_data) ||
            SAI_dump_acl_bind_point_data_is_set(&curr_acl_bind_point->egress_data));
}

static void SAI_dump_acl_bind_points_data_print(_In_ FILE *file, _In_ acl_bind_point_data_t *curr_acl_bind_point_data)
{
    char                      acl_object_type_str[LINE_LENGTH]   = {0};
    char                      sx_direction_type_str[LINE_LENGTH] = {0};
    char                      acl_bind_point_type[LINE_LENGTH]   = {0};
    uint32_t                  target_sx_id;
    dbg_utils_table_columns_t acl_bind_points_data_clmns[] = {
        {"is object set",       16, PARAM_UINT8_E,   &curr_acl_bind_point_data->is_object_set},
        {"is sx group created", 16, PARAM_UINT8_E,   &curr_acl_bind_point_data->is_sx_group_created},
        {"acl db index",        19, PARAM_UINT32_E, &curr_acl_bind_point_data->acl_index.acl_db_index},
        {"acl object type",     15, PARAM_STRING_E, acl_object_type_str},
        {"sx group",            19, PARAM_UINT32_E, &curr_acl_bind_point_data->sx_group},
        {"target is set",       19, PARAM_UINT8_E,   &curr_acl_bind_point_data->target_data.is_set},
        {"target sx direction", 19, PARAM_STRING_E, &sx_direction_type_str},
        {"target bind type",    19, PARAM_STRING_E, &acl_bind_point_type},
        {"target sx id",        19, PARAM_UINT32_E, &target_sx_id},
        {NULL,                  0,  0,              NULL}
    };

    assert(NULL != curr_acl_bind_point_data);

    dbg_utils_print_secondary_header(file, "ACL bind point data");

    dbg_utils_print_table_headline(file, acl_bind_points_data_clmns);

    assert(LINE_LENGTH > strlen(SAI_TYPE_STR(curr_acl_bind_point_data->acl_index.acl_object_type)) + 1);

    strncpy(acl_object_type_str, SAI_TYPE_STR(curr_acl_bind_point_data->acl_index.acl_object_type), LINE_LENGTH);
    acl_object_type_str[LINE_LENGTH - 1] = 0;

    SAI_dump_acl_sx_direction_type_enum_to_str(curr_acl_bind_point_data->target_data.sx_direction,
                                               sx_direction_type_str);

    SAI_dump_acl_bind_point_type_enum_to_str(curr_acl_bind_point_data->target_data.sai_bind_point_type,
                                             acl_bind_point_type);

    switch (curr_acl_bind_point_data->target_data.sai_bind_point_type) {
    case SAI_ACL_BIND_POINT_TYPE_PORT:
    case SAI_ACL_BIND_POINT_TYPE_LAG:
    case SAI_ACL_BIND_POINT_TYPE_SWITCH:
        target_sx_id = curr_acl_bind_point_data->target_data.sx_port;
        break;

    case SAI_ACL_BIND_POINT_TYPE_VLAN:
        target_sx_id = curr_acl_bind_point_data->target_data.vlan_group;
        break;

    case SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF:
        target_sx_id = curr_acl_bind_point_data->target_data.rif;
        break;

    default:
        target_sx_id = -1;
    }

    dbg_utils_print_table_data_line(file, acl_bind_points_data_clmns);
}

static void SAI_dump_acl_bind_point_print(_In_ FILE *file, _In_ acl_bind_point_t *curr_acl_bind_point)
{
    if (SAI_dump_acl_bind_point_data_is_set(&curr_acl_bind_point->ingress_data)) {
        dbg_utils_print_secondary_header(file, "Ingress");

        SAI_dump_acl_bind_points_data_print(file, &curr_acl_bind_point->ingress_data);
    }

    if (SAI_dump_acl_bind_point_data_is_set(&curr_acl_bind_point->egress_data)) {
        dbg_utils_print_secondary_header(file, "Egress");

        SAI_dump_acl_bind_points_data_print(file, &curr_acl_bind_point->egress_data);
    }
}

static void SAI_dump_acl_bind_points_print(_In_ FILE *file, _In_ acl_bind_points_db_t *acl_bind_points)
{
    uint32_t ii = 0;

    assert(NULL != acl_bind_points);

    dbg_utils_print_general_header(file, "ACL bind points");

    dbg_utils_print_secondary_header(file, "Ports & LAGs");

    for (ii = 0; ii < MAX_PORTS; ii++) {
        if (SAI_dump_acl_bind_point_is_set(&acl_bind_points->ports_lags[ii])) {
            dbg_utils_print_secondary_header(file, "Port %d", ii);

            SAI_dump_acl_bind_point_print(file, &acl_bind_points->ports_lags[ii]);
        }
    }

    for (ii = MAX_PORTS; ii < MAX_PORTS * 2; ii++) {
        if (SAI_dump_acl_bind_point_is_set(&acl_bind_points->ports_lags[ii])) {
            dbg_utils_print_secondary_header(file, "LAG %d", ii);

            SAI_dump_acl_bind_point_print(file, &acl_bind_points->ports_lags[ii]);
        }
    }

    dbg_utils_print_secondary_header(file, "VLANs");

    for (ii = 0; ii < ACL_VLAN_COUNT; ii++) {
        if (acl_bind_points->vlans[ii].is_bound) {
            dbg_utils_print_secondary_header(file, "VLAN %d. VLAN Group index - %d", ii,
                                             acl_bind_points->vlans[ii].vlan_group_index);
        }
    }

    dbg_utils_print_secondary_header(file, "RIFs");

    for (ii = 0; ii < ACL_RIF_COUNT; ii++) {
        if (SAI_dump_acl_bind_point_is_set(&acl_bind_points->rifs[ii])) {
            dbg_utils_print_secondary_header(file, "RIF %d", ii);

            SAI_dump_acl_bind_point_print(file, &acl_bind_points->rifs[ii]);
        }
    }
}

static void SAI_dump_acl_groups_db_print(_In_ FILE                 *file,
                                         _In_ acl_group_db_t       *acl_groups_db,
                                         _In_ acl_group_bound_to_t *acl_group_bound_to)
{
    char                      acl_table_group_type_str[LINE_LENGTH] = {0};
    char                      acl_stage_type_str[LINE_LENGTH]       = {0};
    char                      acl_bind_point_type_str[LINE_LENGTH]  = {0};
    acl_group_db_t            current_acl_group;
    sai_object_id_t           obj_id;
    uint32_t                  table_index, table_prio, group_bound_to_count, bind_point_index;
    uint32_t                  ii, jj;
    dbg_utils_table_columns_t acl_group_clmns[] = {
        {"db idx",              7, PARAM_UINT32_E, &ii},
        {"sai obj id",          13, PARAM_UINT64_E, &obj_id},
        {"search type",         15, PARAM_STRING_E, acl_table_group_type_str},
        {"stage",               10, PARAM_STRING_E, acl_stage_type_str},
        {"bound to",            15, PARAM_UINT32_E, &group_bound_to_count},
        {"members count",       15, PARAM_UINT32_E, &current_acl_group.members_count},
        {"bind point types",    19, PARAM_UINT32_E, &current_acl_group.bind_point_types.count},
        {NULL,                  0,  0,              NULL}
    };
    dbg_utils_table_columns_t acl_group_bind_point_types_clmns[] = {
        {"idx",  7,  PARAM_UINT32_E, &jj},
        {"type", 13, PARAM_STRING_E, acl_bind_point_type_str},
        {NULL,   0,  0,              NULL}
    };
    dbg_utils_table_columns_t acl_group_members_clmns[] = {
        {"table index",  7,  PARAM_UINT32_E, &table_index},
        {"table prio",   13, PARAM_UINT32_E, &table_prio},
        {NULL,           0,  0,              NULL}
    };
    dbg_utils_table_columns_t acl_group_bind_point_index_clmns[] = {
        {"type",  13,  PARAM_STRING_E, acl_bind_point_type_str},
        {"index", 7,  PARAM_UINT32_E, &bind_point_index},
        {NULL,    0,  0,              NULL}
    };

    assert(NULL != acl_groups_db);
    assert(NULL != acl_group_bound_to);

    dbg_utils_print_general_header(file, "ACL Groups");

    for (ii = 0; ii < ACL_GROUP_NUMBER; ii++) {
        if (sai_acl_db_group_ptr(ii)->is_used) {
            memcpy(&current_acl_group, sai_acl_db_group_ptr(ii), sizeof(acl_group_db_t));

            SAI_dump_acl_table_group_type_enum_to_str(current_acl_group.search_type, acl_table_group_type_str);
            SAI_dump_acl_stage_enum_to_str(current_acl_group.stage, acl_stage_type_str);
            group_bound_to_count = sai_acl_db_group_bount_to(ii)->count;

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            dbg_utils_print_secondary_header(file, "Group [%d]", ii);

            dbg_utils_print_table_headline(file, acl_group_clmns);

            dbg_utils_print_table_data_line(file, acl_group_clmns);

            dbg_utils_print_secondary_header(file, "List of allowed bind point types");

            dbg_utils_print_table_headline(file, acl_group_bind_point_types_clmns);

            for (jj = 0; jj < current_acl_group.bind_point_types.count; jj++) {
                SAI_dump_acl_bind_point_type_enum_to_str(current_acl_group.bind_point_types.types[jj],
                                                         acl_bind_point_type_str);

                dbg_utils_print_table_data_line(file, acl_group_bind_point_types_clmns);
            }

            if (current_acl_group.members_count > 0) {
                dbg_utils_print_secondary_header(file, "Group members");

                dbg_utils_print_table_headline(file, acl_group_bind_point_types_clmns);

                for (jj = 0; jj < current_acl_group.members_count; jj++) {
                    table_index = sai_acl_db_group_ptr(ii)->members[jj].table_index;
                    table_prio  = sai_acl_db_group_ptr(ii)->members[jj].table_prio;

                    dbg_utils_print_table_data_line(file, acl_group_members_clmns);
                }
            }

            if (group_bound_to_count > 0) {
                dbg_utils_print_secondary_header(file, "Group is bound to");

                dbg_utils_print_table_headline(file, acl_group_bind_point_index_clmns);

                for (jj = 0; jj < group_bound_to_count; jj++) {
                    SAI_dump_acl_bind_point_type_enum_to_str(sai_acl_db_group_bount_to(ii)->indexes[jj].type,
                                                             acl_bind_point_type_str);

                    bind_point_index = sai_acl_db_group_bount_to(ii)->indexes[jj].index;

                    dbg_utils_print_table_data_line(file, acl_group_bind_point_index_clmns);
                }
            }
        }
    }
}

static void SAI_dump_acl_vlan_groups_db_print(_In_ FILE *file, _In_ acl_vlan_group_t *acl_vlan_group)
{
    acl_vlan_group_t          current_vlan_group;
    uint32_t                  ii;
    dbg_utils_table_columns_t acl_vlan_group_clmns[] = {
        {"idx",             7,  PARAM_UINT32_E, &ii},
        {"vlan count",      10,  PARAM_UINT32_E, &current_vlan_group.vlan_count},
        {"sx vlan group",   15, PARAM_UINT16_E, &current_vlan_group.sx_vlan_group},
        {NULL,              0,  0,              NULL}
    };

    assert(NULL != acl_vlan_group);

    dbg_utils_print_general_header(file, "ACL VLAN Groups");

    for (ii = 0; ii < ACL_VLAN_GROUP_COUNT; ii++) {
        if (acl_vlan_group[ii].vlan_count > 0) {
            memcpy(&current_vlan_group, &acl_vlan_group[ii], sizeof(acl_vlan_group_t));

            dbg_utils_print_secondary_header(file, "VLAN Group [%d]", ii);

            dbg_utils_print_table_headline(file, acl_vlan_group_clmns);

            dbg_utils_print_table_data_line(file, acl_vlan_group_clmns);

            SAI_dump_acl_bind_points_data_print(file, &acl_vlan_group[ii].bind_data);
        }
    }
}


void SAI_dump_acl(_In_ FILE *file)
{
    acl_table_db_t       *acl_table_db       = NULL;
    acl_entry_db_t       *acl_entry_db       = NULL;
    acl_setting_tbl_t    *acl_settings_tbl   = NULL;
    acl_pbs_map_entry_t  *acl_pbs_map_db     = NULL;
    acl_bind_points_db_t *acl_bind_points    = NULL;
    acl_group_db_t       *acl_group_db       = NULL;
    acl_vlan_group_t     *acl_vlan_group     = NULL;
    acl_group_bound_to_t *acl_group_bound_to = NULL;

    acl_table_db     = (acl_table_db_t*)calloc(ACL_TABLE_DB_SIZE, sizeof(acl_table_db_t));
    acl_entry_db     = (acl_entry_db_t*)calloc(ACL_ENTRY_DB_SIZE, sizeof(acl_entry_db_t));
    acl_settings_tbl = (acl_setting_tbl_t*)calloc(1, sizeof(acl_setting_tbl_t));
    acl_pbs_map_db   = (acl_pbs_map_entry_t*)calloc(ACL_PBS_MAP_PREDEF_REG_SIZE + g_sai_acl_db_pbs_map_size,
                                                    sizeof(acl_pbs_map_entry_t));
    acl_bind_points = (acl_bind_points_db_t*)calloc(1, sizeof(acl_bind_points_db_t) +
                                                    sizeof(acl_bind_point_t) * ACL_RIF_COUNT);
    acl_group_db = (acl_group_db_t*)calloc(ACL_GROUP_NUMBER,
                                           sizeof(acl_group_db_t) + sizeof(acl_group_member_t) * ACL_GROUP_SIZE);
    acl_vlan_group     = (acl_vlan_group_t*)calloc(ACL_VLAN_GROUP_COUNT, sizeof(acl_vlan_group_t));
    acl_group_bound_to = (acl_group_bound_to_t*)calloc(ACL_GROUP_NUMBER, sizeof(acl_group_bound_to_t) +
                                                       (sizeof(acl_bind_point_index_t) *
                                                        SAI_ACL_MAX_BIND_POINT_BOUND));

    if ((!acl_table_db) || (!acl_entry_db) ||
        (!acl_settings_tbl) || (!acl_pbs_map_db) || (!acl_bind_points) ||
        (!acl_group_db) || (!acl_vlan_group) || !(acl_group_bound_to)) {
        goto cleanup;
    }

    SAI_dump_acl_getdb(acl_table_db,
                       acl_entry_db,
                       acl_settings_tbl,
                       acl_pbs_map_db,
                       acl_bind_points,
                       acl_group_db,
                       acl_vlan_group,
                       acl_group_bound_to);

    dbg_utils_print_module_header(file, "SAI ACL");

    if (false == acl_settings_tbl->lazy_initialized) {
        dbg_utils_print_general_header(file, "SAI ACL DB is not initialized\n");
        goto cleanup;
    }

    SAI_dump_acl_table_print(file, acl_table_db);
    SAI_dump_acl_entry_print(file, acl_entry_db);
    SAI_dump_acl_settings_tbl_print(file, acl_settings_tbl);
    SAI_dump_acl_pbs_map_db_print(file, acl_pbs_map_db);
    SAI_dump_acl_bind_points_print(file, acl_bind_points);
    SAI_dump_acl_groups_db_print(file, acl_group_db, acl_group_bound_to);
    SAI_dump_acl_vlan_groups_db_print(file, acl_vlan_group);

cleanup:
    free(acl_table_db);
    free(acl_entry_db);
    free(acl_settings_tbl);
    free(acl_pbs_map_db);
    free(acl_bind_points);
    free(acl_group_db);
    free(acl_vlan_group);
    free(acl_group_bound_to);
}
