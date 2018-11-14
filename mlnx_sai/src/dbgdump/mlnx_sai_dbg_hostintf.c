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

static void SAI_dump_hostintf_getdb(_Out_ sai_object_id_t  *default_trap_group,
                                    _Out_ bool             *trap_group_valid,
                                    _Out_ mlnx_trap_t      *traps_db,
                                    _Out_ trap_mirror_db_t *trap_mirror_discard_wred_db,
                                    _Out_ trap_mirror_db_t *trap_mirror_discard_router_db,
                                    _Out_ sai_netdev_t     *hostif_db)
{
    assert(NULL != default_trap_group);
    assert(NULL != trap_group_valid);
    assert(NULL != traps_db);
    assert(NULL != trap_mirror_discard_wred_db);
    assert(NULL != trap_mirror_discard_router_db);
    assert(NULL != hostif_db);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    *default_trap_group = g_sai_db_ptr->default_trap_group,

    memcpy(trap_group_valid,
           g_sai_db_ptr->trap_group_valid,
           MAX_TRAP_GROUPS * sizeof(bool));

    memcpy(traps_db,
           g_sai_db_ptr->traps_db,
           SXD_TRAP_ID_ACL_MAX * sizeof(mlnx_trap_t));

    memcpy(trap_mirror_discard_wred_db,
           &g_sai_db_ptr->trap_mirror_discard_wred_db,
           sizeof(trap_mirror_db_t));

    memcpy(trap_mirror_discard_router_db,
           &g_sai_db_ptr->trap_mirror_discard_router_db,
           sizeof(trap_mirror_db_t));

    memcpy(hostif_db,
           g_sai_db_ptr->hostif_db,
           sizeof(g_sai_db_ptr->hostif_db));

    sai_db_unlock();
}

static void SAI_dump_default_trap_group_print(_In_ FILE *file, _In_ sai_object_id_t *default_trap_group)
{
    assert(NULL != default_trap_group);

    dbg_utils_print_general_header(file, "Default trap group");

    dbg_utils_print_field(file, "default trap group", default_trap_group, PARAM_UINT64_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_trap_group_valid_print(_In_ FILE *file, _In_ bool *trap_group_valid)
{
    uint32_t                  ii                       = 0;
    uint32_t                  curr_trap_group_valid    = 0;
    dbg_utils_table_columns_t trap_group_valid_clmns[] = {
        {"db idx",           11, PARAM_UINT32_E, &ii},
        {"trap group valid", 16, PARAM_BOOL_E,   &curr_trap_group_valid},
        {NULL,               0,  0,              NULL}
    };

    assert(NULL != trap_group_valid);

    dbg_utils_print_general_header(file, "Trap group valid");

    dbg_utils_print_secondary_header(file, "trap_group_valid");

    dbg_utils_print_table_headline(file, trap_group_valid_clmns);

    for (ii = 0; ii < MAX_TRAP_GROUPS; ii++) {
        curr_trap_group_valid = trap_group_valid[ii];
        dbg_utils_print_table_data_line(file, trap_group_valid_clmns);
    }
}

static void SAI_dump_action_enum_to_str(_In_ sai_packet_action_t action, _Out_ char *str)
{
    assert(NULL != str);

    switch (action) {
    case SAI_PACKET_ACTION_DROP:
        strcpy(str, "drop");
        break;

    case SAI_PACKET_ACTION_FORWARD:
        strcpy(str, "forward");
        break;

    case SAI_PACKET_ACTION_COPY:
        strcpy(str, "copy");
        break;

    case SAI_PACKET_ACTION_COPY_CANCEL:
        strcpy(str, "copy cancel");
        break;

    case SAI_PACKET_ACTION_TRAP:
        strcpy(str, "trap");
        break;

    case SAI_PACKET_ACTION_LOG:
        strcpy(str, "log");
        break;

    case SAI_PACKET_ACTION_DENY:
        strcpy(str, "deny");
        break;

    case SAI_PACKET_ACTION_TRANSIT:
        strcpy(str, "transit");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_traps_db_print(_In_ FILE *file, _In_ mlnx_trap_t *traps_db)
{
    uint32_t                  ii = 0;
    char                      action_str[LINE_LENGTH];
    mlnx_trap_t               curr_traps_db;
    dbg_utils_table_columns_t traps_db_clmns[] = {
        {"db idx",       7,  PARAM_UINT32_E, &ii},
        {"action",       16, PARAM_STRING_E, &action_str},
        {"trap group",   16, PARAM_UINT64_E, &curr_traps_db.trap_group},
        {NULL,           0,  0,              NULL}
    };

    assert(NULL != traps_db);

    dbg_utils_print_general_header(file, "Traps db");

    dbg_utils_print_secondary_header(file, "traps_db");

    dbg_utils_print_table_headline(file, traps_db_clmns);

    for (ii = 0; ii < SXD_TRAP_ID_ACL_MAX; ii++) {
        memcpy(&curr_traps_db, &traps_db[ii], sizeof(mlnx_trap_t));

        SAI_dump_action_enum_to_str(traps_db[ii].action,
                                    action_str);

        dbg_utils_print_table_data_line(file, traps_db_clmns);
    }
}

static void SAI_dump_hostif_subtype_enum_to_str(_In_ sai_host_object_type_t subtype, _Out_ char *str)
{
    assert(NULL != str);

    switch (subtype) {
    case SAI_HOSTIF_OBJECT_TYPE_VLAN:
        strcpy(str, "vlan");
        break;

    case SAI_HOSTIF_OBJECT_TYPE_PORT:
        strcpy(str, "port");
        break;

    case SAI_HOSTIF_OBJECT_TYPE_LAG:
        strcpy(str, "LAG");
        break;

    case SAI_HOSTIF_OBJECT_TYPE_FD:
        strcpy(str, "FD");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_hostif_db_print(_In_ FILE *file, _In_ sai_netdev_t *hostif_db)
{
    uint32_t                  ii = 0;
    sai_netdev_t              curr_host_if;
    char                      subtype_str[LINE_LENGTH];
    dbg_utils_table_columns_t hostif_db_clmns[] = {
        {"db idx",       7, PARAM_UINT32_E, &ii},
        {"subtype",      8, PARAM_STRING_E, &subtype_str },
        {"ifname",      16, PARAM_STRING_E, &curr_host_if.ifname },
        {"port",        12, PARAM_HEX_E,    &curr_host_if.port_id },
        {"vlan",         7, PARAM_UINT16_E, &curr_host_if.vid },
        {NULL,           0,  0,              NULL}
    };

    assert(NULL != hostif_db);

    dbg_utils_print_general_header(file, "Host IF db");

    dbg_utils_print_secondary_header(file, "hostif_db");

    dbg_utils_print_table_headline(file, hostif_db_clmns);

    for (ii = 0; ii < MAX_HOSTIFS; ii++) {
        if (hostif_db[ii].is_used) {
            memcpy(&curr_host_if, &hostif_db[ii], sizeof(sai_netdev_t));

            SAI_dump_hostif_subtype_enum_to_str(curr_host_if.sub_type, subtype_str);

            dbg_utils_print_table_data_line(file, hostif_db_clmns);
        }
    }
}

static void SAI_dump_trap_mirror_discard_db(_In_ FILE             *file,
                                            _In_ trap_mirror_db_t *trap_mirror_discard_wred_db,
                                            _In_ trap_mirror_db_t *trap_mirror_discard_router_db)
{
    uint32_t                  ii = 0;
    sai_object_id_t           curr_mirror_oid;
    uint32_t                  count                    = 0;
    dbg_utils_table_columns_t traps_mirror_oid_clmns[] = {
        {"db idx",       7,  PARAM_UINT32_E, &ii},
        {"mirror oid",   16, PARAM_UINT64_E, &curr_mirror_oid},
        {NULL,           0,  0,              NULL}
    };

    assert(NULL != trap_mirror_discard_wred_db);
    assert(NULL != trap_mirror_discard_router_db);

    dbg_utils_print_general_header(file, "Trap mirror discard wred db");

    dbg_utils_print_secondary_header(file, "trap_mirror_discard_wred_db");

    count = trap_mirror_discard_wred_db->count;

    dbg_utils_print_field(file, "trap mirror discard wred db count", &count, PARAM_UINT32_E);

    dbg_utils_print_table_headline(file, traps_mirror_oid_clmns);

    for (ii = 0; ii < count; ii++) {
        curr_mirror_oid = trap_mirror_discard_wred_db->mirror_oid[ii];

        dbg_utils_print_table_data_line(file, traps_mirror_oid_clmns);
    }

    dbg_utils_print_general_header(file, "Trap mirror discard router db");

    dbg_utils_print_secondary_header(file, "trap_mirror_discard_router_db");

    count = trap_mirror_discard_router_db->count;

    dbg_utils_print_field(file, "trap mirror discard router db count", &count, PARAM_UINT32_E);

    dbg_utils_print_table_headline(file, traps_mirror_oid_clmns);

    for (ii = 0; ii < count; ii++) {
        curr_mirror_oid = trap_mirror_discard_router_db->mirror_oid[ii];

        dbg_utils_print_table_data_line(file, traps_mirror_oid_clmns);
    }
}

void SAI_dump_hostintf(_In_ FILE *file)
{
    sai_object_id_t  default_trap_group = 0;
    bool             trap_group_valid[MAX_TRAP_GROUPS];
    sai_netdev_t     hostif_db[MAX_HOSTIFS];
    mlnx_trap_t     *traps_db;
    trap_mirror_db_t trap_mirror_discard_wred_db;
    trap_mirror_db_t trap_mirror_discard_router_db;

    memset(trap_group_valid, 0, MAX_TRAP_GROUPS * sizeof(bool));
    memset(hostif_db, 0, sizeof(hostif_db));
    traps_db = (mlnx_trap_t*)calloc(SXD_TRAP_ID_ACL_MAX, sizeof(mlnx_trap_t));
    memset(&trap_mirror_discard_wred_db, 0, sizeof(trap_mirror_db_t));
    memset(&trap_mirror_discard_router_db, 0, sizeof(trap_mirror_db_t));

    if (!traps_db) {
        return;
    }

    SAI_dump_hostintf_getdb(&default_trap_group,
                            trap_group_valid,
                            traps_db,
                            &trap_mirror_discard_wred_db,
                            &trap_mirror_discard_router_db,
                            hostif_db);
    dbg_utils_print_module_header(file, "SAI HOSTINTF");
    SAI_dump_default_trap_group_print(file, &default_trap_group);
    SAI_dump_trap_group_valid_print(file, trap_group_valid);
    SAI_dump_traps_db_print(file, traps_db);
    SAI_dump_trap_mirror_discard_db(file,
                                    &trap_mirror_discard_wred_db,
                                    &trap_mirror_discard_router_db);
    SAI_dump_hostif_db_print(file, hostif_db);

    free(traps_db);
}
