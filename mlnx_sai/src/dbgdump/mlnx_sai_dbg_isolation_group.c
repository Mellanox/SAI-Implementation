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
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "mlnx_sai.h"
#include <sx/utils/dbg_utils.h>
#include "assert.h"

static void SAI_dump_isolation_group_get_db(mlnx_isolation_group_t *db_ptr, uint32_t *count_ptr)
{
    mlnx_isolation_group_t *isolation_group_db;
    uint32_t                ii, count = 0;

    assert(db_ptr);
    assert(count_ptr);

    sai_db_read_lock();
    isolation_group_db = g_sai_db_ptr->isolation_groups;

    for (ii = 0; ii < MAX_ISOLATION_GROUPS; ii++) {
        if (!isolation_group_db[ii].is_used) {
            continue;
        }
        db_ptr[count] = isolation_group_db[ii];
        count++;
    }

    sai_db_unlock();

    *count_ptr = count;
}

static void SAI_dump_isolation_group_type_to_str(sai_isolation_group_type_t type, char *str)
{
    assert(NULL != str);

    switch (type) {
    case SAI_ISOLATION_GROUP_TYPE_PORT:
        strcpy(str, "port");
        break;

    case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
        strcpy(str, "bridge port");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_isolation_group_print(FILE *file, mlnx_isolation_group_t *isolation_group_db,
                                           uint32_t entry_count)
{
    uint32_t                  ii, jj;
    uint32_t                  member_count, port_count, acl_count;
    sai_object_id_t           group_oid, member_oid, acl_oid;
    sx_port_log_id_t          log_port;
    char                      type_str[LINE_LENGTH];
    dbg_utils_table_columns_t isolation_group_clmns[] = {
        {"DB idx",            7,  PARAM_UINT32_E, &ii},
        {"SAI OID",           15, PARAM_HEX64_E,  &group_oid},
        {"Type",              11, PARAM_STRING_E, &type_str},
        {"member count",      20, PARAM_UINT32_E, &member_count},
        {"port subscr count", 20, PARAM_UINT32_E, &port_count},
        {"acl subscr count",  20, PARAM_UINT32_E, &acl_count},
        {NULL,            0,               0, NULL}
    };
    dbg_utils_table_columns_t group_member_clmns[] = {
        {"DB idx",        7,  PARAM_UINT32_E, &jj},
        {"SAI OID",       15, PARAM_HEX64_E,  &member_oid},
        {"group OID",     15, PARAM_HEX64_E,  &group_oid},
        {"group type",    11, PARAM_STRING_E, &type_str},
        {"logical",       11, PARAM_HEX_E,    &log_port},
        {NULL,            0,               0, NULL}
    };
    dbg_utils_table_columns_t port_group_subscr_clmns[] = {
        {"DB idx",        7,  PARAM_UINT32_E, &jj},
        {"logical",       11, PARAM_HEX_E,    &log_port},
        {"group OID",     15, PARAM_HEX64_E,  &group_oid},
        {"group type",    11, PARAM_STRING_E, &type_str},
        {NULL,            0,               0, NULL}
    };
    dbg_utils_table_columns_t acl_group_subscr_clmns[] = {
        {"DB idx",        7,  PARAM_UINT32_E, &jj},
        {"SAI OID",       15, PARAM_UINT32_E, &acl_oid},
        {"group OID",     15, PARAM_HEX64_E,  &group_oid},
        {"group type",    11, PARAM_STRING_E, &type_str},
        {NULL,            0,               0, NULL}
    };

    assert(file);
    assert(isolation_group_db);


    for (ii = 0; ii < entry_count; ii++) {
        dbg_utils_print_general_header(file, "Isolation group");
        dbg_utils_print_table_headline(file, isolation_group_clmns);
        SAI_dump_isolation_group_type_to_str(isolation_group_db[ii].type, type_str);
        mlnx_create_isolation_group_oid(ii, isolation_group_db[ii].type, &group_oid);
        member_count = isolation_group_db[ii].members_count;
        port_count = isolation_group_db[ii].subscribed_ports_count;
        acl_count = isolation_group_db[ii].subscribed_acl_count;

        dbg_utils_print_table_data_line(file, isolation_group_clmns);

        if (member_count) {
            dbg_utils_print_general_header(file, "isolation group members");
            dbg_utils_print_table_headline(file, group_member_clmns);

            for (jj = 0; jj < member_count; jj++) {
                log_port = isolation_group_db[ii].members[jj];
                mlnx_create_isolation_group_member_oid(&member_oid, group_oid, log_port);

                dbg_utils_print_table_data_line(file, group_member_clmns);
            }
        }

        if (port_count) {
            dbg_utils_print_general_header(file, "isolation group port subscribers");
            dbg_utils_print_table_headline(file, port_group_subscr_clmns);

            for (jj = 0; jj < port_count; jj++) {
                log_port = isolation_group_db[ii].subscribed_ports[jj];

                dbg_utils_print_table_data_line(file, port_group_subscr_clmns);
            }
        }

        if (acl_count) {
            dbg_utils_print_general_header(file, "isolation group ACL Entry subscribers");
            dbg_utils_print_table_headline(file, acl_group_subscr_clmns);

            for (jj = 0; jj < acl_count; jj++) {
                acl_oid = isolation_group_db[ii].subscribed_acl[jj];

                dbg_utils_print_table_data_line(file, acl_group_subscr_clmns);
            }
        }
    }
}

void SAI_dump_isolation_group(_In_ FILE *file)
{
    mlnx_isolation_group_t *isolation_group_db = calloc(MAX_ISOLATION_GROUPS, sizeof(*isolation_group_db));
    uint32_t                entry_count = 0;

    if (!isolation_group_db) {
        goto out;
    }

    SAI_dump_isolation_group_get_db(isolation_group_db, &entry_count);

    dbg_utils_print_module_header(file, "SAI Isolation Groups DB");
    SAI_dump_isolation_group_print(file, isolation_group_db, entry_count);

out:
    free(isolation_group_db);
}
