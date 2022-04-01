/*
 *  Copyright (C) 2019-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "saimetadata.h"
#include "assert.h"

#define MAX_STR_LENGTH 50

static void SAI_dump_nhg_getdb(_Out_ mlnx_nhg_db_entry_t *dbg_nhg_db, _Out_ uint32_t *count)
{
    sai_status_t               status;
    const mlnx_nhg_db_entry_t *dbg_nhg;
    uint32_t                   db_size, dbg_nhg_idx, copied = 0;
    void                      *ptr;

    assert(dbg_nhg_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NHG);

    for (dbg_nhg_idx = 0; dbg_nhg_idx < db_size; dbg_nhg_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_NHG, dbg_nhg_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        dbg_nhg = ptr;

        if (!(dbg_nhg->array_hdr.is_used)) {
            continue;
        }

        dbg_nhg_db[copied] = *dbg_nhg;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}

static void SAI_dump_nhgm_getdb(_Out_ mlnx_nhgm_db_entry_t *dbg_nhgm_db, _Out_ uint32_t *count)
{
    sai_status_t                status;
    const mlnx_nhgm_db_entry_t *dbg_nhgm;
    uint32_t                    db_size, dbg_nhgm_idx, copied = 0;
    void                       *ptr;

    assert(dbg_nhgm_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER);

    for (dbg_nhgm_idx = 0; dbg_nhgm_idx < db_size; dbg_nhgm_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER, dbg_nhgm_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        dbg_nhgm = ptr;

        if (!(dbg_nhgm->array_hdr.is_used)) {
            continue;
        }

        dbg_nhgm_db[copied] = *dbg_nhgm;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}

static void SAI_dump_nhg_type_to_str(_In_ mlnx_nhg_type_t type, _Out_ char *str)
{
    assert(str);
    assert(type <= MLNX_NHG_TYPE_FINE_GRAIN);

    const char *name = sai_metadata_enum_sai_next_hop_group_type_t.valuesshortnames[type];

    strncpy(str, name, MAX_STR_LENGTH);
    str[MAX_STR_LENGTH - 1] = '\0';
}

static void SAI_dump_nhgm_type_to_str(_In_ mlnx_nhgm_type_t type, _Out_ char *str)
{
    const char* const sai_next_hop_group_member_type_t_enum_values_short_names[] = {
        "NHGM_NULL_ECMP",
        "NHGM_NATIVE_ECMP",
        "NHGM_ENCAP_ECMP",
        "NHGM_FINE_GRAIN_ECMP",
        NULL
    };

    assert(str);
    assert(type <= MLNX_NHGM_TYPE_FINE_GRAIN);

    strncpy(str, sai_next_hop_group_member_type_t_enum_values_short_names[type], MAX_STR_LENGTH);
    str[MAX_STR_LENGTH - 1] = '\0';
}

static void SAI_dump_nhg_print(_In_ FILE *file, _In_ const mlnx_nhg_db_entry_t   *dbg_nhg, _In_ uint32_t size)
{
    mlnx_nhg_db_entry_t     cur_nhg;
    uint32_t                ii, loop = 0;
    char                    type_str[MAX_STR_LENGTH];
    mlnx_shm_rm_array_idx_t idx;

    idx.type = MLNX_SHM_RM_ARRAY_TYPE_NHG;
    char                       empty = '\0';
    dbg_utils_table_columns_t  debug_nhg_encap_clmns[] = {
        {"DB idx",            7,  PARAM_UINT32_E, &idx},
        {"members idx",       12, PARAM_UINT32_E, &cur_nhg.data.members},
        {"members count",     13, PARAM_UINT32_E, &cur_nhg.data.members_count},
        {"flow counter idx",  18, PARAM_UINT32_E, &cur_nhg.data.flow_counter},
        {"type",              23, PARAM_STRING_E, type_str},
        {"encap assoc vrf",   18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].associated_vrf},
        {"encap vrf ecmp id", 18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].sx_ecmp_id},
        {"ref count",         18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].refcount},
        {NULL,                0,               0, NULL}
    };
    dbg_utils_table_columns_t  debug_nhg_encap_tb_clmns[] = {
        {" ",                 77, PARAM_STRING_E, &empty},
        {"encap assoc vrf",   18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].associated_vrf},
        {"encap vrf ecmp id", 18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].sx_ecmp_id},
        {"ref count",         18, PARAM_UINT32_E, &cur_nhg.data.data.encap.vrf_data[loop].refcount},
        {NULL,                0,               0, NULL}
    };
    dbg_utils_table_columns_t  debug_nhg_fg_clmns[] = {
        {"DB idx",               7,  PARAM_UINT32_E, &idx},
        {"members idx",          12, PARAM_UINT32_E, &cur_nhg.data.members},
        {"members count",        13, PARAM_UINT32_E, &cur_nhg.data.members_count},
        {"flow counter idx",     18, PARAM_UINT32_E, &cur_nhg.data.flow_counter},
        {"type",                 23, PARAM_STRING_E, type_str},
        {"fine grain real size", 21, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.real_size},
        {"fine grain conf size", 21, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.configured_size},
        {"fine grain ecmp id",   20, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.sx_ecmp_id},
        {NULL,                   0,               0, NULL}
    };
    dbg_utils_table_columns_t *encap_print;

    assert(file);
    assert(dbg_nhg);

    dbg_utils_print_general_header(file, "Next hop groups");

    for (ii = 0; ii < size; ii++) {
        memcpy(&cur_nhg, &dbg_nhg[ii], sizeof(cur_nhg));

        SAI_dump_nhg_type_to_str(cur_nhg.data.type, type_str);

        idx.idx = ii;

        if (MLNX_NHG_TYPE_ECMP == cur_nhg.data.type) {
            encap_print = debug_nhg_encap_clmns;
            dbg_utils_print_table_headline(file, debug_nhg_encap_clmns);

            for (loop = 0; loop < NUMBER_OF_LOCAL_VNETS; ++loop) {
                if (0 < cur_nhg.data.data.encap.vrf_data[loop].refcount) {
                    dbg_utils_print_table_data_line(file, encap_print);
                    encap_print = debug_nhg_encap_tb_clmns;
                }
            }
            if (encap_print == debug_nhg_encap_clmns) {
                dbg_utils_print_table_data_line(file, encap_print);
            }
        } else if (MLNX_NHG_TYPE_FINE_GRAIN == cur_nhg.data.type) {
            dbg_utils_print_table_headline(file, debug_nhg_fg_clmns);
            dbg_utils_print_table_data_line(file, debug_nhg_fg_clmns);
        } else {
            continue;
        }
    }
}

static void SAI_dump_nhgm_print(_In_ FILE *file, _In_ const mlnx_nhgm_db_entry_t *dbg_nhgm, _In_ uint32_t size)
{
    mlnx_nhgm_db_entry_t    cur_nhgm;
    uint32_t                ii;
    char                    type_str[MAX_STR_LENGTH];
    void                   *table_data = &ii;
    mlnx_shm_rm_array_idx_t idx;

    idx.type = MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER;

    dbg_utils_table_columns_t debug_nhgm_clmns[] = {
        {"DB idx",                  7,  PARAM_UINT32_E, &idx},
        {"nhg idx",                 8,  PARAM_UINT32_E, &cur_nhgm.data.nhg_idx},
        {"weight",                  8,  PARAM_UINT32_E, &cur_nhgm.data.weight},
        {"flow counter idx",        18, PARAM_UINT32_E, &cur_nhgm.data.flow_counter},
        {"type",                    23, PARAM_STRING_E, type_str},
        {"data",                    14, PARAM_UINT32_E, table_data},
        {"previous member",         15, PARAM_UINT32_E, &cur_nhgm.data.prev_member_idx},
        {"next member",             12, PARAM_UINT32_E, &cur_nhgm.data.next_member_idx},
        {NULL,                      0,               0, NULL}
    };

    assert(file);
    assert(dbg_nhgm);

    dbg_utils_print_general_header(file, "Next hop groups members");
    dbg_utils_print_table_headline(file, debug_nhgm_clmns);

    for (ii = 0; ii < size; ii++) {
        memcpy(&cur_nhgm, &dbg_nhgm[ii], sizeof(cur_nhgm));

        SAI_dump_nhgm_type_to_str(cur_nhgm.data.type, type_str);
        switch (cur_nhgm.data.type) {
        case MLNX_NHGM_TYPE_NATIVE:
            table_data = &cur_nhgm.data.entry.nh_idx;
            break;

        case MLNX_NHGM_TYPE_ENCAP:
            table_data = &cur_nhgm.data.entry.sx_ecmp_id;
            break;

        case MLNX_NHGM_TYPE_FINE_GRAIN:
            table_data = &cur_nhgm.data.entry.fg_id;
            break;

        default:
            table_data = 0;
        }

        idx.idx = ii;

        dbg_utils_print_table_data_line(file, debug_nhgm_clmns);
    }
}

void SAI_dump_nhg_nhgm(_In_ FILE *file)
{
    mlnx_nhg_db_entry_t  *dbg_nhg = NULL;
    mlnx_nhgm_db_entry_t *dbg_nhgm = NULL;
    uint32_t              size_nhg = 0;
    uint32_t              size_nhgm = 0;

    dbg_nhg = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NHG),
                     sizeof(mlnx_nhg_db_entry_t));
    if (!dbg_nhg) {
        goto out;
    }

    dbg_nhgm = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER),
                      sizeof(mlnx_nhgm_db_entry_t));
    if (!dbg_nhgm) {
        goto out;
    }

    SAI_dump_nhg_getdb(dbg_nhg, &size_nhg);

    SAI_dump_nhgm_getdb(dbg_nhgm, &size_nhgm);

    dbg_utils_print_module_header(file, "SAI NHG DEBUG");

    SAI_dump_nhg_print(file, dbg_nhg, size_nhg);

    SAI_dump_nhgm_print(file, dbg_nhgm, size_nhgm);

out:
    free(dbg_nhg);
    free(dbg_nhgm);
}
