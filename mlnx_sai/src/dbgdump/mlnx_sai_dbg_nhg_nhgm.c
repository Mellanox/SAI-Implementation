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
#include "assert.h"
#include "mlnx_sai_dbg.h"

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

static void SAI_dump_nhg_type_to_str(_In_ mlnx_nhg_type_t type, _Out_ char          *str)
{
    static const char* const sai_nhg_type_names[] = {
        "<invalid>",
        "ECMP",
        "FINE_GRAIN",
        "ORDERED",
        NULL
    };

    assert(str);
    assert(type <= MLNX_NHG_TYPE_MAX);

    sprintf(str, "%s", sai_nhg_type_names[type]);
}

static void SAI_dump_nhgm_type_to_str(_In_ mlnx_nhgm_type_t type, _Out_ char           *str)
{
    static const char* const sai_nhgm_type_names[] = {
        "<invalid>",
        "NATIVE",
        "ENCAP",
        "FINE_GRAIN",
        "ORDERED_NATIVE",
        "ORDERED_ENCAP",
        NULL
    };

    assert(str);
    assert(type <= MLNX_NHGM_TYPE_MAX);

    uint32_t name_id = 0;

    while (type) {
        name_id++;
        type >>= 1;
    }

    assert(name_id < (sizeof(sai_nhgm_type_names) / sizeof(*sai_nhgm_type_names)));

    sprintf(str, "%s", sai_nhgm_type_names[name_id]);
}

static void SAI_dump_nhgm_data_to_str(_In_ mlnx_nhgm_db_entry_t *dbg_nhgm, _Out_ char                *str)
{
    assert(str && dbg_nhgm);

    switch (dbg_nhgm->data.type) {
    case MLNX_NHGM_TYPE_ENCAP:
        sprintf(str, "NH ID:%u", dbg_nhgm->data.entry.encap.nh_idx.idx);
        break;

    case MLNX_NHGM_TYPE_NATIVE:
        sprintf(str, "ecmp:0x%X", dbg_nhgm->data.entry.native.sx_ecmp_id);
        break;

    case MLNX_NHGM_TYPE_FINE_GRAIN:
        sprintf(str, "index:%u", dbg_nhgm->data.entry.fg.id);
        break;

    case MLNX_NHGM_TYPE_ORDERED_NATIVE:
        sprintf(str,
                "prio:%u, ecmp:0x%X",
                dbg_nhgm->data.entry.ordered.prio,
                dbg_nhgm->data.entry.ordered.entry.native.sx_ecmp_id);
        break;

    case MLNX_NHGM_TYPE_ORDERED_ENCAP:
        sprintf(str,
                "prio:%u, NH ID:%u",
                dbg_nhgm->data.entry.ordered.prio,
                dbg_nhgm->data.entry.ordered.entry.encap.nh_idx.idx);
        break;

    default:
        sprintf(str, "<invalid>");
    }
}

static void SAI_dump_nhg_print(_In_ FILE *file, _In_ const mlnx_nhg_db_entry_t   *dbg_nhg, _In_ uint32_t size)
{
    sai_status_t              status;
    mlnx_nhg_db_entry_t       cur_nhg;
    uint32_t                  nhg_db_idx;
    uint32_t                  members_db_idx;
    uint32_t                  flow_counted_db_idx;
    sai_object_id_t           nhg_oid;
    char                      nhg_oid_str[OID_STR_MAX_SIZE];
    char                      vrf_oid_str[OID_STR_MAX_SIZE];
    char                      ecmp_str[OID_STR_MAX_SIZE];
    mlnx_nhg_encap_vrf_data_t vrf_data;
    uint32_t                  vrf_data_idx = 0;
    char                      type_str[MAX_STR_LENGTH];
    dbg_utils_table_columns_t nhg_encap_clmns[] = {
        {"ID",              7,  PARAM_UINT32_E, &nhg_db_idx},
        {"OID",             18, PARAM_STRING_E, nhg_oid_str},
        {"type",            12, PARAM_STRING_E, type_str},
        {"first member ID", 17, PARAM_UINT32_E, &members_db_idx},
        {"members count",   13, PARAM_UINT32_E, &cur_nhg.data.members_count},
        {"flow counter ID", 17, PARAM_UINT32_E, &flow_counted_db_idx},
        {NULL,              0,               0, NULL}
    };
    dbg_utils_table_columns_t nhg_encap_vrf_data_clmns[] = {
        {"vrf_data",  8,  PARAM_UINT32_E, &vrf_data_idx},
        {"VRF OID",   18, PARAM_STRING_E, vrf_oid_str},
        {"ecmp_id",   10, PARAM_STRING_E, ecmp_str},
        {"ref_count", 10, PARAM_UINT32_E, &vrf_data.refcount},
        {NULL,        0,               0, NULL}
    };
    dbg_utils_table_columns_t nhg_fg_clmns[] = {
        {"ID",              7,  PARAM_UINT32_E, &nhg_db_idx},
        {"OID",             18, PARAM_STRING_E, nhg_oid_str},
        {"type",            23, PARAM_STRING_E, type_str},
        {"first member ID", 17, PARAM_UINT32_E, &members_db_idx},
        {"members count",   13, PARAM_UINT32_E, &cur_nhg.data.members_count},
        {"flow counter ID", 18, PARAM_UINT32_E, &flow_counted_db_idx},
        {"real_size",       17, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.real_size},
        {"configured_size", 17, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.configured_size},
        {"ecmp_id",         18, PARAM_UINT32_E, &cur_nhg.data.data.fine_grain.sx_ecmp_id},
        {NULL,              0,               0, NULL}
    };

    assert(file);
    assert(dbg_nhg);

    dbg_utils_print_general_header(file, "NEXT_HOP_GROUP");

    for (nhg_db_idx = 0; nhg_db_idx < size; nhg_db_idx++) {
        memcpy(&cur_nhg, &dbg_nhg[nhg_db_idx], sizeof(cur_nhg));

        mlnx_shm_rm_array_idx_t nhg_idx;
        nhg_idx.type = MLNX_SHM_RM_ARRAY_TYPE_NHG;
        nhg_idx.idx = nhg_db_idx;
        status = mlnx_nhg_oid_create(nhg_idx,
                                     &nhg_oid);
        if (SAI_ERR(status)) {
            nhg_oid = SAI_NULL_OBJECT_ID;
        }
        oid_to_hex_str(nhg_oid_str, nhg_oid);

        members_db_idx = cur_nhg.data.members.idx;
        flow_counted_db_idx = cur_nhg.data.flow_counter.idx;

        SAI_dump_nhg_type_to_str(cur_nhg.data.type, type_str);

        if ((MLNX_NHG_TYPE_ECMP == cur_nhg.data.type) ||
            (MLNX_NHG_TYPE_ORDERED == cur_nhg.data.type)) {
            dbg_utils_print_table_headline(file, nhg_encap_clmns);
            dbg_utils_print_table_data_line(file, nhg_encap_clmns);

            dbg_utils_print_table_headline(file, nhg_encap_vrf_data_clmns);
            for (vrf_data_idx = 0; vrf_data_idx < NUMBER_OF_VRF_DATA_SETS; ++vrf_data_idx) {
                if ((cur_nhg.data.data.encap.vrf_data[vrf_data_idx].sx_ecmp_id != 0) ||
                    (cur_nhg.data.data.encap.vrf_data[vrf_data_idx].refcount > 0)) {
                    vrf_data = cur_nhg.data.data.encap.vrf_data[vrf_data_idx];
                    oid_to_hex_str(vrf_oid_str, vrf_data.associated_vrf);
                    snprintf(ecmp_str, OID_STR_MAX_SIZE, "0x%X", vrf_data.sx_ecmp_id);
                    dbg_utils_print_table_data_line(file, nhg_encap_vrf_data_clmns);
                }
            }
        } else if (MLNX_NHG_TYPE_FINE_GRAIN == cur_nhg.data.type) {
            dbg_utils_print_table_headline(file, nhg_fg_clmns);
            dbg_utils_print_table_data_line(file, nhg_fg_clmns);
        }
    }
}

static void SAI_dump_nhgm_print(_In_ FILE *file, _In_ const mlnx_nhgm_db_entry_t *dbg_nhgm, _In_ uint32_t size)
{
    sai_status_t              status;
    mlnx_nhgm_db_entry_t      cur_nhgm;
    uint32_t                  nhgm_db_idx;
    uint32_t                  nhg_db_idx;
    uint32_t                  prev_db_idx, next_db_idx;
    uint32_t                  flow_counter_db_idx;
    sai_object_id_t           nhgm_oid;
    char                      nhgm_oid_str[OID_STR_MAX_SIZE];
    char                      type_str[MAX_STR_LENGTH];
    char                      data_str[MAX_STR_LENGTH];
    dbg_utils_table_columns_t debug_nhgm_clmns[] = {
        {"ID",              7,  PARAM_INT_E,    &nhgm_db_idx},
        {"OID",             18, PARAM_STRING_E, nhgm_oid_str},
        {"type",            15, PARAM_STRING_E, type_str},
        {"NHG ID",          8,  PARAM_INT_E,    &nhg_db_idx},
        {"data",            30, PARAM_STRING_E, data_str},
        {"weight",          8,  PARAM_UINT32_E, &cur_nhgm.data.weight},
        {"flow counter ID", 18, PARAM_INT_E,    &flow_counter_db_idx},
        {"prev_member ID",  15, PARAM_INT_E,    &prev_db_idx},
        {"next_member ID",  15, PARAM_INT_E,    &next_db_idx},
        {NULL,              0,            0,    NULL}
    };

    assert(file);
    assert(dbg_nhgm);

    dbg_utils_print_general_header(file, "NEXT_HOP_GROUP_MEMBER");
    dbg_utils_print_table_headline(file, debug_nhgm_clmns);

    for (nhgm_db_idx = 0; nhgm_db_idx < size; nhgm_db_idx++) {
        memcpy(&cur_nhgm, &dbg_nhgm[nhgm_db_idx], sizeof(cur_nhgm));

        SAI_dump_nhgm_type_to_str(cur_nhgm.data.type, type_str);
        SAI_dump_nhgm_data_to_str(&cur_nhgm, data_str);

        flow_counter_db_idx = mlnx_get_shm_rm_id(cur_nhgm.data.flow_counter);
        nhg_db_idx = mlnx_get_shm_rm_id(cur_nhgm.data.nhg_idx);
        prev_db_idx = mlnx_get_shm_rm_id(cur_nhgm.data.prev_member_idx);
        next_db_idx = mlnx_get_shm_rm_id(cur_nhgm.data.next_member_idx);

        mlnx_shm_rm_array_idx_t nhgm_idx;
        nhgm_idx.type = MLNX_SHM_RM_ARRAY_TYPE_NHG_MEMBER;
        nhgm_idx.idx = nhgm_db_idx;
        status = mlnx_nhgm_oid_create(nhgm_idx,
                                      &nhgm_oid);
        if (SAI_ERR(status)) {
            nhgm_oid = SAI_NULL_OBJECT_ID;
        }
        oid_to_hex_str(nhgm_oid_str, nhgm_oid);

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

    dbg_utils_print_module_header(file, "SAI NHG & NHGM");

    SAI_dump_nhg_print(file, dbg_nhg, size_nhg);

    SAI_dump_nhgm_print(file, dbg_nhgm, size_nhgm);

out:
    free(dbg_nhg);
    free(dbg_nhgm);
}
