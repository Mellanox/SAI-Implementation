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
#include <string.h>

static void SAI_dump_hash_getdb(_Out_ mlnx_hash_obj_t                   *hash_list,
                                _Out_ sai_object_id_t                   *oper_hash_list,
                                _Out_ sx_router_ecmp_port_hash_params_t *ecmp_params)
{
    assert(NULL != hash_list);
    assert(NULL != oper_hash_list);
    assert(NULL != ecmp_params);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(hash_list,
           g_sai_db_ptr->hash_list,
           SAI_HASH_MAX_OBJ_COUNT * sizeof(mlnx_hash_obj_t));

    memcpy(oper_hash_list,
           g_sai_db_ptr->oper_hash_list,
           SAI_HASH_MAX_OBJ_ID * sizeof(sai_object_id_t));

    memcpy(ecmp_params,
           &g_sai_db_ptr->port_hash_params,
           sizeof(*ecmp_params));

    sai_db_unlock();
}

static void SAI_dump_hash_print(_In_ FILE *file, _In_ mlnx_hash_obj_t *hash_list)
{
    uint32_t                  ii = 0;
    mlnx_hash_obj_t           curr_hash_list;
    dbg_utils_table_columns_t hash_clmns[] = {
        {"sai obj id",  16, PARAM_UINT64_E, &curr_hash_list.hash_id},
        {"db idx",      11, PARAM_UINT32_E, &ii},
        {"field mask",  16, PARAM_UINT64_E, &curr_hash_list.field_mask},
        {NULL,          0,  0,              NULL}
    };

    assert(NULL != hash_list);

    dbg_utils_print_general_header(file, "Hash");

    dbg_utils_print_secondary_header(file, "mlnx_hash_obj_t");

    dbg_utils_print_table_headline(file, hash_clmns);

    for (ii = 0; ii < SAI_HASH_MAX_OBJ_COUNT; ii++) {
        memcpy(&curr_hash_list, &hash_list[ii], sizeof(mlnx_hash_obj_t));
        dbg_utils_print_table_data_line(file, hash_clmns);
    }
}

static void SAI_dump_oper_hash_print(_In_ FILE *file, _In_ sai_object_id_t *oper_hash_list)
{
    uint32_t                  ii = 0;
    mlnx_hash_obj_t           curr_oper_hash_list;
    dbg_utils_table_columns_t hash_clmns[] = {
        {"sai obj id",  16, PARAM_UINT64_E, &curr_oper_hash_list},
        {"db idx",      11, PARAM_UINT32_E, &ii},
        {NULL,          0,  0,              NULL}
    };

    assert(NULL != oper_hash_list);

    dbg_utils_print_general_header(file, "Oper hash");

    dbg_utils_print_secondary_header(file, "oper_hash_list");

    dbg_utils_print_table_headline(file, hash_clmns);

    for (ii = 0; ii < SAI_HASH_MAX_OBJ_ID; ii++) {
        memcpy(&curr_oper_hash_list, &oper_hash_list[ii], sizeof(sai_object_id_t));
        dbg_utils_print_table_data_line(file, hash_clmns);
    }
}

static void SAI_dump_hash_ecmp_print(_In_ FILE *file, _In_ const sx_router_ecmp_port_hash_params_t *ecmp_params)
{
    sx_router_ecmp_port_hash_params_t curr_ecmp_params;
    char hash_type_str[LINE_LENGTH];

    dbg_utils_table_columns_t ecmp_params_columns[] = {
        {"hash type",  32, PARAM_STRING_E, &hash_type_str},
        {"symmetric",  10, PARAM_BOOL_E,   &curr_ecmp_params.symmetric_hash},
        {"seed",       10, PARAM_UINT32_E, &curr_ecmp_params.seed},
        {NULL,          0,  0,             NULL}
    };

    assert(NULL != ecmp_params);

    memcpy(&curr_ecmp_params, ecmp_params, sizeof(curr_ecmp_params));

    dbg_utils_print_general_header(file, "Port ECMP hash params");

    strncpy(hash_type_str, SX_ROUTER_ECMP_HASH_TYPE_STR(curr_ecmp_params.ecmp_hash_type), sizeof(hash_type_str)-1);
    hash_type_str[LINE_LENGTH - 1] = 0;

    dbg_utils_print_table_headline(file, ecmp_params_columns);
    dbg_utils_print_table_data_line(file, ecmp_params_columns);
}

void SAI_dump_hash(_In_ FILE *file)
{
    mlnx_hash_obj_t hash_list[SAI_HASH_MAX_OBJ_COUNT];
    sai_object_id_t oper_hash_list[SAI_HASH_MAX_OBJ_ID];
    sx_router_ecmp_port_hash_params_t ecmp_params;

    memset(hash_list, 0, SAI_HASH_MAX_OBJ_COUNT * sizeof(mlnx_hash_obj_t));
    memset(oper_hash_list, 0, SAI_HASH_MAX_OBJ_ID * sizeof(sai_object_id_t));

    SAI_dump_hash_getdb(hash_list, oper_hash_list, &ecmp_params);

    dbg_utils_print_module_header(file, "SAI Hash");

    SAI_dump_hash_ecmp_print(file, &ecmp_params);
    SAI_dump_hash_print(file, hash_list);
    SAI_dump_oper_hash_print(file, oper_hash_list);
}
