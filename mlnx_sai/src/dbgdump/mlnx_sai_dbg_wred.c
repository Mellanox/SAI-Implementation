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

static void SAI_dump_wred_getdb(_Out_ mlnx_wred_profile_t *wred_db)
{
    assert(NULL != wred_db);
    assert(NULL != g_sai_qos_db_ptr);

    sai_db_read_lock();

    memcpy(wred_db,
           g_sai_qos_db_ptr->wred_db,
           g_resource_limits.cos_redecn_profiles_max * sizeof(mlnx_wred_profile_t));

    sai_db_unlock();
}

static void SAI_dump_wred_db_print(_In_ FILE *file, _In_ mlnx_wred_profile_t *wred_db)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_wred_profile_t       curr_wred_db;
    dbg_utils_table_columns_t wred_db_clmns[] = {
        {"sai oid",           16, PARAM_UINT64_E, &obj_id},
        {"db idx",            13, PARAM_UINT32_E, &ii},
        {"green profile id",  16, PARAM_UINT32_E, &curr_wred_db.green_profile_id},
        {"yellow profile id", 17, PARAM_UINT32_E, &curr_wred_db.yellow_profile_id},
        {"red profile id",    14, PARAM_UINT32_E, &curr_wred_db.red_profile_id},
        {"wred enabled",      12, PARAM_UINT8_E,  &curr_wred_db.wred_enabled},
        {"ecn enabled",       11, PARAM_UINT8_E,  &curr_wred_db.ecn_enabled},
        {NULL,                 0,  0,              NULL}
    };

    assert(NULL != wred_db);

    dbg_utils_print_general_header(file, "Wred db");

    dbg_utils_print_secondary_header(file, "wred_db");

    dbg_utils_print_table_headline(file, wred_db_clmns);

    for (ii = 0; ii < g_resource_limits.cos_redecn_profiles_max; ii++) {
        if (wred_db[ii].in_use) {
            memcpy(&curr_wred_db, &wred_db[ii], sizeof(mlnx_wred_profile_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_WRED, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            dbg_utils_print_table_data_line(file, wred_db_clmns);
        }
    }
}

void SAI_dump_wred(_In_ FILE *file)
{
    mlnx_wred_profile_t *wred_db = NULL;

    wred_db = (mlnx_wred_profile_t*)calloc(g_resource_limits.cos_redecn_profiles_max, sizeof(mlnx_wred_profile_t));

    if ((!wred_db)) {
        return;
    }

    SAI_dump_wred_getdb(wred_db);

    dbg_utils_print_module_header(file, "SAI Wred");

    SAI_dump_wred_db_print(file, wred_db);

    free(wred_db);
}
