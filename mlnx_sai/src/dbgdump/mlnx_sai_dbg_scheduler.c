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

static void SAI_dump_scheduler_getdb(_Out_ mlnx_sched_profile_t *sched_db)
{
    assert(NULL != sched_db);
    assert(NULL != g_sai_qos_db_ptr);

    sai_db_read_lock();

    memcpy(sched_db,
           g_sai_qos_db_ptr->sched_db,
           MAX_SCHED * sizeof(mlnx_sched_profile_t));

    sai_db_unlock();
}

static void SAI_dump_sched_db_print(_In_ FILE *file, _In_ mlnx_sched_profile_t *sched_db)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_sched_profile_t      curr_sched_db;
    dbg_utils_table_columns_t sched_db_clmns[] = {
        {"sai oid",            16, PARAM_UINT64_E, &obj_id},
        {"db idx",             13, PARAM_UINT32_E, &ii},
        {"element hierarchy",  14, PARAM_UINT8_E,  &curr_sched_db.ets.element_hierarchy},
        {"element index",      14, PARAM_UINT8_E,  &curr_sched_db.ets.element_index},
        {"next element index", 14, PARAM_UINT8_E,  &curr_sched_db.ets.next_element_index},
        {"min shaper enable",  14, PARAM_UINT8_E,  &curr_sched_db.ets.min_shaper_enable},
        {"packets mode",       14, PARAM_UINT8_E,  &curr_sched_db.ets.packets_mode},
        {"min shaper rate",    14, PARAM_UINT32_E, &curr_sched_db.ets.min_shaper_rate},
        {"max shaper enable",  14, PARAM_UINT8_E,  &curr_sched_db.ets.max_shaper_enable},
        {"max shaper rate",    14, PARAM_UINT32_E, &curr_sched_db.ets.max_shaper_rate},
        {"dwrr enable",        14, PARAM_UINT8_E,  &curr_sched_db.ets.dwrr_enable},
        {"dwrr",               14, PARAM_UINT8_E,  &curr_sched_db.ets.dwrr},
        {"dwrr weight",        14, PARAM_UINT8_E,  &curr_sched_db.ets.dwrr_weight},
        {"min rate",           13, PARAM_UINT32_E, &curr_sched_db.min_rate},
        {"max rate",           19, PARAM_UINT64_E, &curr_sched_db.max_rate},
        {NULL,                 0,  0,              NULL}
    };

    assert(NULL != sched_db);

    dbg_utils_print_general_header(file, "Scheduler db");

    dbg_utils_print_secondary_header(file, "sched_db");

    dbg_utils_print_table_headline(file, sched_db_clmns);

    for (ii = 0; ii < MAX_SCHED; ii++) {
        if (sched_db[ii].is_used) {
            memcpy(&curr_sched_db, &sched_db[ii], sizeof(mlnx_sched_profile_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_SCHEDULER, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            dbg_utils_print_table_data_line(file, sched_db_clmns);
        }
    }
}

void SAI_dump_scheduler(_In_ FILE *file)
{
    mlnx_sched_profile_t *sched_db = NULL;

    sched_db = (mlnx_sched_profile_t*)calloc(MAX_SCHED, sizeof(mlnx_sched_profile_t));

    if ((!sched_db)) {
        return;
    }

    SAI_dump_scheduler_getdb(sched_db);

    dbg_utils_print_module_header(file, "SAI Scheduler");

    SAI_dump_sched_db_print(file, sched_db);

    free(sched_db);
}
