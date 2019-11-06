/*
 *  Copyright (C) 2019. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#include "saimetadata.h"
#include "assert.h"

static void SAI_dump_debug_counter_getdb(_Out_ mlnx_debug_counter_t *dbg_counter_db,
                                         _Out_ uint32_t             *count)
{
    sai_status_t                status;
    const mlnx_debug_counter_t *dbg_counter;
    uint32_t                    db_size, dbg_counter_idx, copied = 0;
    void                       *ptr;

    assert(dbg_counter_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER);

    for (dbg_counter_idx = 0; dbg_counter_idx < db_size; dbg_counter_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER, dbg_counter_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        dbg_counter = ptr;

        dbg_counter_db[copied] = *dbg_counter;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}

static void SAI_dump_debug_counter_type_to_str(_In_ sai_debug_counter_type_t  type,
                                               _Out_ char                    *str)
{
    assert(str);
    assert(type <= SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS);

    const char *name = sai_metadata_enum_sai_debug_counter_type_t.valuesshortnames[type];
    strcpy(str, name);
}

static void SAI_dump_debug_counter_reasons_to_str(_In_ const mlnx_debug_counter_t *dbg_counter,
                                                  _Out_ char *str,
                                                  _In_ uint32_t len)
{
    uint32_t ii, written = 0;

    assert(dbg_counter);
    assert(str);

    written += snprintf(str + written, len - written, "Drop reasons:[\n");

    for (ii = 0; ii < MLNX_DEBUG_COUNTER_MAX_REASONS; ii++) {
        if (dbg_counter->drop_reasons[ii]) {
            written += snprintf(str + written, len - written, "%s\n",
                                sai_metadata_enum_sai_in_drop_reason_t.valuesshortnames[ii]);
        }
    }

    written += snprintf(str + written, len - written, "]\n");
}

static void SAI_dump_debug_counter_print(_In_ FILE *file,
                                         _In_ const mlnx_debug_counter_t *dbg_counters,
                                         _In_ uint32_t                    size)
{
    mlnx_debug_counter_t cur_debug_counter;
    uint32_t             ii;
    char                 type_str[50];
    dbg_utils_table_columns_t debug_counter_clmns[] = {
        {"DB idx",           7, PARAM_UINT32_E, &ii},
        {"SX trap group",   16, PARAM_HEX_E,    &cur_debug_counter.sx_trap_group},
        {"policer db idx",  15, PARAM_UINT32_E, &cur_debug_counter.policer_db_idx},
        {"type",            30, PARAM_STRING_E, type_str},
        {NULL,               0,              0, NULL}
    };

    assert(file);
    assert(dbg_counters);

    dbg_utils_print_general_header(file, "Debug counters");

    dbg_utils_print_table_headline(file, debug_counter_clmns);

    for (ii = 0; ii < size; ii++) {
        if (!dbg_counters[ii].array_hdr.is_used) {
            continue;
        }

        memcpy(&cur_debug_counter, &dbg_counters[ii], sizeof(cur_debug_counter));

        SAI_dump_debug_counter_type_to_str(cur_debug_counter.type, type_str);

        char reasons_str[30 * MLNX_DEBUG_COUNTER_MAX_REASONS + 1] = {0};

        SAI_dump_debug_counter_reasons_to_str(&cur_debug_counter, reasons_str, ARRAY_SIZE(reasons_str) - 1);
        dbg_utils_print_table_data_line(file, debug_counter_clmns);
        dbg_utils_print(file, "%s", reasons_str);
    }
}

void SAI_dump_debug_counter(_In_ FILE *file)
{
    mlnx_debug_counter_t *dbg_counters = NULL;
    uint32_t              size = 0;

    dbg_counters = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_DEBUG_COUNTER),
                          sizeof(mlnx_debug_counter_t));
    if (!dbg_counters) {
        goto out;
    }

    SAI_dump_debug_counter_getdb(dbg_counters, &size);

    dbg_utils_print_module_header(file, "SAI Debug counter DB");

    SAI_dump_debug_counter_print(file, dbg_counters, size);

out:
    free(dbg_counters);
}
