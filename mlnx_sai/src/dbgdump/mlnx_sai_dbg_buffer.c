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

static void SAI_dump_buffer_getdb(_Out_ mlnx_sai_db_buffer_profile_entry_t *buffer_profiles,
                                  _Out_ uint32_t                           *port_buffer_data,
                                  _Out_ bool                               *pool_allocation,
                                  _Out_ uint32_t                           *sai_buffer_db_size)
{
    assert(NULL != buffer_profiles);
    assert(NULL != port_buffer_data);
    assert(NULL != pool_allocation);
    assert(NULL != sai_buffer_db_size);
    assert(NULL != g_sai_buffer_db_ptr);

    sai_db_read_lock();

    memcpy(buffer_profiles,
           g_sai_buffer_db_ptr->buffer_profiles,
           mlnx_sai_get_buffer_profile_number() * sizeof(mlnx_sai_db_buffer_profile_entry_t));

    memcpy(port_buffer_data,
           g_sai_buffer_db_ptr->port_buffer_data,
           BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE * MAX_PORTS * sizeof(uint32_t));

    memcpy(pool_allocation,
           g_sai_buffer_db_ptr->pool_allocation,
           (mlnx_sai_get_buffer_resource_limits()->num_ingress_pools + 
           mlnx_sai_get_buffer_resource_limits()->num_egress_pools + 1) * sizeof(bool));

    *sai_buffer_db_size = g_sai_buffer_db_size;

    sai_db_unlock();
}

static void SAI_dump_buffer_resource_limits_print(_In_ FILE *file)
{
    assert(NULL != mlnx_sai_get_buffer_resource_limits());

    dbg_utils_print_general_header(file, "Buffer resource limits");
    dbg_utils_print_field(file, "num ingress pools",
                          &mlnx_sai_get_buffer_resource_limits()->num_ingress_pools,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "num egress pools",
                          &mlnx_sai_get_buffer_resource_limits()->num_egress_pools,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "num total pools",
                          &mlnx_sai_get_buffer_resource_limits()->num_total_pools,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "num port queue buff",
                          &mlnx_sai_get_buffer_resource_limits()->num_port_queue_buff,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "num port pg buff",
                          &mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "unit size",
                          &mlnx_sai_get_buffer_resource_limits()->unit_size,
                          PARAM_UINT32_E);
    dbg_utils_print_field(file, "max buffers per port",
                          &mlnx_sai_get_buffer_resource_limits()->max_buffers_per_port,
                          PARAM_UINT32_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_sai_buffer_db_size_print(_In_ FILE *file, _In_ uint32_t *sai_buffer_db_size)
{
    assert(NULL != sai_buffer_db_size);

    dbg_utils_print_general_header(file, "Buffer db size");

    dbg_utils_print_field(file, "sai_buffer_db_size", sai_buffer_db_size, PARAM_UINT32_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_buffer_profile_mode_enum_to_str(_In_ sai_buffer_profile_threshold_mode_t mode, _Out_ char *str)
{
    assert(NULL != str);

    switch (mode) {
    case SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC:
        strcpy(str, "static");
        break;

    case SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC:
        strcpy(str, "dynamic");
        break;

    case SAI_BUFFER_PROFILE_THRESHOLD_MODE_INHERIT_BUFFER_POOL_MODE:
        strcpy(str, "inherit buffer pool");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_buffer_profile_print(_In_ FILE *file, _In_ mlnx_sai_db_buffer_profile_entry_t *buffer_profile)
{
    uint32_t                           ii     = 0;
    sai_object_id_t                    obj_id = SAI_NULL_OBJECT_ID;
    mlnx_sai_db_buffer_profile_entry_t curr_buffer_profile;
    char                               mode_str[LINE_LENGTH];
    int32_t                            curr_max               = 0;
    dbg_utils_table_columns_t          buffer_profile_clmns[] = {
        {"sai oid",       16, PARAM_UINT64_E, &obj_id},
        {"db idx",        13, PARAM_UINT32_E, &ii},
        {"sai pool",      14, PARAM_UINT64_E, &curr_buffer_profile.sai_pool},
        {"reserved size", 13, PARAM_UINT32_E, &curr_buffer_profile.reserved_size},
        {"mode",          19, PARAM_STRING_E, mode_str},
        {"max",           19, PARAM_INT_E,    &curr_max},
        {"xon",           13, PARAM_UINT32_E, &curr_buffer_profile.xon},
        {"xoff",          13, PARAM_UINT32_E, &curr_buffer_profile.xoff},
        {NULL,            0,  0,              NULL}
    };

    assert(NULL != buffer_profile);

    dbg_utils_print_general_header(file, "Buffer profile");

    dbg_utils_print_secondary_header(file, "buffer_profile");

    dbg_utils_print_table_headline(file, buffer_profile_clmns);

    for (ii = 0; ii < mlnx_sai_get_buffer_profile_number(); ii++) {
        if (buffer_profile[ii].is_valid) {
            memcpy(&curr_buffer_profile, &buffer_profile[ii], sizeof(mlnx_sai_db_buffer_profile_entry_t));

            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_BUFFER_PROFILE, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }

            SAI_dump_buffer_profile_mode_enum_to_str(buffer_profile[ii].shared_max.mode, mode_str);

            switch (buffer_profile[ii].shared_max.mode) {
            /*case SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC:*/
            case SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC:
                curr_max = buffer_profile[ii].shared_max.max.static_th;
                break;

            /*case SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC:*/
            case SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC:
                curr_max = buffer_profile[ii].shared_max.max.alpha;
                break;

            /*case SAI_BUFFER_PROFILE_THRESHOLD_MODE_INHERIT_BUFFER_POOL_MODE:
             *   curr_max = 0;
             *   break;*/

            default:
                curr_max = 0;
                break;
            }

            dbg_utils_print_table_data_line(file, buffer_profile_clmns);
        }
    }
}

static void SAI_dump_port_buffer_data_print(_In_ FILE *file, _In_ uint32_t *port_buffer_data)
{
    uint32_t                  ii                       = 0;
    uint32_t                  jj                       = 0;
    uint32_t                  curr_port_buffer_data    = 0;
    const uint32_t            num_ingress_pools        = mlnx_sai_get_buffer_resource_limits()->num_ingress_pools;
    const uint32_t            num_egress_pools         = mlnx_sai_get_buffer_resource_limits()->num_egress_pools;
    const uint32_t            num_port_pg_buff         = mlnx_sai_get_buffer_resource_limits()->num_port_pg_buff;
    const uint32_t            ingress_pools_base       = 0;
    const uint32_t            egress_pools_base        = MAX_PORTS * num_ingress_pools;
    const uint32_t            port_pg_buff_base        = egress_pools_base + MAX_PORTS * num_egress_pools;
    dbg_utils_table_columns_t port_buffer_data_clmns[] = {
        {"db idx",           11, PARAM_UINT32_E, &jj},
        {"port buffer data", 16, PARAM_UINT32_E, &curr_port_buffer_data},
        {NULL,               0,  0,              NULL}
    };

    assert(NULL != port_buffer_data);

    dbg_utils_print_general_header(file, "Port buffer data");

    dbg_utils_print_secondary_header(file, "port_buffer_data");

    dbg_utils_print_secondary_header(file, "Port ingress pool");

    for (ii = 0; ii < MAX_PORTS; ii++) {
        dbg_utils_print_secondary_header(file, "Port %d ingress pool", ii);

        dbg_utils_print_table_headline(file, port_buffer_data_clmns);

        for (jj = 0; jj < num_ingress_pools; jj++) {
            curr_port_buffer_data = port_buffer_data[ingress_pools_base + jj + ii * num_ingress_pools];

            dbg_utils_print_table_data_line(file, port_buffer_data_clmns);
        }
    }

    dbg_utils_print_secondary_header(file, "Port egress pool");

    for (ii = 0; ii < MAX_PORTS; ii++) {
        dbg_utils_print_secondary_header(file, "Port %d egress pool", ii);

        dbg_utils_print_table_headline(file, port_buffer_data_clmns);

        for (jj = 0; jj < num_egress_pools; jj++) {
            curr_port_buffer_data = port_buffer_data[egress_pools_base + jj + ii * num_egress_pools];

            dbg_utils_print_table_data_line(file, port_buffer_data_clmns);
        }
    }

    dbg_utils_print_secondary_header(file, "Port pg");

    for (ii = 0; ii < MAX_PORTS; ii++) {
        dbg_utils_print_secondary_header(file, "Port %d pg", ii);

        dbg_utils_print_table_headline(file, port_buffer_data_clmns);

        for (jj = 0; jj < num_port_pg_buff; jj++) {
            curr_port_buffer_data = port_buffer_data[port_pg_buff_base + jj + ii * num_port_pg_buff];

            dbg_utils_print_table_data_line(file, port_buffer_data_clmns);
        }
    }
}

static void SAI_dump_pool_allocation_print(_In_ FILE *file, _In_ bool *pool_allocation)
{
    uint32_t                  ii                           = 0;
    uint32_t                  curr_pool_allocation         = false;
    dbg_utils_table_columns_t pool_allocation_data_clmns[] = {
        {"db idx",          11, PARAM_UINT32_E, &ii},
        {"pool allocation", 15, PARAM_BOOL_E,   &curr_pool_allocation},
        {NULL,              0,  0,              NULL}
    };

    assert(NULL != pool_allocation);

    dbg_utils_print_general_header(file, "Pool allocation");

    dbg_utils_print_secondary_header(file, "pool_allocation");

    dbg_utils_print_table_headline(file, pool_allocation_data_clmns);

    for (ii = 0; ii < mlnx_sai_get_buffer_resource_limits()->num_ingress_pools + 
        mlnx_sai_get_buffer_resource_limits()->num_egress_pools + 1; ii++) {
        curr_pool_allocation = pool_allocation[ii];

        dbg_utils_print_table_data_line(file, pool_allocation_data_clmns);
    }
}

void SAI_dump_buffer(_In_ FILE *file)
{
    mlnx_sai_db_buffer_profile_entry_t *buffer_profile          = NULL;
    uint32_t                           *port_buffer_data        = NULL;
    bool                               *pool_allocation         = NULL;
    uint32_t                            sai_buffer_db_size      = 0;

    buffer_profile =
        (mlnx_sai_db_buffer_profile_entry_t*)calloc(
            mlnx_sai_get_buffer_profile_number(), sizeof(mlnx_sai_db_buffer_profile_entry_t));
    port_buffer_data = (uint32_t*)calloc(BUFFER_DB_PER_PORT_PROFILE_INDEX_ARRAY_SIZE * MAX_PORTS,
                                         sizeof(uint32_t));
    pool_allocation = (bool*)calloc(mlnx_sai_get_buffer_resource_limits()->num_ingress_pools + 
        mlnx_sai_get_buffer_resource_limits()->num_egress_pools + 1, sizeof(bool));

    if ((!buffer_profile) || (!port_buffer_data) || (!pool_allocation)) {
        if (buffer_profile) {
            free(buffer_profile);
        }
        if (port_buffer_data) {
            free(port_buffer_data);
        }
        if (pool_allocation) {
            free(pool_allocation);
        }
        return;
    }

    SAI_dump_buffer_getdb(buffer_profile,
                          port_buffer_data,
                          pool_allocation,
                          &sai_buffer_db_size);

    dbg_utils_print_module_header(file, "SAI Buffer");
    SAI_dump_buffer_resource_limits_print(file);
    SAI_dump_buffer_profile_print(file, buffer_profile);
    SAI_dump_port_buffer_data_print(file, port_buffer_data);
    SAI_dump_pool_allocation_print(file, pool_allocation);
    SAI_dump_sai_buffer_db_size_print(file, &sai_buffer_db_size);

    free(buffer_profile);
    free(port_buffer_data);
    free(pool_allocation);
}
