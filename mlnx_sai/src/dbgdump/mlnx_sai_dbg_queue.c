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

static void SAI_dump_queue_getdb(_Out_ mlnx_qos_queue_config_t *queue_db)
{
    assert(NULL != queue_db);
    assert(NULL != g_sai_qos_db_ptr);

    sai_db_read_lock();

    memcpy(queue_db,
           g_sai_qos_db_ptr->queue_db,
           (g_resource_limits.cos_port_ets_traffic_class_max + 1) * MAX_PORTS * 2
           * sizeof(mlnx_qos_queue_config_t));

    sai_db_unlock();
}

static void SAI_dump_sched_type_enum_to_str(_In_ mlnx_sched_obj_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case MLNX_SCHED_OBJ_GROUP:
        strcpy(str, "group");
        break;

    case MLNX_SCHED_OBJ_QUEUE:
        strcpy(str, "queue");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_ets_type_enum_to_str(_In_ sx_cos_ets_hierarchy_t ets_type, _Out_ char *str)
{
    assert(NULL != str);

    switch (ets_type) {
    case SX_COS_ETS_HIERARCHY_PORT_E:
        strcpy(str, "port");
        break;

    case SX_COS_ETS_HIERARCHY_GROUP_E:
        strcpy(str, "group");
        break;

    case SX_COS_ETS_HIERARCHY_SUB_GROUP_E:
        strcpy(str, "sub group");
        break;

    case SX_COS_ETS_HIERARCHY_TC_E:
        strcpy(str, "tc");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_queue_db_print(_In_ FILE *file, _In_ mlnx_qos_queue_config_t *queue_db)
{
    uint32_t                  ii     = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_qos_queue_config_t   curr_queue_db;
    char                      type_str[LINE_LENGTH];
    char                      ets_type_str[LINE_LENGTH];
    dbg_utils_table_columns_t queue_db_clmns[] = {
        {"sai oid",         16, PARAM_UINT64_E, &obj_id},
        {"db idx",          13, PARAM_UINT32_E, &ii},
        {"wred id",         16, PARAM_UINT64_E, &curr_queue_db.wred_id},
        {"buffer id",       17, PARAM_UINT64_E, &curr_queue_db.buffer_id},
        {"type",            5,  PARAM_STRING_E, type_str},
        {"scheduler id",    14, PARAM_UINT64_E, &curr_queue_db.sched_obj.scheduler_id},
        {"index",           14, PARAM_UINT8_E,  &curr_queue_db.sched_obj.index},
        {"is used",         14, PARAM_UINT8_E,  &curr_queue_db.sched_obj.is_used},
        {"next index",      14, PARAM_INT_E,    &curr_queue_db.sched_obj.next_index},
        {"level",           14, PARAM_UINT8_E,  &curr_queue_db.sched_obj.level},
        {"max child count", 14, PARAM_UINT32_E, &curr_queue_db.sched_obj.max_child_count},
        {"ets type",        14, PARAM_STRING_E, ets_type_str},
        {NULL,              0,  0,              NULL}
    };

    assert(NULL != queue_db);

    dbg_utils_print_general_header(file, "Queue db");

    dbg_utils_print_secondary_header(file, "queue_db");

    dbg_utils_print_table_headline(file, queue_db_clmns);

    for (ii = 0; ii < (g_resource_limits.cos_port_ets_traffic_class_max + 1) * MAX_PORTS * 2; ii++) {
        memcpy(&curr_queue_db, &queue_db[ii], sizeof(mlnx_qos_queue_config_t));

        if (SAI_STATUS_SUCCESS !=
            mlnx_create_object(SAI_OBJECT_TYPE_QUEUE, ii, NULL, &obj_id)) {
            obj_id = SAI_NULL_OBJECT_ID;
        }

        SAI_dump_sched_type_enum_to_str(queue_db[ii].sched_obj.type,
                                        type_str);
        SAI_dump_ets_type_enum_to_str(queue_db[ii].sched_obj.ets_type,
                                      ets_type_str);
        dbg_utils_print_table_data_line(file, queue_db_clmns);
    }
}

void SAI_dump_queue(_In_ FILE *file)
{
    mlnx_qos_queue_config_t *queue_db = NULL;

    queue_db = (mlnx_qos_queue_config_t*)calloc((g_resource_limits.cos_port_ets_traffic_class_max + 1) * MAX_PORTS * 2,
                                                sizeof(mlnx_qos_queue_config_t));

    if ((!queue_db)) {
        return;
    }

    SAI_dump_queue_getdb(queue_db);

    dbg_utils_print_module_header(file, "SAI Queue");

    SAI_dump_queue_db_print(file, queue_db);

    free(queue_db);
}
