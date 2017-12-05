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

static void SAI_dump_qosmaps_getdb(_Out_ mlnx_qos_map_t *qos_maps_db,
                                   _Out_ uint32_t       *switch_qos_maps,
                                   _Out_ uint8_t        *switch_default_tc)
{
    assert(NULL != qos_maps_db);
    assert(NULL != switch_qos_maps);
    assert(NULL != switch_default_tc);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(qos_maps_db,
           g_sai_db_ptr->qos_maps_db,
           MAX_QOS_MAPS * sizeof(mlnx_qos_map_t));

    memcpy(switch_qos_maps,
           g_sai_db_ptr->switch_qos_maps,
           MLNX_QOS_MAP_TYPES_MAX * sizeof(uint32_t));

    *switch_default_tc = g_sai_db_ptr->switch_default_tc;

    sai_db_unlock();
}

static void SAI_dump_qos_map_type_enum_to_str(_In_ sai_qos_map_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    /*case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:*/
    case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
        strcpy(str, "dot1p 2 tc");
        break;

    /*case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:*/
    case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
        strcpy(str, "dot1p 2 color");
        break;

    /*case SAI_QOS_MAP_TYPE_DSCP_TO_TC:*/
    case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
        strcpy(str, "dscp 2 tc");
        break;

    /*case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:*/
    case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
        strcpy(str, "dscp 2 color");
        break;

    /*case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:*/
    case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
        strcpy(str, "tc 2 queue");
        break;

    /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:*/
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
        strcpy(str, "tc and color 2 dscp");
        break;

    /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:*/
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
        strcpy(str, "tc and color 2 dot1p");
        break;

    /*case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:*/
    case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:
        strcpy(str, "tc to prio group");
        break;

    /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:*/
    case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:
        strcpy(str, "pfc prio to prio group");
        break;

    /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:*/
    case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:
        strcpy(str, "pfc prio to queue");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_qos_maps_db_print(_In_ FILE *file, _In_ mlnx_qos_map_t *qos_maps_db)
{
    uint32_t                  ii = 0;
    uint32_t                  jj = 0;
    char                      type_str[LINE_LENGTH];
    mlnx_qos_map_t            curr_qos_maps_db;
    sx_cos_priority_color_t   prio_color;
    sx_cos_pcp_dei_t          pcp_dei;
    sx_cos_dscp_t             dscp                = 0;
    sx_cos_traffic_class_t    queue               = 0;
    uint8_t                   pg                  = 0;
    uint8_t                   pfc                 = 0;
    dbg_utils_table_columns_t qos_maps_db_clmns[] = {
        {"db idx", 11, PARAM_UINT32_E, &ii},
        {"type",   22, PARAM_STRING_E, &type_str},
        {"cnt",    3,  PARAM_UINT8_E,  &curr_qos_maps_db.count},
        {"set",    3,  PARAM_UINT8_E,  &curr_qos_maps_db.is_set },
        {NULL,     0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_dot1p_2_tc_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"pcp from",  8,  PARAM_UINT8_E,  &pcp_dei.pcp},
        {"dei from",  8,  PARAM_UINT8_E,  &pcp_dei.dei},
        {"prio to",   7,  PARAM_UINT8_E,  &prio_color.priority},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_dot1p_2_color_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"pcp from",  8,  PARAM_UINT8_E,  &pcp_dei.pcp},
        {"dei from",  8,  PARAM_UINT8_E,  &pcp_dei.dei},
        {"color to",  7,  PARAM_UINT8_E,  &prio_color.color},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_dscp_2_tc_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"dscp from", 9,  PARAM_UINT8_E,  &dscp},
        {"prio to",   7,  PARAM_UINT8_E,  &prio_color.priority},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_dscp_2_color_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"dscp from", 9,  PARAM_UINT8_E,  &dscp},
        {"color to",  7,  PARAM_UINT8_E,  &prio_color.color},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_tc_2_queue_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"prio from", 9,  PARAM_UINT8_E,  &prio_color.priority},
        {"queue to",  8,  PARAM_UINT8_E,  &queue},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_tc_color_2_dscp_clmns[] = {
        {"param idx",  11, PARAM_UINT32_E, &ii},
        {"prio from",  9,  PARAM_UINT8_E,  &prio_color.priority},
        {"color from", 11, PARAM_UINT8_E,  &prio_color.color},
        {"dscp to",    7,  PARAM_UINT8_E,  &dscp},
        {NULL,         0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_tc_color_2_dot1p_clmns[] = {
        {"param idx",  11, PARAM_UINT32_E, &ii},
        {"prio from",  9,  PARAM_UINT8_E,  &prio_color.priority},
        {"color from", 11, PARAM_UINT8_E,  &prio_color.color},
        {"pcp to",     6,  PARAM_UINT8_E,  &pcp_dei.pcp},
        {"dei to",     6,  PARAM_UINT8_E,  &pcp_dei.dei},
        {NULL,         0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_tc_2_pg_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"prio from", 9,  PARAM_UINT8_E,  &prio_color.priority},
        {"pg to",     5,  PARAM_UINT8_E,  &pg},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_pfc_2_pg_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"pfc from",  8,  PARAM_UINT8_E,  &pfc},
        {"pg to",     5,  PARAM_UINT8_E,  &pg},
        {NULL,        0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_param_pfc_2_queue_clmns[] = {
        {"param idx", 11, PARAM_UINT32_E, &ii},
        {"pfc from",  8,  PARAM_UINT8_E,  &pfc},
        {"queue to",  8,  PARAM_UINT8_E,  &queue},
        {NULL,        0,  0,              NULL}
    };

    assert(NULL != qos_maps_db);

    dbg_utils_print_general_header(file, "Qos maps db");

    dbg_utils_print_secondary_header(file, "qos_maps_db");

    dbg_utils_print_table_headline(file, qos_maps_db_clmns);

    for (ii = 0; ii < MAX_QOS_MAPS; ii++) {
        if (qos_maps_db[ii].is_used) {
            memcpy(&curr_qos_maps_db, &qos_maps_db[ii], sizeof(mlnx_qos_map_t));

            SAI_dump_qos_map_type_enum_to_str(qos_maps_db[ii].type,
                                              type_str);

            dbg_utils_print_table_data_line(file, qos_maps_db_clmns);
        }
    }

    for (ii = 0; ii < MAX_QOS_MAPS; ii++) {
        if (qos_maps_db[ii].is_used) {
            switch (qos_maps_db[ii].type) {
            /*case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:*/
            case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
                dbg_utils_print_table_headline(file, qos_maps_param_dot1p_2_tc_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:*/
            case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
                dbg_utils_print_table_headline(file, qos_maps_param_dot1p_2_color_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_DSCP_TO_TC:*/
            case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
                dbg_utils_print_table_headline(file, qos_maps_param_dscp_2_tc_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:*/
            case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
                dbg_utils_print_table_headline(file, qos_maps_param_dscp_2_color_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:*/
            case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
                dbg_utils_print_table_headline(file, qos_maps_param_tc_2_queue_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:*/
            case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
                dbg_utils_print_table_headline(file, qos_maps_param_tc_color_2_dscp_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:*/
            case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
                dbg_utils_print_table_headline(file, qos_maps_param_tc_color_2_dot1p_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:*/
            case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:
                dbg_utils_print_table_headline(file, qos_maps_param_tc_2_pg_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:*/
            case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:
                dbg_utils_print_table_headline(file, qos_maps_param_pfc_2_pg_clmns);
                break;

            /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:*/
            case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:
                dbg_utils_print_table_headline(file, qos_maps_param_pfc_2_queue_clmns);
                break;

            default:
                break;
            }

            for (jj = 0; jj < qos_maps_db[ii].count; jj++) {
                switch (qos_maps_db[ii].type) {
                /*case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:*/
                case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
                    pcp_dei.pcp         = qos_maps_db[ii].from.pcp_dei[jj].pcp;
                    pcp_dei.dei         = qos_maps_db[ii].from.pcp_dei[jj].dei;
                    prio_color.priority = qos_maps_db[ii].to.prio_color[jj].priority;
                    dbg_utils_print_table_data_line(file, qos_maps_param_dot1p_2_tc_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:*/
                case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
                    pcp_dei.pcp      = qos_maps_db[ii].from.pcp_dei[jj].pcp;
                    pcp_dei.dei      = qos_maps_db[ii].from.pcp_dei[jj].dei;
                    prio_color.color = qos_maps_db[ii].to.prio_color[jj].color;
                    dbg_utils_print_table_data_line(file, qos_maps_param_dot1p_2_color_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_DSCP_TO_TC:*/
                case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
                    dscp                = qos_maps_db[ii].from.dscp[jj];
                    prio_color.priority = qos_maps_db[ii].to.prio_color[jj].priority;
                    dbg_utils_print_table_data_line(file, qos_maps_param_dscp_2_tc_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:*/
                case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
                    dscp             = qos_maps_db[ii].from.dscp[jj];
                    prio_color.color = qos_maps_db[ii].to.prio_color[jj].color;
                    dbg_utils_print_table_data_line(file, qos_maps_param_dscp_2_color_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:*/
                case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
                    prio_color.priority = qos_maps_db[ii].from.prio_color[jj].priority;
                    queue               = qos_maps_db[ii].to.queue[jj];
                    dbg_utils_print_table_data_line(file, qos_maps_param_tc_2_queue_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:*/
                case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
                    prio_color.priority = qos_maps_db[ii].from.prio_color[jj].priority;
                    prio_color.color    = qos_maps_db[ii].from.prio_color[jj].color;
                    queue               = qos_maps_db[ii].to.queue[jj];
                    dbg_utils_print_table_data_line(file, qos_maps_param_tc_color_2_dscp_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:*/
                case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
                    prio_color.priority = qos_maps_db[ii].from.prio_color[jj].priority;
                    prio_color.color    = qos_maps_db[ii].from.prio_color[jj].color;
                    pcp_dei.pcp         = qos_maps_db[ii].to.pcp_dei[jj].pcp;
                    pcp_dei.dei         = qos_maps_db[ii].to.pcp_dei[jj].dei;
                    dbg_utils_print_table_data_line(file, qos_maps_param_tc_color_2_dot1p_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:*/
                case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:
                    prio_color.priority = qos_maps_db[ii].from.prio_color[jj].priority;
                    pg                  = qos_maps_db[ii].to.pg[jj];
                    dbg_utils_print_table_data_line(file, qos_maps_param_tc_2_pg_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:*/
                case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP:
                    pfc = qos_maps_db[ii].from.pfc[jj];
                    pg  = qos_maps_db[ii].to.pg[jj];
                    dbg_utils_print_table_data_line(file, qos_maps_param_pfc_2_pg_clmns);
                    break;

                /*case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:*/
                case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:
                    pfc   = qos_maps_db[ii].from.pfc[jj];
                    queue = qos_maps_db[ii].to.queue[jj];
                    dbg_utils_print_table_data_line(file, qos_maps_param_pfc_2_queue_clmns);
                    break;

                default:
                    break;
                }
            }
        }
    }
}

static void SAI_dump_switch_qos_maps_print(_In_ FILE *file, _In_ uint32_t *switch_qos_maps)
{
    uint32_t                  ii                      = 0;
    uint32_t                  curr_switch_qos_maps    = 0;
    dbg_utils_table_columns_t switch_qos_maps_clmns[] = {
        {"db idx",          7,  PARAM_UINT32_E, &ii},
        {"switch qos maps", 15, PARAM_UINT32_E, &curr_switch_qos_maps},
        {NULL,              0,  0,              NULL}
    };

    assert(NULL != switch_qos_maps);

    dbg_utils_print_general_header(file, "Switch qos maps");

    dbg_utils_print_secondary_header(file, "switch_qos_maps");

    dbg_utils_print_table_headline(file, switch_qos_maps_clmns);

    for (ii = 0; ii < MLNX_QOS_MAP_TYPES_MAX; ii++) {
        curr_switch_qos_maps = switch_qos_maps[ii];
        dbg_utils_print_table_data_line(file, switch_qos_maps_clmns);
    }
}

static void SAI_dump_switch_default_tc_print(_In_ FILE *file, _In_ uint8_t *switch_default_tc)
{
    assert(NULL != switch_default_tc);

    dbg_utils_print_general_header(file, "Switch default tc");

    dbg_utils_print_field(file, "switch_default_tc", switch_default_tc, PARAM_UINT8_E);
    dbg_utils_print(file, "\n");
}

void SAI_dump_qosmaps(_In_ FILE *file)
{
    mlnx_qos_map_t *qos_maps_db       = NULL;
    uint32_t       *switch_qos_maps   = NULL;
    uint8_t         switch_default_tc = 0;

    qos_maps_db     = (mlnx_qos_map_t*)calloc(MAX_QOS_MAPS, sizeof(mlnx_qos_map_t));
    switch_qos_maps = (uint32_t*)calloc(MLNX_QOS_MAP_TYPES_MAX, sizeof(uint32_t));

    if ((!qos_maps_db) || (!switch_qos_maps)) {
        if (qos_maps_db) {
            free(qos_maps_db);
        }
        if (switch_qos_maps) {
            free(switch_qos_maps);
        }

        return;
    }

    SAI_dump_qosmaps_getdb(qos_maps_db,
                           switch_qos_maps,
                           &switch_default_tc);

    dbg_utils_print_module_header(file, "SAI Qosmaps");

    SAI_dump_qos_maps_db_print(file, qos_maps_db);
    SAI_dump_switch_qos_maps_print(file, switch_qos_maps);
    SAI_dump_switch_default_tc_print(file, &switch_default_tc);

    free(qos_maps_db);
    free(switch_qos_maps);
}
