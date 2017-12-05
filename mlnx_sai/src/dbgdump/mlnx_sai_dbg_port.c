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

static void SAI_dump_port_getdb(_Out_ uint32_t           *ports_number,
                                _Out_ uint32_t           *ports_configured,
                                _Out_ mlnx_port_config_t *mlnx_port_config)
{
    assert(NULL != ports_number);
    assert(NULL != ports_configured);
    assert(NULL != mlnx_port_config);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    *ports_number     = g_sai_db_ptr->ports_number;
    *ports_configured = g_sai_db_ptr->ports_configured;
    memcpy(mlnx_port_config,
           g_sai_db_ptr->ports_db,
           MAX_PORTS * 2 * sizeof(mlnx_port_config_t));

    sai_db_unlock();
}

static void SAI_dump_ports_number_print(_In_ FILE *file, _In_ uint32_t *ports_number)
{
    assert(NULL != ports_number);

    dbg_utils_print_general_header(file, "Ports number");

    dbg_utils_print_field(file, "ports number", ports_number, PARAM_UINT32_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_ports_configured_print(_In_ FILE *file, _In_ uint32_t *ports_configured)
{
    assert(NULL != ports_configured);

    dbg_utils_print_general_header(file, "Ports configured");

    dbg_utils_print_field(file, "ports configured", ports_configured, PARAM_UINT32_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_port_breakoutmode_enum_to_str(_In_ mlnx_port_breakout_capability_t mode, _Out_ char *str)
{
    assert(NULL != str);

    switch (mode) {
    case MLNX_PORT_BREAKOUT_CAPABILITY_NONE:
        strcpy(str, "none");
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_TWO:
        strcpy(str, "two");
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_FOUR:
        strcpy(str, "four");
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR:
        strcpy(str, "two four");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_port_mapping_mode_enum_to_str(_In_ sx_port_mapping_mode_t mode, _Out_ char *str)
{
    assert(NULL != str);

    switch (mode) {
    case SX_PORT_MAPPING_MODE_DISABLE:
        strcpy(str, "disable");
        break;

    case SX_PORT_MAPPING_MODE_ENABLE:
        strcpy(str, "enable");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_port_print(_In_ FILE *file, _In_ mlnx_port_config_t *mlnx_port_config)
{
    uint32_t                  ii = 0;
    uint32_t                  jj = 0;
    uint32_t                  kk = 0;
    mlnx_port_config_t        curr_mlnx_port_config;
    uint32_t                  curr_qos_maps;
    sai_object_id_t           curr_port_policers;
    uint8_t                   curr_groups_count;
    sai_object_id_t           curr_groups_scheduler_id;
    char                      breakout_modes_str[LINE_LENGTH];
    char                      mapping_mode_str[LINE_LENGTH];
    dbg_utils_table_columns_t port_clmns[] = {
        {"sai oid",                    16, PARAM_UINT64_E, &curr_mlnx_port_config.saiport},
        {"db idx",                     7,  PARAM_UINT32_E, &ii},
        {"index",                      5,  PARAM_UINT8_E,  &curr_mlnx_port_config.index},
        {"module",                     6,  PARAM_UINT32_E, &curr_mlnx_port_config.module},
        {"width",                      5,  PARAM_UINT32_E, &curr_mlnx_port_config.width},
        {"breakout mode",              13, PARAM_STRING_E, &breakout_modes_str},
        {"speed bitmap",               11, PARAM_UINT32_E, &curr_mlnx_port_config.speed_bitmap},
        {"logical",                    11, PARAM_UINT32_E, &curr_mlnx_port_config.logical},
        {"is split",                   8,  PARAM_UINT8_E,  &curr_mlnx_port_config.is_split},
        {"split count",                11, PARAM_UINT8_E,  &curr_mlnx_port_config.split_count},
        {"mapping local port",         18, PARAM_UINT8_E,  &curr_mlnx_port_config.port_map.local_port},
        {"mapping mode",               12, PARAM_STRING_E, &mapping_mode_str},
        {"mapping module port",        19, PARAM_UINT8_E,  &curr_mlnx_port_config.port_map.module_port},
        {"mapping width",              13, PARAM_UINT8_E,  &curr_mlnx_port_config.port_map.width},
        {"mapping lane bamp",          17, PARAM_UINT8_E,  &curr_mlnx_port_config.port_map.lane_bmap},
        {"mapping config hw",          17, PARAM_UINT8_E,  &curr_mlnx_port_config.port_map.config_hw},
        {"default tc",                 10, PARAM_UINT8_E,  &curr_mlnx_port_config.default_tc},
        {"lag id",                     11, PARAM_UINT32_E, &curr_mlnx_port_config.lag_id},
        {"ingress samplepacket idx",   24, PARAM_UINT32_E,
         &curr_mlnx_port_config.internal_ingress_samplepacket_obj_idx},
        {"egress samplepacket idx",    23, PARAM_UINT32_E,
         &curr_mlnx_port_config.internal_egress_samplepacket_obj_idx},
        {"wred id",                    16, PARAM_UINT64_E, &curr_mlnx_port_config.wred_id},
        {"scheduler id",               16, PARAM_UINT64_E, &curr_mlnx_port_config.scheduler_id},
        {"start queue index",          17, PARAM_UINT32_E, &curr_mlnx_port_config.start_queues_index},
        {"is default sched hierarchy", 17, PARAM_UINT8_E,  &curr_mlnx_port_config.sched_hierarchy.is_default},
        {"rif",                        5,  PARAM_UINT16_E, &curr_mlnx_port_config.rifs},
        /* {"vlan",                       5,  PARAM_UINT16_E, &curr_mlnx_port_config.vlans}, */
        /* {"fdb",                        5,  PARAM_UINT32_E, &curr_mlnx_port_config.fdbs}, */
        {NULL,                         0,  0,              NULL}
    };
    dbg_utils_table_columns_t qos_maps_clmns[] = {
        {"db idx",   7,  PARAM_UINT32_E, &jj},
        {"qos maps", 13, PARAM_UINT32_E, &curr_qos_maps},
        {NULL,       0,  0,              NULL}
    };
    dbg_utils_table_columns_t port_policers_clmns[] = {
        {"db idx",        7,  PARAM_UINT32_E, &jj},
        {"port policers", 13, PARAM_UINT64_E, &curr_port_policers},
        {NULL,            0,  0,              NULL}
    };
    dbg_utils_table_columns_t groups_scheduler_id_clmns[] = {
        {"level",        13, PARAM_UINT32_E, &jj},
        {"groups count", 13, PARAM_UINT8_E,  &curr_groups_count},
        {"index",        13, PARAM_UINT32_E, &kk},
        {"scheduler id", 13, PARAM_UINT64_E, &curr_groups_scheduler_id},
        {NULL,           0,  0,              NULL}
    };

    assert(NULL != mlnx_port_config);

    dbg_utils_print_general_header(file, "Port");

    dbg_utils_print_secondary_header(file, "mlnx_port_config");

    dbg_utils_print_table_headline(file, port_clmns);

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_port_config[ii].is_present) {
            memcpy(&curr_mlnx_port_config, &mlnx_port_config[ii], sizeof(mlnx_port_config_t));

            SAI_dump_port_breakoutmode_enum_to_str(mlnx_port_config[ii].breakout_modes,
                                                   breakout_modes_str);
            SAI_dump_port_mapping_mode_enum_to_str(mlnx_port_config[ii].port_map.mapping_mode,
                                                   mapping_mode_str);
            dbg_utils_print_table_data_line(file, port_clmns);
        }
    }

    dbg_utils_print_secondary_header(file, "port qos_maps");

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_port_config[ii].is_present) {
            dbg_utils_print_secondary_header(file, "port %d qos_maps", ii);
            dbg_utils_print_table_headline(file, qos_maps_clmns);

            for (jj = 0; jj < MLNX_QOS_MAP_TYPES_MAX; jj++) {
                curr_qos_maps = mlnx_port_config[ii].qos_maps[jj];
                dbg_utils_print_table_data_line(file, qos_maps_clmns);
            }
        }
    }

    dbg_utils_print_secondary_header(file, "port policers");

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_port_config[ii].is_present) {
            dbg_utils_print_secondary_header(file, "port %d policers", ii);
            dbg_utils_print_table_headline(file, port_policers_clmns);

            for (jj = 0; jj < MLNX_PORT_POLICER_TYPE_MAX; jj++) {
                curr_port_policers = mlnx_port_config[ii].port_policers[jj];
                dbg_utils_print_table_data_line(file, port_policers_clmns);
            }
        }
    }

    dbg_utils_print_secondary_header(file, "sched hierarchy");

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_port_config[ii].is_present) {
            dbg_utils_print_secondary_header(file, "port %d sched hierarchy", ii);
            dbg_utils_print_table_headline(file, groups_scheduler_id_clmns);

            for (jj = 0; jj < MAX_SCHED_LEVELS; jj++) {
                curr_groups_count = mlnx_port_config[ii].sched_hierarchy.groups_count[jj];

                for (kk = 0; kk < curr_groups_count; kk++) {
                    curr_groups_scheduler_id = mlnx_port_config[ii].sched_hierarchy.groups[jj][kk].scheduler_id;
                    dbg_utils_print_table_data_line(file, groups_scheduler_id_clmns);
                }
            }
        }
    }
}

void SAI_dump_port(_In_ FILE *file)
{
    uint32_t            ports_number     = 0;
    uint32_t            ports_configured = 0;
    mlnx_port_config_t *mlnx_port_config;

    mlnx_port_config = (mlnx_port_config_t*)calloc(MAX_PORTS * 2, sizeof(mlnx_port_config_t));
    if (!mlnx_port_config) {
        return;
    }

    SAI_dump_port_getdb(&ports_number,
                        &ports_configured,
                        mlnx_port_config);
    dbg_utils_print_module_header(file, "SAI Port");
    SAI_dump_ports_number_print(file, &ports_number);
    SAI_dump_ports_configured_print(file, &ports_configured);
    SAI_dump_port_print(file, mlnx_port_config);

    free(mlnx_port_config);
}
