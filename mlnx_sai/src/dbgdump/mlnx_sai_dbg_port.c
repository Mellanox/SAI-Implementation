/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "mlnx_sai_dbg.h"
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

    *ports_number = g_sai_db_ptr->ports_number;
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

/* mlnx_port_breakout_capability_t */
char *port_breakout_mode_mapper_array[] = {
    "none",     /* MLNX_PORT_BREAKOUT_CAPABILITY_NONE     */
    "two",      /* MLNX_PORT_BREAKOUT_CAPABILITY_TWO      */
    "four",     /* MLNX_PORT_BREAKOUT_CAPABILITY_FOUR     */
    "two four", /* MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR */
};

/* sx_port_mapping_mode_t */
char *port_mapping_mode_mapper_array[] = {
    "disable", /* SX_PORT_MAPPING_MODE_DISABLE */
    "enable",  /* SX_PORT_MAPPING_MODE_ENABLE  */
};

/* mlnx_port_autoneg_type_t */
char *auto_neg_mapper_array[] = {
    "DISABLED", /* AUTO_NEG_DISABLE */
    "ENABLED",  /* AUTO_NEG_ENABLE  */
    "DEFAULT",  /* AUTO_NEG_DEFAULT */
};

mlnx_dbg_dump_enum_mapper_t auto_neg_mapper = {
    .map = auto_neg_mapper_array,
    .size = sizeof(auto_neg_mapper_array) / sizeof(char*)
};

mlnx_dbg_dump_enum_mapper_t port_mapping_mode_mapper = {
    .map = port_mapping_mode_mapper_array,
    .size = sizeof(port_mapping_mode_mapper_array) / sizeof(char*)
};

mlnx_dbg_dump_enum_mapper_t port_breakout_mode_mapper = {
    .map = port_breakout_mode_mapper_array,
    .size = sizeof(port_breakout_mode_mapper_array) / sizeof(char*)
};

static void SAI_dump_port_print(_In_ FILE *file, _In_ mlnx_port_config_t *mlnx_port_config)
{
    uint32_t                  ii = 0;
    mlnx_port_config_t        curr_mlnx_port_config;
    char                      breakout_modes_str[LINE_LENGTH];
    char                      mapping_mode_str[LINE_LENGTH];
    char                      auto_neg_mode_str[LINE_LENGTH];
    char                      adv_speeds_str[LINE_LENGTH];
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
        {"admin state",                11, PARAM_UINT8_E,  &curr_mlnx_port_config.admin_state},
        {"sdk port added",             14, PARAM_UINT8_E,  &curr_mlnx_port_config.sdk_port_added},
        {"auto_neg",                   10, PARAM_STRING_E, &auto_neg_mode_str},
        {"speed",                      10, PARAM_UINT32_E, &curr_mlnx_port_config.speed},
        {"adv speeds num",             16, PARAM_UINT32_E, &curr_mlnx_port_config.adv_speeds_num},
        {"adv speeds",                 30, PARAM_STRING_E, &adv_speeds_str},
        {NULL,                         0,  0,              NULL}
    };

    assert(NULL != mlnx_port_config);

    dbg_utils_print_general_header(file, "Port");

    dbg_utils_print_secondary_header(file, "mlnx_port_config");

    dbg_utils_print_table_headline(file, port_clmns);

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_port_config[ii].is_present) {
            memcpy(&curr_mlnx_port_config, &mlnx_port_config[ii], sizeof(mlnx_port_config_t));

            SAI_dump_enums_to_str(&port_breakout_mode_mapper, (int32_t *)&mlnx_port_config[ii].breakout_modes, 1,
                                  breakout_modes_str, LINE_LENGTH);
            SAI_dump_enums_to_str(&port_mapping_mode_mapper, (int32_t *)&mlnx_port_config[ii].port_map.mapping_mode, 1,
                                  mapping_mode_str, LINE_LENGTH);
            SAI_dump_enums_to_str(&auto_neg_mapper, (int32_t *)&mlnx_port_config[ii].auto_neg, 1,
                                  auto_neg_mode_str, LINE_LENGTH);
            SAI_dump_u32list_to_str(mlnx_port_config[ii].adv_speeds,
                                    mlnx_port_config[ii].adv_speeds_num,
                                    adv_speeds_str, LINE_LENGTH);
            dbg_utils_print_table_data_line(file, port_clmns);
        }
    }
}

void SAI_dump_port(_In_ FILE *file)
{
    uint32_t            ports_number = 0;
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
