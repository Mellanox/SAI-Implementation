/*
 *  Copyright (C) 2014. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
        strcpy(str, "2  ");
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_FOUR:
        strcpy(str, "4  ");
        break;

    case MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR:
        strcpy(str, "2 4");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_port_print(_In_ FILE *file, _In_ mlnx_port_config_t *mlnx_port_config)
{
    uint32_t                  ii = 0;
    mlnx_port_config_t        curr_mlnx_port_config;
    char                      breakout_modes_str[LINE_LENGTH];
    dbg_utils_table_columns_t port_clmns[] = {
        {"sai oid",     16, PARAM_UINT64_E, &curr_mlnx_port_config.saiport},
        {"db idx",      7,  PARAM_UINT32_E, &ii},
        {"index",       5,  PARAM_UINT8_E,  &curr_mlnx_port_config.index},
        {"module",      6,  PARAM_UINT32_E, &curr_mlnx_port_config.module},
        {"width",       5,  PARAM_UINT32_E, &curr_mlnx_port_config.width},
        {"breakout",    8,  PARAM_STRING_E, &breakout_modes_str},
        {"speed",       11, PARAM_UINT32_E, &curr_mlnx_port_config.port_speed},
        {"logical",     11, PARAM_UINT32_E, &curr_mlnx_port_config.logical},
        {"split",       5,  PARAM_BOOL_E,   &curr_mlnx_port_config.is_split},
        {"split cnt",   9,  PARAM_UINT8_E,  &curr_mlnx_port_config.split_count},
        {"dflt tc",     7,  PARAM_UINT8_E,  &curr_mlnx_port_config.default_tc},
        {"lag id",      11, PARAM_UINT32_E, &curr_mlnx_port_config.lag_id},
        {"i sflow idx", 11, PARAM_UINT32_E, &curr_mlnx_port_config.internal_ingress_samplepacket_obj_idx},
        {"e sflow idx", 11, PARAM_UINT32_E, &curr_mlnx_port_config.internal_egress_samplepacket_obj_idx},
        {"rif",         5,  PARAM_UINT16_E, &curr_mlnx_port_config.rifs},
        {"vlan",        5,  PARAM_UINT16_E, &curr_mlnx_port_config.vlans},
        {NULL,          0,  0,              NULL}
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
            dbg_utils_print_table_data_line(file, port_clmns);
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
