/*
 *  Copyright (C) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

static void SAI_dump_ar_getdb(_Out_ mlnx_ar_db_data_t *mlnx_ar_config)
{
    assert(NULL != mlnx_ar_config);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_ar_config,
           &g_sai_db_ptr->ar_db,
           sizeof(mlnx_ar_db_data_t));

    sai_db_unlock();
}

static void SAI_dump_ar_print(_In_ FILE *file, _In_ mlnx_ar_db_data_t *ar_config)
{
    dbg_utils_table_columns_t ar_profile_clmns[] = {
        {"Port count", 15, PARAM_UINT32_E,  &ar_config->ar_port_count},
        {"Profile_key", 15, PARAM_UINT32_E,  &ar_config->profile_key.profile},
        {"Mode", 8, PARAM_UINT32_E,  &ar_config->profile_attr.mode},
        {"Threshold:free", 32, PARAM_UINT8_E,  &ar_config->profile_attr.profile_threshold.free_threshold},
        {"Threshold:busy", 32, PARAM_UINT8_E,  &ar_config->profile_attr.profile_threshold.busy_threshold},
        {"Only_elephant_enable", 32, PARAM_BOOL_E,  &ar_config->profile_attr.only_elephant_en},
        {"Enable shaper_to rate", 32, PARAM_BOOL_E,
         &ar_config->profile_attr.shaper_attr_filter.to_shaper_is_enable},
        {"Enable shaper_from rate", 32, PARAM_BOOL_E,
         &ar_config->profile_attr.shaper_attr_filter.from_shaper_is_enable},
        {"Bind time", 24, PARAM_UINT32_E,  &ar_config->profile_attr.bind_time},
        {"Default_classifier_action", 32, PARAM_UINT32_E,
         &ar_config->default_classifier_action.ar_flow_classification},
        {"Classifier_id", 16, PARAM_UINT32_E,  &ar_config->classifier_id},
        {"Classifier_key_l4", 24, PARAM_UINT32_E,  &ar_config->classifier_attr.key.l4},
        {"Classifier_bth_ar", 24, PARAM_UINT32_E,  &ar_config->classifier_attr.key.bth_ar},
        {"Classifier_action", 24, PARAM_UINT32_E,  &ar_config->classifier_action.ar_flow_classification},
        {"Congestion low threshold", 32, PARAM_UINT32_E,
         &ar_config->congestion_threshold.port_threshold.congestion_thresh_lo},
        {"Congestion medium threshold", 32, PARAM_UINT32_E,
         &ar_config->congestion_threshold.port_threshold.congestion_thresh_med},
        {"Congestion high threshold", 32, PARAM_UINT32_E,
         &ar_config->congestion_threshold.port_threshold.congestion_thresh_hi},
        {"Shaper_rate_to", 32, PARAM_UINT32_E,  &ar_config->shaper_attr.shaper_rate_to},
        {"Shaper_rate_from", 32, PARAM_UINT32_E,  &ar_config->shaper_attr.shaper_rate_from},
        {"Ecmp size", 32, PARAM_UINT32_E,  &ar_config->ar_ecmp_size},
        {NULL,           0,  0,              NULL}
    };

    dbg_utils_print_general_header(file, "AR Info");

    dbg_utils_print_secondary_header(file, "AR_profile_config");

    dbg_utils_print_table_headline(file, ar_profile_clmns);

    dbg_utils_print_table_data_line(file, ar_profile_clmns);
    dbg_utils_print_secondary_header(file, "AR Ports");
    for (uint32_t ii = 0; ii < ar_config->ar_port_count; ii++) {
        dbg_utils_table_columns_t ar_port_clmns[] = {
            {"AR port index", 15, PARAM_UINT32_E,  &ii},
            {"AR port logical", 15, PARAM_HEX_E,  &ar_config->ar_port_list[ii].port_id},
            {"AR port link_util_percentage", 28, PARAM_UINT32_E,  &ar_config->ar_port_list[ii].link_util_percentage},
            {NULL,           0,  0,              NULL}
        };

        dbg_utils_print_table_headline(file, ar_port_clmns);
        dbg_utils_print_table_data_line(file, ar_port_clmns);

        dbg_utils_print_secondary_header(file, "AR port %d lanes", ii);
        for (uint32_t jj = 0; jj < ar_config->ar_port_list[ii].lane_count; jj++) {
            dbg_utils_print_field(file, "lane", &ar_config->ar_port_list[ii].lane_list[jj], PARAM_UINT32_E);
        }
    }
}

void SAI_dump_ar(_In_ FILE *file)
{
    /* coverity[stack_use_local_overflow] */
    mlnx_ar_db_data_t mlnx_ar_config = {0};

    SAI_dump_ar_getdb(&mlnx_ar_config);
    dbg_utils_print_module_header(file, "SAI AR");
    SAI_dump_ar_print(file, &mlnx_ar_config);
}
