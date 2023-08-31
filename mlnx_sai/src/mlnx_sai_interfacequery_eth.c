/*
 *  Copyright (C) 2017-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"

#include "sai.h"
#include <errno.h>
#include "mlnx_sai.h"
#include <saimetadata.h>
#include <sx/utils/dbg_utils.h>
#ifndef _WIN32
#include <libgen.h>
#include <dirent.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_INTERFACE_QUERY_ETH

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t sai_dbg_do_dump(_In_ const char *dump_file_name);
static sai_status_t sai_dbg_run_mlxtrace(_In_ const char *dirname);

sai_status_t mlnx_interfacequery_eth_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_api_query_eth(_In_ sai_api_t sai_api_id, _Out_ void** api_method_table)
{
    switch (sai_api_id) {
    case SAI_API_BRIDGE:
        *(const sai_bridge_api_t**)api_method_table = &mlnx_bridge_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SWITCH:
        *(const sai_switch_api_t**)api_method_table = &mlnx_switch_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_PORT:
        *(const sai_port_api_t**)api_method_table = &mlnx_port_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_FDB:
        *(const sai_fdb_api_t**)api_method_table = &mlnx_fdb_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VLAN:
        *(const sai_vlan_api_t**)api_method_table = &mlnx_vlan_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VIRTUAL_ROUTER:
        *(const sai_virtual_router_api_t**)api_method_table = &mlnx_router_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTE:
        *(const sai_route_api_t**)api_method_table = &mlnx_route_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP:
        *(const sai_next_hop_api_t**)api_method_table = &mlnx_next_hop_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP_GROUP:
        *(const sai_next_hop_group_api_t**)api_method_table = &mlnx_next_hop_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTER_INTERFACE:
        *(const sai_router_interface_api_t**)api_method_table = &mlnx_router_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEIGHBOR:
        *(const sai_neighbor_api_t**)api_method_table = &mlnx_neighbor_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ACL:
        *(const sai_acl_api_t**)api_method_table = &mlnx_acl_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HOSTIF:
        *(const sai_hostif_api_t**)api_method_table = &mlnx_host_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QOS_MAP:
        *(const sai_qos_map_api_t**)api_method_table = &mlnx_qos_maps_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_WRED:
        *(const sai_wred_api_t**)api_method_table = &mlnx_wred_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QUEUE:
        *(const sai_queue_api_t**)api_method_table = &mlnx_queue_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER:
        *(const sai_scheduler_api_t**)api_method_table = &mlnx_scheduler_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_POLICER:
        *(const sai_policer_api_t**)api_method_table = &mlnx_policer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_MIRROR:
        *(const sai_mirror_api_t**)api_method_table = &mlnx_mirror_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SAMPLEPACKET:
        *(const sai_samplepacket_api_t**)api_method_table = &mlnx_samplepacket_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_STP:
        *(const sai_stp_api_t**)api_method_table = &mlnx_stp_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_LAG:
        *(const sai_lag_api_t**)api_method_table = &mlnx_lag_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER_GROUP:
        *(const sai_scheduler_group_api_t**)api_method_table = &mlnx_scheduler_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_BUFFER:
        *(const sai_buffer_api_t**)api_method_table = &mlnx_buffer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HASH:
        *(const sai_hash_api_t**)api_method_table = &mlnx_hash_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_UDF:
        *(const sai_udf_api_t**)api_method_table = &mlnx_udf_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_TUNNEL:
        *(const sai_tunnel_api_t**)api_method_table = &mlnx_tunnel_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_L2MC_GROUP:
        *(const sai_l2mc_group_api_t**)api_method_table = &mlnx_l2mc_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_DEBUG_COUNTER:
        *(const sai_debug_counter_api_t**)api_method_table = &mlnx_debug_counter_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_BFD:
        *(const sai_bfd_api_t**)api_method_table = &mlnx_bfd_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_COUNTER:
        *(const sai_counter_api_t**)api_method_table = &mlnx_counter_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ISOLATION_GROUP:
        *(const sai_isolation_group_api_t**)api_method_table = &mlnx_isolation_group_api;
        return SAI_STATUS_SUCCESS;

    default:
        if (sai_api_id >= (sai_api_t)SAI_API_EXTENSIONS_RANGE_END) {
            MLNX_SAI_LOG_ERR("SAI API %d is out of range [%d, %d]\n",
                             sai_api_id,
                             SAI_API_SWITCH,
                             SAI_API_EXTENSIONS_RANGE_END);
            return SAI_STATUS_INVALID_PARAMETER;
        } else {
            MLNX_SAI_LOG_WRN("%s not implemented\n", sai_metadata_get_api_name(sai_api_id));
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }
}

sai_status_t sai_log_set_eth(_In_ sai_api_t sai_api_id, sx_log_severity_t severity)
{
    switch (sai_api_id) {
    case SAI_API_SWITCH:
        mlnx_switch_log_set(severity);
        mlnx_interfacequery_log_set(severity);
        mlnx_interfacequery_eth_log_set(severity);
        mlnx_utils_log_set(severity);
        mlnx_utils_eth_log_set(severity);
        mlnx_issu_storage_log_set(severity);
        mlnx_object_eth_log_set(severity);
        return mlnx_object_log_set(severity);

    case SAI_API_BRIDGE:
        return mlnx_bridge_log_set(severity);

    case SAI_API_PORT:
        return mlnx_port_log_set(severity);

    case SAI_API_FDB:
        return mlnx_fdb_log_set(severity);

    case SAI_API_VLAN:
        return mlnx_vlan_log_set(severity);

    case SAI_API_VIRTUAL_ROUTER:
        return mlnx_router_log_set(severity);

    case SAI_API_ROUTE:
        return mlnx_route_log_set(severity);

    case SAI_API_NEXT_HOP:
        return mlnx_nexthop_log_set(severity);

    case SAI_API_NEXT_HOP_GROUP:
        return mlnx_nexthop_group_log_set(severity);

    case SAI_API_ROUTER_INTERFACE:
        return mlnx_rif_log_set(severity);

    case SAI_API_NEIGHBOR:
        return mlnx_neighbor_log_set(severity);

    case SAI_API_ACL:
        return mlnx_acl_log_set(severity);

    case SAI_API_HOSTIF:
        return mlnx_host_interface_log_set(severity);

    case SAI_API_QOS_MAP:
        return mlnx_qos_map_log_set(severity);

    case SAI_API_WRED:
        return mlnx_wred_log_set(severity);

    case SAI_API_QUEUE:
        return mlnx_queue_log_set(severity);

    case SAI_API_SCHEDULER:
        return mlnx_scheduler_log_set(severity);

    case SAI_API_POLICER:
        return mlnx_policer_log_set(severity);

    case SAI_API_MIRROR:
        return mlnx_mirror_log_set(severity);

    case SAI_API_SAMPLEPACKET:
        return mlnx_samplepacket_log_set(severity);

    case SAI_API_STP:
        return mlnx_stp_log_set(severity);

    case SAI_API_LAG:
        return mlnx_lag_log_set(severity);

    case SAI_API_SCHEDULER_GROUP:
        return mlnx_scheduler_group_log_set(severity);

    case SAI_API_BUFFER:
        return mlnx_sai_buffer_log_set(severity);

    case SAI_API_HASH:
        return mlnx_hash_log_set(severity);

    case SAI_API_UDF:
        return mlnx_udf_log_set(severity);

    case SAI_API_TUNNEL:
        return mlnx_tunnel_log_set(severity);

    case SAI_API_L2MC_GROUP:
        return mlnx_l2mc_group_log_set(severity);

    case SAI_API_DEBUG_COUNTER:
        return mlnx_debug_counter_log_set(severity);

    case SAI_API_BFD:
        return mlnx_bfd_log_set(severity);

    case SAI_API_COUNTER:
        return mlnx_counter_log_set(severity);

    case SAI_API_ISOLATION_GROUP:
        return mlnx_isolation_group_log_set(severity);

    default:
        if (sai_api_id >= (sai_api_t)SAI_API_EXTENSIONS_RANGE_END) {
            MLNX_SAI_LOG_ERR("SAI API %d is out of range [%d, %d]\n",
                             sai_api_id,
                             SAI_API_SWITCH,
                             SAI_API_EXTENSIONS_RANGE_END);
            return SAI_STATUS_INVALID_PARAMETER;
        } else {
            MLNX_SAI_LOG_WRN("%s not implemented\n", sai_metadata_get_api_name(sai_api_id));
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }
}

/**
 * @brief Generate dump file. The dump file may include SAI state information and vendor SDK information.
 *
 * @param[in] dump_file_name Full path for dump file
 * @param[in] flags Flags regarding optional dump behavior
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_dbg_generate_dump_ext(_In_ const char *dump_file_name, _In_ int32_t flags)
{
    sx_dbg_extra_info_t dbg_info;
    sai_status_t        status = SAI_STATUS_SUCCESS;
    sx_status_t         sx_status = SX_STATUS_ERROR;

#ifndef _WIN32
    char *file_name = NULL;
#endif

    status = sai_dbg_do_dump(dump_file_name);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Start async sx_api_dbg_generate_dump_extra */
    memset(&dbg_info, 0, sizeof(dbg_info));
    dbg_info.dev_id = SX_DEVICE_ID;
    dbg_info.force_db_refresh = true;
    dbg_info.is_async = true;
    dbg_info.ir_dump_enable = (flags > 1) ? true : false;

#ifndef _WIN32
    file_name = strdup(dump_file_name);
    strncpy(dbg_info.path, dirname(file_name), sizeof(dbg_info.path));
    dbg_info.path[sizeof(dbg_info.path) - 1] = 0;
    free(file_name);
#endif

    sx_status = sx_api_dbg_generate_dump_extra(gh_sdk, &dbg_info);
    if (SX_ERR(sx_status)) {
        MLNX_SAI_LOG_ERR("Error generating extended sdk dump, sx status: %s\n", SX_STATUS_MSG(sx_status));
    }

    status = wait_for_sem(&g_sai_db_ptr->dfw_sem, 25);
    if (SX_ERR(status)) {
        MLNX_SAI_LOG_ERR("Failed to wait on DFW semaphore.\n");
        goto out;
    }

out:
    return SAI_STATUS_SUCCESS;
}
/**
 * @brief Generate dump file. The dump file may include SAI state information and vendor SDK information.
 *
 * @param[in] dump_file_name Full path for dump file
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t sai_dbg_generate_dump(_In_ const char *dump_file_name)
{
    return sai_dbg_generate_dump_ext(dump_file_name, 0);
}

sai_status_t sai_dbg_do_dump(_In_ const char *dump_file_name)
{
    FILE       *file = NULL;
    sx_status_t sdk_status = SX_STATUS_ERROR;
    char        dump_directory[SX_API_DUMP_PATH_LEN_LIMIT + 1];

#ifndef _WIN32
    sai_status_t sai_status = SAI_STATUS_FAILURE;
    char        *file_name = NULL;
#endif

    if (!gh_sdk) {
        MLNX_SAI_LOG_ERR("Can't generate debug dump before creating switch\n");
        return SAI_STATUS_FAILURE;
    }

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_dbg_generate_dump(gh_sdk, dump_file_name))) {
        MLNX_SAI_LOG_ERR("Error generating sdk dump, sx status: %s\n", SX_STATUS_MSG(sdk_status));
    }

    file = fopen(dump_file_name, "a");

    if (NULL == file) {
        MLNX_SAI_LOG_ERR("Error opening file %s with write permission\n", dump_file_name);
        return SAI_STATUS_FAILURE;
    }

    dbg_utils_print_module_header(file, "SAI DEBUG DUMP");

    SAI_dump_acl(file);

    SAI_dump_gp_reg(file);

    SAI_dump_buffer(file);

    SAI_dump_hash(file);

    SAI_dump_hostintf(file);

    SAI_dump_mirror(file);

    SAI_dump_policer(file);

    SAI_dump_port(file);

    SAI_dump_ar(file);

    SAI_dump_qosmaps(file);

    SAI_dump_queue(file);

    SAI_dump_samplepacket(file);

    SAI_dump_scheduler(file);

    SAI_dump_stp(file);

    SAI_dump_tunnel(file);

    SAI_dump_vlan(file);

    SAI_dump_wred(file);

    SAI_dump_bridge(file);

    SAI_dump_udf(file);

    SAI_dump_debug_counter(file);

    SAI_dump_bfd(file);

    SAI_dump_isolation_group(file);

    SAI_dump_nhg_nhgm(file);

    SAI_dump_nh(file);

    fclose(file);

#ifndef _WIN32
    file_name = strdup(dump_file_name);
    snprintf(dump_directory, sizeof(dump_directory), "%s", dirname(file_name));
    dump_directory[sizeof(dump_directory) - 1] = 0;
    sai_status = sai_dbg_run_mlxtrace(dump_directory);
    if (SAI_ERR(sai_status)) {
        MLNX_SAI_LOG_ERR("Failed to run mlxtrace\n");
    }
    free(file_name);
#endif

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_dbg_run_mlxtrace(_In_ const char *dirname)
{
    const char mlxtrace_ext_command_line_fmt[] =
        "mlxtrace_ext -d /dev/mst/%s %s %s%s -m MEM -a OB_GW -n -o %s/%s_mlxtrace.trc >/dev/null 2>&1";
    const char                      *device_name = NULL;
    const char                      *config_file_name = NULL;
    char                             mlxtrace_ext_command_line[2 * PATH_MAX + 200];
    int                              system_err;
    const mlnx_dump_configuration_t *dump_conf = &g_sai_db_ptr->dump_configuration;
    bool                             config_file_needed = false;

    if ((mlnx_chip_is_spc2()) || (mlnx_chip_is_spc3())) {
        config_file_needed = true;
    }

    if (config_file_needed) {
#ifndef _WIN32
        DIR *d = opendir(dump_conf->mft_cfg_path);
        if (NULL == d) {
            return SAI_STATUS_SUCCESS;
        } else {
            closedir(d);
        }
#endif
    }

    if (mlnx_chip_is_spc()) {
        device_name = "mt52100_pci_cr0";
    } else if (mlnx_chip_is_spc2()) {
        device_name = "mt53100_pci_cr0";
        config_file_name = "/mlxtrace_spectrum2_itrace.cfg.ext";
    } else if (mlnx_chip_is_spc3()) {
        device_name = "mt53104_pci_cr0";
        config_file_name = "/mlxtrace_spectrum3_itrace.cfg.ext";
    } else if (mlnx_chip_is_spc4()) {
        /* TODO : replace with secure tool for SPC4 */
        return SAI_STATUS_SUCCESS;
    } else {
        SX_LOG_ERR("Chip type is not one of valid: SPC1, SPC2, SPC3, SPC4\n");
        return SAI_STATUS_FAILURE;
    }

    snprintf(mlxtrace_ext_command_line,
             sizeof(mlxtrace_ext_command_line),
             mlxtrace_ext_command_line_fmt,
             device_name,
             (config_file_needed) ? "-c" : "",
             (config_file_needed) ? dump_conf->mft_cfg_path : "",
             (config_file_needed) ? config_file_name : "",
             dirname,
             device_name);

    system_err = system(mlxtrace_ext_command_line);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", mlxtrace_ext_command_line);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}
