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
#endif

#undef  __MODULE__
#define __MODULE__ SAI_INTERFACE_QUERY_IB

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t sai_dbg_do_dump(_In_ const char *dump_file_name);
static sai_status_t sai_dbg_run_mlxtrace(_In_ const char *dirname);

extern sai_status_t mlnx_object_ib_log_set(sx_verbosity_level_t level);
extern sai_status_t mlnx_utils_ib_log_set(sx_verbosity_level_t level);

sai_status_t mlnx_interfacequery_ib_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_api_query_ib(_In_ sai_api_t sai_api_id, _Out_ void** api_method_table)
{
    switch (sai_api_id) {
    case SAI_API_SWITCH:
        *(const sai_switch_api_t**)api_method_table = &mlnx_switch_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_PORT:
        *(const sai_port_api_t**)api_method_table = &mlnx_port_api;
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

sai_status_t sai_log_set_ib(_In_ sai_api_t sai_api_id, sx_log_severity_t severity)
{
    /* TODO : map the utils module */

    switch (sai_api_id) {
    case SAI_API_SWITCH:
        mlnx_switch_log_set(severity);
        mlnx_switch_common_log_set(severity);
        mlnx_interfacequery_log_set(severity);
        mlnx_interfacequery_ib_log_set(severity);
        mlnx_utils_log_set(severity);
        mlnx_utils_ib_log_set(severity);
        mlnx_prm_api_log_set(severity);
        mlnx_swid_api_log_set(severity);
        mlnx_object_ib_log_set(severity);
        return mlnx_object_log_set(severity);

    case SAI_API_PORT:
        mlnx_prm_api_log_set(severity);
        mlnx_swid_api_log_set(severity);
        return mlnx_port_log_set(severity);

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
    sai_status_t        sem_status;
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
    if (flags > 0) {
        dbg_info.ir_dump_enable = true;
        dbg_info.amber_dump_enable = true;
    }

#ifndef _WIN32
    file_name = strdup(dump_file_name);
    strncpy(dbg_info.path, dirname(file_name), sizeof(dbg_info.path));
    dbg_info.path[sizeof(dbg_info.path) - 1] = 0;
    free(file_name);
#endif

    sx_status = sx_api_dbg_generate_dump_extra(gh_sdk, &dbg_info);
    if (SX_ERR(sx_status)) {
        MLNX_SAI_LOG_ERR("Error generating extended sdk dump, sx status: %s\n", SX_STATUS_MSG(sx_status));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    sem_status = wait_for_sem(&g_sai_db_ptr->dfw_sem, 30);
    if (SX_ERR(sem_status)) {
        MLNX_SAI_LOG_ERR("Failed to wait on DFW semaphore.\n");
        status = sem_status;
    }

out:
    return status;
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

    SAI_dump_port(file);

    fclose(file);

#ifndef _WIN32
    file_name = strdup(dump_file_name);
    strncpy(dump_directory, dirname(file_name), sizeof(dump_directory));
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
    SX_LOG_INF("mlxtrace is currently disabled\n");
    /* TODO: Enable mlxtrace with NVOS support */
    return SAI_STATUS_SUCCESS;

    /* const char mlxtrace_ext_command_line_fmt[] = */
    /*     "mlxtrace_ext -d /dev/mst/%s %s -m MEM -a OB_GW -n -o %s/%s_mlxtrace.trc >/dev/null 2>&1"; */
    /* const char *device_name = NULL; */
    /* const char *config_cmd_line_switch = NULL; */
    /* char        mlxtrace_ext_command_line[2 * PATH_MAX + 200]; */
    /* int         system_err; */

    /* if (mlnx_chip_is_qtm()) { */
    /*     device_name = "mt54000_pci_cr0"; */
    /*     config_cmd_line_switch = "-c /etc/mft/fwtrace_cfg/mlxtrace_quantum_itrace.cfg.ext"; */
    /* } else if (mlnx_chip_is_sib2()) { */
    /*     device_name = "mt53000_pci_cr0"; */
    /*     config_cmd_line_switch = "-c /etc/mft/fwtrace_cfg/mlxtrace_sib2_itrace.cfg.ext"; */
    /* } else if (mlnx_chip_is_qtm2()) { */
    /*     device_name = "mt54002_pci_cr0"; */
    /*     config_cmd_line_switch = "-c /etc/mft/fwtrace_cfg/mlxtrace_quantum2_itrace.cfg.ext"; */
    /* } else { */
    /*     SX_LOG_ERR("Chip type is not one of valid: QTM, SIB2, QTM2\n"); */
    /*     return SAI_STATUS_FAILURE; */
    /* } */

    /* snprintf(mlxtrace_ext_command_line, */
    /*          sizeof(mlxtrace_ext_command_line), */
    /*          mlxtrace_ext_command_line_fmt, */
    /*          device_name, */
    /*          config_cmd_line_switch, */
    /*          dirname, */
    /*          device_name); */

    /* system_err = system(mlxtrace_ext_command_line); */
    /* if (0 != system_err) { */
    /*     SX_LOG_ERR("Failed running \"%s\".\n", mlxtrace_ext_command_line); */
    /*     return SAI_STATUS_FAILURE; */
    /* } */

    /* return SAI_STATUS_SUCCESS; */
}
