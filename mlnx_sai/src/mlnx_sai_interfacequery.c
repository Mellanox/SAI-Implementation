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
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"

#include "sai.h"
#include "mlnx_sai.h"

#undef  __MODULE__
#define __MODULE__ SAI_INTERFACE_QUERY

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
sai_service_method_table_t g_mlnx_services;
bool                       g_is_chipsim;
static bool                g_initialized = false;

typedef struct mlnx_log_lavel_preinit {
    bool            is_set;
    sai_log_level_t level;
} mlnx_log_lavel_preinit_t;

static mlnx_log_lavel_preinit_t mlnx_sai_log_levels[SAI_API_EXTENSIONS_RANGE_END] = {
    {0}
};

sai_status_t sai_log_set_ib(_In_ sai_api_t sai_api_id, sx_log_severity_t severity);
sai_status_t sai_api_query_ib(_In_ sai_api_t sai_api_id, _Out_ void** api_method_table);
static bool is_chipsim_machine();

sai_status_t mlnx_interfacequery_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Adapter module initialization call. This is NOT for SDK initialization.
 *
 * Arguments:
 *     [in] flags - reserved for future use, must be zero
 *     [in] services - methods table with services provided by adapter host
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_api_initialize(_In_ uint64_t flags, _In_ const sai_service_method_table_t* services)
{
#ifdef CONFIG_SYSLOG
    if (!g_initialized) {
        openlog("SAI", 0, LOG_USER);
    }
#endif

    if (g_initialized) {
        MLNX_SAI_LOG_ERR("SAI API initialize already called before, can't re-initialize\n");
        return SAI_STATUS_FAILURE;
    }

    if ((NULL == services) || (NULL == services->profile_get_next_value) || (NULL == services->profile_get_value)) {
        MLNX_SAI_LOG_ERR("Invalid services handle passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memcpy(&g_mlnx_services, services, sizeof(g_mlnx_services));

    if (0 != flags) {
        MLNX_SAI_LOG_ERR("Invalid flags passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    g_initialized = true;

    g_is_chipsim = is_chipsim_machine();

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Retrieve a pointer to the C-style method table for desired SAI
 *     functionality as specified by the given sai_api_id.
 *
 * Arguments:
 *     [in] sai_api_id - SAI api ID
 *     [out] api_method_table - Caller allocated method table
 *           The table must remain valid until the sai_api_uninitialize() is called
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_api_query(_In_ sai_api_t sai_api_id, _Out_ void** api_method_table)
{
    if (!g_initialized) {
        fprintf(stderr, "SAI API not initialized before calling API query\n");
        return SAI_STATUS_UNINITIALIZED;
    }
    if (NULL == api_method_table) {
        MLNX_SAI_LOG_ERR("NULL method table passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return sai_api_query_ib(sai_api_id, api_method_table);
}

/*
 * Routine Description:
 *   Uninitialization of the adapter module. SAI functionalities, retrieved via
 *   sai_api_query() cannot be used after this call.
 *
 * Arguments:
 *   None
 *
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t sai_api_uninitialize(void)
{
    memset(&g_mlnx_services, 0, sizeof(g_mlnx_services));
    g_initialized = false;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_log_level_save(_In_ sai_api_t sai_api_id, _In_ sai_log_level_t log_level)
{
    /* no need to save when sdk is initialized */
    if (gh_sdk) {
        return SAI_STATUS_SUCCESS;
    }

    if (sai_api_id >= (sai_api_t)SAI_API_EXTENSIONS_RANGE_END) {
        MLNX_SAI_LOG_ERR("SAI API %d is out of range [%d, %d]\n",
                         sai_api_id,
                         SAI_API_SWITCH,
                         SAI_API_EXTENSIONS_RANGE_END);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (log_level > SAI_LOG_LEVEL_CRITICAL) {
        MLNX_SAI_LOG_ERR("SAI log level %d is out of range [%d, %d]\n", log_level,
                         SAI_LOG_LEVEL_DEBUG, SAI_LOG_LEVEL_CRITICAL);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    MLNX_SAI_LOG_INF("Saving log level %d for API %d\n", log_level, sai_api_id);

    mlnx_sai_log_levels[sai_api_id].is_set = true;
    mlnx_sai_log_levels[sai_api_id].level = log_level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_log_levels_post_init(void)
{
    sai_api_t    api;
    sai_status_t status;

    for (api = SAI_API_SWITCH; api < (sai_api_t)SAI_API_EXTENSIONS_RANGE_END; api++) {
        if (mlnx_sai_log_levels[api].is_set) {
            /* Related to Bug #3374691
             * TODO: Remove when removing all ETH API files*/
            if (!((api == SAI_API_SWITCH) || (api == SAI_API_PORT))) {
                continue;
            }
            MLNX_SAI_LOG_INF("Restoring log level %d for API %d\n",  mlnx_sai_log_levels[api].level, api);
            status = sai_log_set(api, mlnx_sai_log_levels[api].level);
            if (SAI_ERR(status) && (SAI_STATUS_NOT_IMPLEMENTED != status)) {
                SX_LOG_ERR("Failed to set log level for SAI API %d\n", api);
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *     Set log level for sai api module. The default log level is SAI_LOG_WARN.
 *
 * Arguments:
 *     [in] sai_api_id - SAI api ID
 *     [in] log_level - log level
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_log_set(_In_ sai_api_t sai_api_id, _In_ sai_log_level_t log_level)
{
    sai_status_t      status;
    sx_log_severity_t severity;

    switch (log_level) {
    case SAI_LOG_LEVEL_DEBUG:
        severity = SX_VERBOSITY_LEVEL_DEBUG;
        break;

    case SAI_LOG_LEVEL_INFO:
        severity = SX_VERBOSITY_LEVEL_INFO;
        break;

    case SAI_LOG_LEVEL_NOTICE:
        severity = SX_VERBOSITY_LEVEL_NOTICE;
        break;

    case SAI_LOG_LEVEL_WARN:
        severity = SX_VERBOSITY_LEVEL_WARNING;
        break;

    case SAI_LOG_LEVEL_ERROR:
        severity = SX_VERBOSITY_LEVEL_ERROR;
        break;

    case SAI_LOG_LEVEL_CRITICAL:
        severity = SX_VERBOSITY_LEVEL_ERROR;
        break;

    default:
        MLNX_SAI_LOG_ERR("Invalid log level %d\n", log_level);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = sai_log_level_save(sai_api_id, log_level);
    if (SAI_ERR(status)) {
        return status;
    }

    return sai_log_set_ib(sai_api_id, severity);
}

/*
 * Routine Description:
 *     Query sai object type.
 *
 * Arguments:
 *     [in] sai_object_id_t
 *
 * Return Values:
 *    Return SAI_OBJECT_TYPE_NULL when sai_object_id is not valid.
 *    Otherwise, return a valid sai object type SAI_OBJECT_TYPE_XXX
 */
sai_object_type_t sai_object_type_query(_In_ sai_object_id_t sai_object_id)
{
    sai_object_type_t type = ((mlnx_object_id_t*)&sai_object_id)->object_type;

    if (SAI_TYPE_CHECK_RANGE(type)) {
        return type;
    } else {
        MLNX_SAI_LOG_ERR("Unknown type %d", type);
        return SAI_OBJECT_TYPE_NULL;
    }
}

/**
 * @brief Query sai switch id.
 *
 * @param[in] sai_object_id Object id
 *
 * @return Return #SAI_NULL_OBJECT_ID when sai_object_id is not valid.
 * Otherwise, return a valid SAI_OBJECT_TYPE_SWITCH object on which
 * provided object id belongs. If valid switch id object is provided
 * as input parameter it should return itself.
 */
sai_object_id_t sai_switch_id_query(_In_ sai_object_id_t sai_object_id)
{
    sai_object_id_t  switch_id;
    mlnx_object_id_t mlnx_switch_id = { 0 };

    /* return hard coded single switch instance */
    mlnx_switch_id.id.is_created = true;
    mlnx_object_id_to_sai(SAI_OBJECT_TYPE_SWITCH, &mlnx_switch_id, &switch_id);
    return switch_id;
}

/**
 * @brief Query PCI Driver for Chipsim PCI driver.
 *
 * @return True if system call returns 0, false for other value.
 */
static bool is_chipsim_machine()
{
    return system("lspci -vv | grep QEMU > /dev/null") == 0;
}
