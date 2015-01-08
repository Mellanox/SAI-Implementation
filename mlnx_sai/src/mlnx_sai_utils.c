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

#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"

#undef  __MODULE__
#define __MODULE__ SAI_UTILS

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

sai_status_t sdk_to_sai(sx_status_t status)
{
    switch (status) {
    case SX_STATUS_SUCCESS:
        return SAI_STATUS_SUCCESS;

    case SX_STATUS_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_MODULE_UNINITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_SDK_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_INVALID_HANDLE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_COMM_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_NO_RESOURCES:
        return SAI_STATUS_INSUFFICIENT_RESOURCES;

    case SX_STATUS_NO_MEMORY:
        return SAI_STATUS_NO_MEMORY;

    case SX_STATUS_MEMORY_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_INCOMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_CMD_UNPERMITTED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARAM_NULL:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_ERROR:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_EXCEEDS_RANGE:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_MESSAGE_SIZE_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MESSAGE_SIZE_EXCEEDS_LIMIT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_DB_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_DB_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_DB_NOT_EMPTY:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_END_OF_DB:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_NOT_FOUND:
        return SAI_STATUS_ITEM_NOT_FOUND;

    case SX_STATUS_ENTRY_ALREADY_EXISTS:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_ENTRY_NOT_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_ALREADY_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_WRONG_POLICER_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNEXPECTED_EVENT_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TRAP_ID_NOT_CONFIGURED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_INT_COMM_CLOSE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_RESOURCE_IN_USE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_EVENT_TRAP_ALREADY_ASSOCIATED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TIMEOUT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_SX_UTILS_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARTIALLY_COMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SXD_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    default:
        SX_LOG_NTC("Unexpected status code %d, mapping to failure\n", status);
        return SAI_STATUS_FAILURE;
    }
}
