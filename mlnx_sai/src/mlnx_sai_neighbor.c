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
#define __MODULE__ SAI_NEIGHBOR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Create neighbor entry
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_neighbor_entry(_In_ sai_neighbor_entry_t* neighbor_entry)
{
    UNREFERENCED_PARAMETER(neighbor_entry);

    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Delete neighbor entry
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_neighbor_entry(_In_ sai_neighbor_entry_t* neighbor_entry)
{
    UNREFERENCED_PARAMETER(neighbor_entry);

    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Delete all neighbor entries
 *
 * Arguments:
 *    None
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_all_neighbor_entries(void)
{
    SX_LOG_ENTER();

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Check if neighbor entry was used
 *
 * Arguments:
 *    [in] neighbor_entry - neighbor entry
 *    [in] reset_used_flag - reset the used flag after reading
 *    [out] is_used - true if neighbor entry was used
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_query_neighbor_entry(_In_ sai_neighbor_entry_t* neighbor_entry,
                                       _In_ bool                  reset_used_flag,
                                       _Out_ bool               * is_used)
{
    UNREFERENCED_PARAMETER(neighbor_entry);
    UNREFERENCED_PARAMETER(reset_used_flag);

    SX_LOG_ENTER();

    if (NULL == is_used) {
        SX_LOG_ERR("NULL is used param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* ....Call to SDK... */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_neighbor_api_t neighbor_api = {
    mlnx_create_neighbor_entry,
    mlnx_delete_neighbor_entry,
    mlnx_delete_all_neighbor_entries,
    mlnx_query_neighbor_entry
};
