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
#define __MODULE__ SAI_NEXT_HOP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Create next hop group
 *
 * Arguments:
 *    [in,out] next_hop_group_id - next hop group id
 *    [in] next_hop_group_type - next hop group type
 *    [in] next_hop - array of next hops
 *    [in] next_hop_count - number of next hops
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_next_hop_group(_Inout_ sai_next_hop_group_id_t* next_hop_group_id,
                                        _In_ sai_next_hop_group_type_t   next_hop_group_type,
                                        _In_ sai_next_hop_t            * next_hop,
                                        _In_ int                         next_hop_count)
{
    UNREFERENCED_PARAMETER(next_hop_group_id);
    UNREFERENCED_PARAMETER(next_hop_group_type);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Delete next hop group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_next_hop_group(_In_ sai_next_hop_group_id_t next_hop_group_id)
{
    UNREFERENCED_PARAMETER(next_hop_group_id);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Add next hop to a group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *    [in] next_hop - next hop to add
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_add_next_hop_to_group(_In_ sai_next_hop_group_id_t next_hop_group_id, _In_ sai_next_hop_t* next_hop)
{
    UNREFERENCED_PARAMETER(next_hop_group_id);
    UNREFERENCED_PARAMETER(next_hop);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Remove next hop from a group
 *
 * Arguments:
 *    [in] next_hop_group_id - next hop group id
 *    [in] next_hop - next hop to remove
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_remove_next_hop_from_group(_In_ sai_next_hop_group_id_t next_hop_group_id,
                                             _In_ sai_next_hop_t        * next_hop)
{
    UNREFERENCED_PARAMETER(next_hop_group_id);
    UNREFERENCED_PARAMETER(next_hop);

    SX_LOG_ENTER();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_next_hop_api_t next_hop_api = {
    mlnx_create_next_hop_group,
    mlnx_delete_next_hop_group,
    mlnx_add_next_hop_to_group,
    mlnx_remove_next_hop_from_group
};
