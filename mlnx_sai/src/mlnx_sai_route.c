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
#define __MODULE__ SAI_ROUTE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/*
 * Routine Description:
 *    Set route attribute value
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *    [in] attribute - route attribute
 *    [in] value - route attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_route(_In_ sai_unicast_route_entry_t* unicast_route_entry,
                            _In_ sai_route_attr_t           attribute,
                            _In_ uint64_t                   value)
{
    UNUSED_PARAM(unicast_route_entry);
    UNUSED_PARAM(attribute);
    UNUSED_PARAM(value);

    SX_LOG_ENTER();

    /* TODO : fill... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Get route attribute value
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *    [in] attribute - route attribute
 *    [out] value - route attribute value
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_route(_In_ sai_unicast_route_entry_t* unicast_route_entry,
                            _In_ sai_route_attr_t           attribute,
                            _Out_ uint64_t                * value)
{
    UNUSED_PARAM(unicast_route_entry);
    UNUSED_PARAM(attribute);

    SX_LOG_ENTER();

    if (NULL == value) {
        SX_LOG_ERR("NULL value param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : fill... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Create Route
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_route(_In_ sai_unicast_route_entry_t* unicast_route_entry)
{
    UNUSED_PARAM(unicast_route_entry);

    SX_LOG_ENTER();

    /* TODO : fill... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

/*
 * Routine Description:
 *    Delete Route
 *
 * Arguments:
 *    [in] unicast_route_entry - route entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_delete_route(_In_ sai_unicast_route_entry_t* unicast_route_entry)
{
    UNUSED_PARAM(unicast_route_entry);

    SX_LOG_ENTER();

    /* TODO : fill... */

    SX_LOG_EXIT();
    return SAI_STATUS_FAILURE;
}

const sai_route_api_t route_api = {
    mlnx_create_route,
    mlnx_delete_route,
    mlnx_set_route,
    mlnx_get_route
};
