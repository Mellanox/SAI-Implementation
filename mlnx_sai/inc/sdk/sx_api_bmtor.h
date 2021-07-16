/*
 *  Copyright (C) 2014-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef __SX_API_BMTOR_H__
#define __SX_API_BMTOR_H__

#include "sx_bmtor.h"

/************************************************
 *  API functions
 ***********************************************/

/**
 * This function sets the log verbosity level of bmtor MODULE
 *
 * @param[in] handle                   - SX-API handle
 * @param[in] verbosity_target         - set verbosity of : API / MODULE / BOTH
 * @param[in] module_verbosity_level   - BMTOR module verbosity level
 * @param[in] api_verbosity_level      - BMTOR API verbosity level
 *
 * @return SX_STATUS_SUCCESS if operation completes successfully
 * @return SX_STATUS_PARAM_NULL, SX_STATUS_PARAM_ERROR or SX_STATUS_PARAM_EXCEEDS_RANGE if any input parameter is invalid
 *         SX_STATUS_ERROR general error
 */
sx_status_t sx_api_bmtor_log_verbosity_level_set(const sx_api_handle_t           handle,
                                                 const sx_log_verbosity_target_t verbosity_target,
                                                 const sx_verbosity_level_t      module_verbosity_level,
                                                 const sx_verbosity_level_t      api_verbosity_level);

/**
 * This function sets the table_meta_tunnel entry
 *
 * @param[in] handle        - SX-API handle
 * @param[in] cmd           - CREATE / DESTOY
 * @param[in] key_data_p    - key and mask values of the table_meta_tunnel entry
 * @param[in] action_data_p - table_meta_tunnel action type and parameters
 * @param[out] priority     - table_meta_tunnel entry priority
 *
 * @return SX_STATUS_SUCCESS if operation completes successfully
 * @return SX_STATUS_PARAM_NULL, SX_STATUS_PARAM_ERROR or SX_STATUS_PARAM_EXCEEDS_RANGE if any input parameter is invalid
 * @return SX_STATUS_NO_RESOURCES if no entry is available to create
 * @return SX_STATUS_ERROR general error
 */
sx_status_t sx_api_table_meta_tunnel_entry_set(const sx_api_handle_t                           handle,
                                               const sx_access_cmd_t                           cmd,
                                               const sx_table_meta_tunnel_entry_key_data_t    *key_data_p,
                                               const sx_table_meta_tunnel_entry_action_data_t *action_data_p);



#endif /** __SX_API_BMTOR_H__ */