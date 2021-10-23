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

#ifndef _SX_BMTOR_H_
#define _SX_BMTOR_H_

/**
 * table_meta_tunnel key data
 */
typedef struct _sx_table_meta_tunnel_entry_key_data_t {
    /** in_rif_metadata value */
    u_int32_t in_rif_metadata_field;
    /** cache value used to provide direct access to the ACL rule */
    uint32_t  priority;
} sx_table_meta_tunnel_entry_key_data_t;

/**
 * table_meta_tunnel key data
 */
typedef enum _sx_table_meta_tunnel_action_t {
    /** Action tunnel_encap */
    SX_TABLE_META_TUNNEL_TUNNEL_ENCAP_ACTION,

    /** Action NoAction */
    SX_TABLE_META_TUNNEL_NOACTION_ACTION,
} sx_table_meta_tunnel_action_t;

/**
 * table_meta_tunnel key data
 */
typedef struct _sx_table_meta_tunnel_entry_action_data_t {
    /** table_meta_tunnel action type */
    sx_table_meta_tunnel_action_t action;

    /** table_meta_tunnel action data */
    union {
        /** tunnel_encap action parameters */
        struct {
            /** dst_mac value */
            sx_mac_addr_t dst_mac;

            /** tunnel_id value */
            sx_tunnel_id_t tunnel_id;

            /** underlay_dip value */
            in_addr_t underlay_dip;

        } tunnel_encap_params;
    } data;
} sx_table_meta_tunnel_entry_action_data_t;


#endif /** _SX_BMTOR_H_ */
