/*
 *  Copyright (C) 2018-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <sx/utils/dbg_utils.h>
#include "assert.h"

static void SAI_dump_mirror_getdb(_Out_ mlnx_mirror_vlan_t *erspan_vlan_header)
{
    assert(NULL != erspan_vlan_header);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(erspan_vlan_header,
           g_sai_db_ptr->erspan_vlan_header,
           SPAN_SESSION_MAX * sizeof(mlnx_mirror_vlan_t));

    sai_db_unlock();
}

static void SAI_dump_mirror_policer_getdb(_Out_ mlnx_mirror_policer_t *mirror_policer)
{
    assert(NULL != mirror_policer);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mirror_policer,
           g_sai_db_ptr->mirror_policer,
           SPAN_SESSION_MAX * sizeof(mlnx_mirror_policer_t));

    sai_db_unlock();
}

static void SAI_dump_mirror_print(_In_ FILE *file, _In_ mlnx_mirror_vlan_t *erspan_vlan_header)
{
    uint32_t                  ii = 0;
    sai_object_id_t           obj_id = SAI_NULL_OBJECT_ID;
    mlnx_mirror_vlan_t        curr_erspan_vlan_header;
    dbg_utils_table_columns_t mirror_clmns[] = {
        {"sai obj id",        16, PARAM_UINT64_E, &obj_id},
        {"db idx",            11, PARAM_UINT32_E, &ii},
        {"vlan header valid", 18, PARAM_UINT8_E,  &curr_erspan_vlan_header.vlan_header_valid},
        {"vlan id",           8,  PARAM_UINT16_E, &curr_erspan_vlan_header.vlan_id},
        {"vlan pri",          9,  PARAM_UINT8_E,  &curr_erspan_vlan_header.vlan_pri},
        {"vlan cfi",          9,  PARAM_UINT8_E,  &curr_erspan_vlan_header.vlan_cfi},
        {NULL,                0,  0,              NULL}
    };

    assert(NULL != erspan_vlan_header);

    dbg_utils_print_general_header(file, "ERSPAN");

    dbg_utils_print_secondary_header(file, "erspan_vlan_header");

    dbg_utils_print_table_headline(file, mirror_clmns);

    for (ii = 0; ii < SPAN_SESSION_MAX; ii++) {
        memcpy(&curr_erspan_vlan_header, &erspan_vlan_header[ii], sizeof(mlnx_mirror_vlan_t));

        if (SAI_STATUS_SUCCESS !=
            mlnx_create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, ii, NULL, &obj_id)) {
            obj_id = SAI_NULL_OBJECT_ID;
        }

        dbg_utils_print_table_data_line(file, mirror_clmns);
    }
}

static void SAI_dump_mirror_policer_print(_In_ FILE *file, _In_ mlnx_mirror_policer_t *mirror_policer)
{
    uint32_t                  ii;
    sx_acl_direction_t        sx_direction;
    mlnx_mirror_policer_t     curr_mirror_policer;
    dbg_utils_table_columns_t mirror_clmns[] = {
        {"sx span id",        11, PARAM_UINT32_E, &ii},
        {"policer oid",       18, PARAM_UINT64_E, &curr_mirror_policer.policer_oid},
        {NULL,                0,  0,              NULL}
    };
    mlnx_mirror_policer_acl_t curr_mirror_policer_acl;
    dbg_utils_table_columns_t acl_clmns[] = {
        {"sx_direction",      13, PARAM_UINT32_E, &sx_direction},
        {"is_acl_created",    15, PARAM_UINT8_E,  &curr_mirror_policer_acl.is_acl_created},
        {"refs",              8, PARAM_UINT32_E, &curr_mirror_policer_acl.refs},
        {"sx_key",            8, PARAM_UINT32_E, &curr_mirror_policer_acl.key},
        {"sx_acl_group",      13, PARAM_UINT32_E, &curr_mirror_policer_acl.acl_group},
        {"sx_acl",            10, PARAM_UINT32_E, &curr_mirror_policer_acl.acl},
        {"sx_region",         12, PARAM_UINT32_E, &curr_mirror_policer_acl.region},
        {NULL,                 0,              0, NULL}
    };

    assert(NULL != mirror_policer);

    dbg_utils_print_general_header(file, "Mirror policer");

    for (ii = 0; ii < SPAN_SESSION_MAX; ii++) {
        memcpy(&curr_mirror_policer, &mirror_policer[ii], sizeof(mlnx_mirror_policer_t));

        dbg_utils_print_table_headline(file, mirror_clmns);
        dbg_utils_print_table_data_line(file, mirror_clmns);

        dbg_utils_print_table_headline(file, acl_clmns);

        for (sx_direction = SX_ACL_DIRECTION_INGRESS; sx_direction < SX_ACL_DIRECTION_LAST; sx_direction++) {
            memcpy(&curr_mirror_policer_acl, &mirror_policer[ii].extra_acl[sx_direction],
                   sizeof(mlnx_mirror_policer_acl_t));

            dbg_utils_print_table_data_line(file, acl_clmns);
        }
    }
}

void SAI_dump_mirror(_In_ FILE *file)
{
    mlnx_mirror_vlan_t    erspan_vlan_header[SPAN_SESSION_MAX];
    mlnx_mirror_policer_t mirror_policer[SPAN_SESSION_MAX];

    memset(erspan_vlan_header, 0, SPAN_SESSION_MAX * sizeof(mlnx_mirror_vlan_t));

    SAI_dump_mirror_getdb(erspan_vlan_header);
    SAI_dump_mirror_policer_getdb(mirror_policer);

    dbg_utils_print_module_header(file, "SAI Mirror");

    SAI_dump_mirror_print(file, erspan_vlan_header);
    SAI_dump_mirror_policer_print(file, mirror_policer);
}
