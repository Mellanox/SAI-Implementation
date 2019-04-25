/*
 *  Copyright (C) 2018. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

static void SAI_dump_mirror_print(_In_ FILE *file, _In_ mlnx_mirror_vlan_t *erspan_vlan_header)
{
    uint32_t                  ii     = 0;
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

void SAI_dump_mirror(_In_ FILE *file)
{
    mlnx_mirror_vlan_t erspan_vlan_header[SPAN_SESSION_MAX];

    memset(erspan_vlan_header, 0, SPAN_SESSION_MAX * sizeof(mlnx_mirror_vlan_t));

    SAI_dump_mirror_getdb(erspan_vlan_header);

    dbg_utils_print_module_header(file, "SAI Mirror");

    SAI_dump_mirror_print(file, erspan_vlan_header);
}
