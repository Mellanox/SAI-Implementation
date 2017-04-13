/*
 *  Copyright (C) 2017. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

static void SAI_dump_vlan_getdb(_Out_ mlnx_vlan_db_t *mlnx_vlan_db)
{
    assert(NULL != mlnx_vlan_db);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_vlan_db,
           g_sai_db_ptr->vlans_db,
           SXD_VID_MAX * sizeof(mlnx_vlan_db_t));

    sai_db_unlock();
}

static void SAI_dump_vlan_print(_In_ FILE *file, _In_ mlnx_vlan_db_t *mlnx_vlan_db)
{
    uint32_t                  ii           = 0;
    sx_mstp_inst_id_t         stp_id       = 0;
    dbg_utils_table_columns_t vlan_clmns[] = {
        {"db idx", 7,  PARAM_UINT32_E, &ii},
        {"stp id", 16, PARAM_UINT16_E, &stp_id},
        {NULL,     0,  0,              NULL}
    };

    assert(NULL != mlnx_vlan_db);

    dbg_utils_print_general_header(file, "Vlan");

    dbg_utils_print_secondary_header(file, "vlan_db");

    dbg_utils_print_table_headline(file, vlan_clmns);

    for (ii = 0; ii < SXD_VID_MAX; ii++) {
        stp_id = mlnx_vlan_db[ii].stp_id;
        dbg_utils_print_table_data_line(file, vlan_clmns);
    }
}

void SAI_dump_vlan(_In_ FILE *file)
{
    mlnx_vlan_db_t *mlnx_vlan_db;

    mlnx_vlan_db = (mlnx_vlan_db_t*)calloc(SXD_VID_MAX, sizeof(mlnx_vlan_db_t));
    if (!mlnx_vlan_db) {
        return;
    }

    SAI_dump_vlan_getdb(mlnx_vlan_db);
    dbg_utils_print_module_header(file, "SAI Vlan");
    SAI_dump_vlan_print(file, mlnx_vlan_db);

    free(mlnx_vlan_db);
}
