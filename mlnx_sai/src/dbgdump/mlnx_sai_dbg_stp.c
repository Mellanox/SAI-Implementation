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

static void SAI_dump_stp_getdb(_Out_ sx_mstp_inst_id_t *def_stp_id, _Out_ mlnx_mstp_inst_t *mlnx_mstp_inst_db)
{
    assert(NULL != def_stp_id);
    assert(NULL != mlnx_mstp_inst_db);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    *def_stp_id = g_sai_db_ptr->def_stp_id;

    memcpy(mlnx_mstp_inst_db,
           g_sai_db_ptr->mlnx_mstp_inst_db,
           (SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1) * sizeof(mlnx_mstp_inst_t));

    sai_db_unlock();
}

static void SAI_dump_default_stp_print(_In_ FILE *file, _In_ sx_mstp_inst_id_t *def_stp_id)
{
    assert(NULL != def_stp_id);

    dbg_utils_print_general_header(file, "Default STP");

    dbg_utils_print_field(file, "default stp", def_stp_id, PARAM_UINT16_E);
    dbg_utils_print(file, "\n");
}

static void SAI_dump_stp_print(_In_ FILE *file, _In_ mlnx_mstp_inst_t *mlnx_mstp_inst_db)
{
    uint32_t                  ii          = 0;
    sai_object_id_t           obj_id      = SAI_NULL_OBJECT_ID;
    uint32_t                  vlan_count  = 0;
    dbg_utils_table_columns_t stp_clmns[] = {
        {"sai obj id", 16, PARAM_UINT64_E, &obj_id},
        {"db idx",     11, PARAM_UINT32_E, &ii},
        {"vlan cnt",   11, PARAM_UINT32_E, &vlan_count},
        {NULL,         0,  0,              NULL}
    };

    assert(NULL != mlnx_mstp_inst_db);

    dbg_utils_print_general_header(file, "STP");

    dbg_utils_print_secondary_header(file, "mlnx_mstp_inst_db");

    dbg_utils_print_table_headline(file, stp_clmns);

    for (ii = 0; ii < SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1; ii++) {
        if (mlnx_mstp_inst_db[ii].is_used) {
            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_STP, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            vlan_count = mlnx_mstp_inst_db[ii].vlan_count;
            dbg_utils_print_table_data_line(file, stp_clmns);
        }
    }
}

void SAI_dump_stp(_In_ FILE *file)
{
    sx_mstp_inst_id_t def_stp_id = 0;
    mlnx_mstp_inst_t  mlnx_mstp_inst_db[SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1];

    memset(mlnx_mstp_inst_db, 0,
           (SX_MSTP_INST_ID_MAX - SX_MSTP_INST_ID_MIN + 1) * sizeof(mlnx_mstp_inst_t));

    SAI_dump_stp_getdb(&def_stp_id, mlnx_mstp_inst_db);

    dbg_utils_print_module_header(file, "SAI STP");

    SAI_dump_default_stp_print(file, &def_stp_id);
    SAI_dump_stp_print(file, mlnx_mstp_inst_db);
}
