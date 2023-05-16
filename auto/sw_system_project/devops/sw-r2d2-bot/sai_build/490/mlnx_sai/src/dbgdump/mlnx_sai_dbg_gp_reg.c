/*
 *  Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "mlnx_sai.h"
#include <sx/utils/dbg_utils.h>
#include "saimetadata.h"
#include "assert.h"


#define MAX_GP_REG_NAME_STR_LEN  (30)
#define MAX_GP_REG_USAGE_STR_LEN (30)

static void SAI_dump_gp_reg_getdb(_Out_ mlnx_gp_reg_db_t *gp_reg_db, _Out_ uint32_t         *count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     db_size = 0;
    uint32_t     gp_reg_idx = 0;
    uint32_t     copied = 0;
    void        *ptr = NULL;

    assert(gp_reg_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_GP_REG);

    for (gp_reg_idx = 0; gp_reg_idx < db_size; gp_reg_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_GP_REG, gp_reg_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        gp_reg_db[copied] = *(mlnx_gp_reg_db_t*)ptr;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}

static void SAI_dbg_dump_gp_reg_usage_to_str(_In_ mlnx_gp_reg_usage_t usage, _Out_ char *str)
{
    assert(NULL != str);

    switch (usage) {
    case GP_REG_USED_NONE:
        strcpy(str, "None");
        break;

    case GP_REG_USED_HASH_1:
        strcpy(str, "Hash 1");
        break;

    case GP_REG_USED_HASH_2:
        strcpy(str, "Hash 2");
        break;

    case GP_REG_USED_UDF:
        strcpy(str, "UDF");
        break;

    case GP_REG_USED_IP_IDENT:
        strcpy(str, "IP ID");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_gp_reg_print(_In_ FILE *file, _In_ const mlnx_gp_reg_db_t *gp_registers, _In_ uint32_t size)
{
    char                      gp_reg_name[MAX_GP_REG_NAME_STR_LEN] = {0};
    char                      usage[MAX_GP_REG_USAGE_STR_LEN] = {0};
    uint32_t                  ii = 0;
    dbg_utils_table_columns_t gp_registers_clmns[] = {
        {"DB idx",        7,  PARAM_UINT32_E, &ii},
        {"GP reg name",   30, PARAM_STRING_E, gp_reg_name},
        {"GP reg usage",  30, PARAM_STRING_E, usage},
        {NULL,            0,               0, NULL}
    };

    assert(file);
    assert(gp_registers);

    dbg_utils_print_general_header(file, "General Purpose Registers (GP registers)");
    dbg_utils_print_table_headline(file, gp_registers_clmns);

    for (ii = 0; ii < size; ii++) {
        snprintf(gp_reg_name, MAX_GP_REG_NAME_STR_LEN, "GP_REGISTER_%d", ii);
        SAI_dbg_dump_gp_reg_usage_to_str(gp_registers[ii].gp_usage, usage);

        dbg_utils_print_table_data_line(file, gp_registers_clmns);
    }
}

void SAI_dump_gp_reg(_In_ FILE *file)
{
    mlnx_gp_reg_db_t *gp_regs = NULL;
    uint32_t          size = 0;

    if (mlnx_chip_is_spc()) {
        goto out;
    }

    gp_regs = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_GP_REG),
                     sizeof(*gp_regs));
    if (!gp_regs) {
        goto out;
    }

    SAI_dump_gp_reg_getdb(gp_regs, &size);

    dbg_utils_print_module_header(file, "SAI GP REGISTER DB");

    SAI_dump_gp_reg_print(file, gp_regs, size);

out:
    free(gp_regs);
}
