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

static void SAI_dump_samplepacket_getdb(_Out_ mlnx_samplepacket_t *mlnx_samplepacket_session)
{
    assert(NULL != mlnx_samplepacket_session);
    assert(NULL != g_sai_db_ptr);

    sai_db_read_lock();

    memcpy(mlnx_samplepacket_session,
           g_sai_db_ptr->mlnx_samplepacket_session,
           MLNX_SAMPLEPACKET_SESSION_MAX * sizeof(mlnx_samplepacket_t));

    sai_db_unlock();
}

static void SAI_dump_samplepacket_type_enum_to_str(_In_ sai_samplepacket_type_t type, _Out_ char *str)
{
    assert(NULL != str);

    switch (type) {
    case SAI_SAMPLEPACKET_TYPE_SLOW_PATH:
        strcpy(str, "slow path");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_samplepacket_mode_enum_to_str(_In_ sai_samplepacket_mode_t mode, _Out_ char *str)
{
    assert(NULL != str);

    switch (mode) {
    case SAI_SAMPLEPACKET_MODE_EXCLUSIVE:
        strcpy(str, "exclusive");
        break;

    case SAI_SAMPLEPACKET_MODE_SHARED:
        strcpy(str, "shared");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_samplepacket_print(_In_ FILE *file, _In_ mlnx_samplepacket_t *mlnx_samplepacket_session)
{
    uint32_t                  ii              = 0;
    sai_object_id_t           obj_id          = SAI_NULL_OBJECT_ID;
    uint32_t                  sai_sample_rate = 0;
    char                      sai_type_str[LINE_LENGTH];
    char                      sai_mode_str[LINE_LENGTH];
    dbg_utils_table_columns_t samplepacket_clmns[] = {
        {"sai obj id",  16, PARAM_UINT64_E, &obj_id},
        {"db idx",      11, PARAM_UINT32_E, &ii},
        {"sample rate", 11, PARAM_UINT32_E, &sai_sample_rate},
        {"type",        10, PARAM_STRING_E, &sai_type_str},
        {"mode",        10, PARAM_STRING_E, &sai_mode_str},
        {NULL,          0,  0,              NULL}
    };

    assert(NULL != mlnx_samplepacket_session);

    dbg_utils_print_general_header(file, "Sample packet");

    dbg_utils_print_secondary_header(file, "mlnx_samplepaccket_session");

    dbg_utils_print_table_headline(file, samplepacket_clmns);

    for (ii = 0; ii < MLNX_SAMPLEPACKET_SESSION_MAX; ii++) {
        if (mlnx_samplepacket_session[ii].in_use) {
            if (SAI_STATUS_SUCCESS !=
                mlnx_create_object(SAI_OBJECT_TYPE_SAMPLEPACKET, ii, NULL, &obj_id)) {
                obj_id = SAI_NULL_OBJECT_ID;
            }
            sai_sample_rate = mlnx_samplepacket_session[ii].sai_sample_rate;
            SAI_dump_samplepacket_type_enum_to_str(mlnx_samplepacket_session[ii].sai_type,
                                                   sai_type_str);
            SAI_dump_samplepacket_mode_enum_to_str(mlnx_samplepacket_session[ii].sai_mode,
                                                   sai_mode_str);
            dbg_utils_print_table_data_line(file, samplepacket_clmns);
        }
    }
}

void SAI_dump_samplepacket(_In_ FILE *file)
{
    mlnx_samplepacket_t mlnx_samplepacket_session[MLNX_SAMPLEPACKET_SESSION_MAX];

    memset(mlnx_samplepacket_session, 0, MLNX_SAMPLEPACKET_SESSION_MAX * sizeof(mlnx_samplepacket_t));

    SAI_dump_samplepacket_getdb(mlnx_samplepacket_session);

    dbg_utils_print_module_header(file, "SAI Sample packet");

    SAI_dump_samplepacket_print(file, mlnx_samplepacket_session);
}
