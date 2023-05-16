/*
 *  Copyright (C) 2019-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "saimetadata.h"
#include "assert.h"

#define MAX_IP_STR_LEN 40

static void SAI_dump_bfd_getdb(_Out_ mlnx_bfd_session_db_entry_t *bfd_session_db,
                               _Out_ uint32_t                    *count)
{
    sai_status_t status;
    uint32_t     db_size, bfd_session_idx, copied = 0;
    void        *ptr;

    assert(bfd_session_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION);

    for (bfd_session_idx = 0; bfd_session_idx < db_size; bfd_session_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION, bfd_session_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        bfd_session_db[copied] = *(mlnx_bfd_session_db_entry_t*)ptr;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}


static void SAI_dump_bfd_print(_In_ FILE                              *file,
                               _In_ const mlnx_bfd_session_db_entry_t *bfd_sessions,
                               _In_ uint32_t                           size)
{
    sai_status_t               status;
    mlnx_bfd_session_db_data_t cur_bfd_data;
    sai_object_id_t            bfd_session_oid;
    char                       src_ip_str[MAX_IP_STR_LEN];
    char                       dst_ip_str[MAX_IP_STR_LEN];
    uint32_t                   multihop_flag;
    mlnx_shm_rm_array_idx_t    bfd_db_index;
    uint32_t                   ii;
    dbg_utils_table_columns_t  bfd_session_clmns[] = {
        {"DB idx",        7,  PARAM_UINT32_E, &ii},
        {"SAI OID",       10, PARAM_HEX64_E,  &bfd_session_oid},
        {"TX id",         6,  PARAM_UINT32_E, &cur_bfd_data.tx_session},
        {"RX id",         6,  PARAM_UINT32_E, &cur_bfd_data.rx_session},
        {"Multiplier",    10, PARAM_UINT8_E,  &cur_bfd_data.multiplier},
        {"Local disc.",   11, PARAM_UINT32_E, &cur_bfd_data.local_discriminator},
        {"Remote disc.",  12, PARAM_UINT32_E, &cur_bfd_data.remote_discriminator},
        {"Min TX",        10, PARAM_UINT32_E, &cur_bfd_data.min_tx},
        {"Min RX",        10, PARAM_UINT32_E, &cur_bfd_data.min_rx},
        {"UDP src port",  12, PARAM_UINT32_E, &cur_bfd_data.udp_src_port},
        {"Multihop",      8,  PARAM_BOOL_E,   &multihop_flag},
        {"IP header ver", 13, PARAM_UINT8_E,  &cur_bfd_data.ip_header_version},
        {"Src IP",        40, PARAM_STRING_E, src_ip_str},
        {"Dst IP",        40, PARAM_STRING_E, dst_ip_str},
        {"TC",            3,  PARAM_UINT8_E,  &cur_bfd_data.traffic_class},
        {"TOS",           4,  PARAM_UINT8_E,  &cur_bfd_data.tos},
        {"TTL",           4,  PARAM_UINT8_E,  &cur_bfd_data.ttl},
        {NULL,            0,               0, NULL}
    };

    assert(file);
    assert(bfd_sessions);

    fprintf(file, "\nBFD module initialized - %s\n", g_sai_db_ptr->is_bfd_module_initialized ? "TRUE" : "FALSE");
    dbg_utils_print_general_header(file, "BFD sessions");
    dbg_utils_print_table_headline(file, bfd_session_clmns);

    for (ii = 0; ii < size; ii++) {
        if (!bfd_sessions[ii].array_hdr.is_used) {
            continue;
        }

        bfd_db_index.type = MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION;
        bfd_db_index.idx = ii;
        status = mlnx_bfd_session_oid_create(bfd_db_index, &bfd_session_oid);
        if (SAI_ERR(status)) {
            bfd_session_oid = SAI_NULL_OBJECT_ID;
        }

        memcpy(&cur_bfd_data, &bfd_sessions[ii].data, sizeof(cur_bfd_data));

        multihop_flag = cur_bfd_data.multihop ? 1 : 0;
        status = sai_ipaddr_to_str(cur_bfd_data.src_ip, MAX_IP_STR_LEN - 1, src_ip_str, NULL);
        if (SAI_ERR(status)) {
            strcpy(src_ip_str, "-");
        }
        status = sai_ipaddr_to_str(cur_bfd_data.dst_ip, MAX_IP_STR_LEN - 1, dst_ip_str, NULL);
        if (SAI_ERR(status)) {
            strcpy(dst_ip_str, "-");
        }

        dbg_utils_print_table_data_line(file, bfd_session_clmns);
    }
}

void SAI_dump_bfd(_In_ FILE *file)
{
    mlnx_bfd_session_db_entry_t *bfd_sessions = NULL;
    uint32_t                     size = 0;

    bfd_sessions = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_BFD_SESSION),
                          sizeof(mlnx_bfd_session_db_entry_t));
    if (!bfd_sessions) {
        goto out;
    }

    SAI_dump_bfd_getdb(bfd_sessions, &size);

    dbg_utils_print_module_header(file, "SAI BFD DB");

    SAI_dump_bfd_print(file, bfd_sessions, size);

out:
    free(bfd_sessions);
}
