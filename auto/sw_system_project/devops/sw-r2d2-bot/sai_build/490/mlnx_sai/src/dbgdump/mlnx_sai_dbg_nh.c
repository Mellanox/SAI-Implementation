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
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "mlnx_sai.h"
#include <sx/utils/dbg_utils.h>
#include "assert.h"
#include "mlnx_sai_dbg.h"

#define MAX_STR_LENGTH 50

static void SAI_dump_nh_getdb(_Out_ mlnx_encap_nexthop_db_entry_t *dbg_nh_db,
                              _Out_ uint32_t                      *count)
{
    sai_status_t                         status;
    const mlnx_encap_nexthop_db_entry_t *dbg_nh;
    uint32_t                             db_size, dbg_nh_idx, copied = 0;
    void                                *ptr;

    assert(dbg_nh_db);
    assert(g_sai_db_ptr);
    assert(count);

    sai_db_read_lock();

    db_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP);

    for (dbg_nh_idx = 0; dbg_nh_idx < db_size; dbg_nh_idx++) {
        status = mlnx_shm_rm_array_type_idx_to_ptr(MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP, dbg_nh_idx, &ptr);
        if (SAI_ERR(status)) {
            continue;
        }

        dbg_nh = ptr;

        if (!(dbg_nh->array_hdr.is_used)) {
            continue;
        }

        dbg_nh_db[copied] = *dbg_nh;
        copied++;
    }

    *count = copied;

    sai_db_unlock();
}

static void SAI_dump_nh_print(_In_ FILE *file, _In_ const mlnx_encap_nexthop_db_entry_t *dbg_nh, _In_ uint32_t size)
{
    sai_status_t                  status;
    mlnx_encap_nexthop_db_entry_t cur_nh;
    sai_object_id_t               nh_oid;
    uint32_t                      nh_db_idx;
    char                          nh_oid_str[OID_STR_MAX_SIZE];
    char                          tunnel_oid_str[OID_STR_MAX_SIZE];
    char                          vrf_oid_str[OID_STR_MAX_SIZE];
    char                          fake_ecmp_str[OID_STR_MAX_SIZE];
    char                          dst_ip_str[46];
    char                          tunnel_mac_str[18];
    mlnx_fake_nh_db_data_t        fake_data;
    uint32_t                      fake_data_idx = 0;
    dbg_utils_table_columns_t     nh_encap_clmns[] = {
        {"ID",              7,  PARAM_UINT32_E,   &nh_db_idx},
        {"OID",             18, PARAM_STRING_E,   nh_oid_str},
        {"dst_ip",          46, PARAM_STRING_E,   dst_ip_str},
        {"Tunnel OID",      18, PARAM_STRING_E,   tunnel_oid_str},
        {"Tunnel MAC",      18, PARAM_STRING_E,   tunnel_mac_str},
        {"Tunnel VNI",      10, PARAM_UINT32_E,   &cur_nh.data.tunnel_vni},
        {"Fake MAC",        18, PARAM_MAC_ADDR_E, &cur_nh.data.sx_fake_mac},
        {"ACL counter",     11, PARAM_UINT64_E,   &cur_nh.data.acl_counter},
        {"ACL index",       9,  PARAM_UINT32_E,   &cur_nh.data.acl_index},
        {"SX flow counter", 18, PARAM_UINT32_E,   &cur_nh.data.flow_counter},
        {NULL,              0,               0,   NULL}
    };
    dbg_utils_table_columns_t     nh_encap_fake_data_clmns[] = {
        {"Fake_data IDX",    13,  PARAM_UINT32_E, &fake_data_idx},
        {"VRF OID",          18,  PARAM_STRING_E, vrf_oid_str},
        {"Fake IP",          16,  PARAM_IPV4_E,   &fake_data.sx_fake_ip_v4_addr},
        {"Fake ECMP",        10,  PARAM_STRING_E, fake_ecmp_str},
        {"NH ref counter",   14,  PARAM_UINT32_E, &fake_data.counter},
        {"NHGM ref counter", 16,  PARAM_UINT32_E, &fake_data.nhgm_counter},
        {NULL,                0,              0,  NULL}
    };

    assert(file);
    assert(dbg_nh);

    dbg_utils_print_general_header(file, "NEXT_HOP (ENCAP)");

    for (nh_db_idx = 0; nh_db_idx < size; nh_db_idx++) {
        memcpy(&cur_nh, &dbg_nh[nh_db_idx], sizeof(cur_nh));

        mlnx_shm_rm_array_idx_t nh_idx;
        nh_idx.type = MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP;
        nh_idx.idx = nh_db_idx;
        status = mlnx_encap_nexthop_oid_create(nh_idx,
                                               &nh_oid);
        if (SAI_ERR(status)) {
            nh_oid = SAI_NULL_OBJECT_ID;
        }

        oid_to_hex_str(nh_oid_str, nh_oid);
        oid_to_hex_str(tunnel_oid_str, cur_nh.data.tunnel_id);

        sai_ipaddr_to_str(cur_nh.data.dst_ip, 46, dst_ip_str, NULL);
        snprintf(tunnel_mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 cur_nh.data.tunnel_mac[0],
                 cur_nh.data.tunnel_mac[1],
                 cur_nh.data.tunnel_mac[2],
                 cur_nh.data.tunnel_mac[3],
                 cur_nh.data.tunnel_mac[4],
                 cur_nh.data.tunnel_mac[5]);

        dbg_utils_print_table_headline(file, nh_encap_clmns);
        dbg_utils_print_table_data_line(file, nh_encap_clmns);

        dbg_utils_print_table_headline(file, nh_encap_fake_data_clmns);
        for (fake_data_idx = 0; fake_data_idx < NUMBER_OF_LOCAL_VNETS; ++fake_data_idx) {
            if ((cur_nh.data.fake_data[fake_data_idx].counter != 0) ||
                (cur_nh.data.fake_data[fake_data_idx].nhgm_counter != 0)) {
                fake_data = cur_nh.data.fake_data[fake_data_idx];
                oid_to_hex_str(vrf_oid_str, fake_data.associated_vrf);
                snprintf(fake_ecmp_str, OID_STR_MAX_SIZE, "0x%X", fake_data.sx_fake_nexthop);
                dbg_utils_print_table_data_line(file, nh_encap_fake_data_clmns);
            }
        }
    }
}

void SAI_dump_nh(_In_ FILE *file)
{
    mlnx_encap_nexthop_db_entry_t *dbg_nh = NULL;
    uint32_t                       size_nh = 0;

    dbg_nh = calloc(mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_NEXTHOP),
                    sizeof(mlnx_nhg_db_entry_t));
    if (!dbg_nh) {
        goto out;
    }

    SAI_dump_nh_getdb(dbg_nh, &size_nh);

    dbg_utils_print_module_header(file, "SAI NH");

    SAI_dump_nh_print(file, dbg_nh, size_nh);

out:
    free(dbg_nh);
}
