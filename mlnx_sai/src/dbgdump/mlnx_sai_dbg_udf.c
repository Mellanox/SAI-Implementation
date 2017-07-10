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

static void SAI_dump_udf_group_type_to_str(_In_ sai_udf_group_type_t type, _Out_ char                *str)
{
    assert(str);

    switch (type) {
    case SAI_UDF_GROUP_TYPE_GENERIC:
        strcpy(str, "generic");
        break;

    case SAI_UDF_GROUP_TYPE_HASH:
        strcpy(str, "hash");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_udf_base_to_str(_In_ sai_udf_base_t base, _Out_ char          *str)
{
    assert(str);

    switch (base) {
    case SAI_UDF_BASE_L2:
        strcpy(str, "L2");
        break;

    case SAI_UDF_BASE_L3:
        strcpy(str, "L3");
        break;

    case SAI_UDF_BASE_L4:
        strcpy(str, "L4");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_udf_match_type_to_str(_In_ mlnx_udf_match_type_t type, _Out_ char                 *str)
{
    assert(str);

    switch (type) {
    case MLNX_UDF_MATCH_TYPE_EMPTY:
        strcpy(str, "Empty");
        break;

    case MLNX_UDF_MATCH_TYPE_ARP:
        strcpy(str, "ARP");
        break;

    case MLNX_UDF_MATCH_TYPE_IPv4:
        strcpy(str, "IPv4");
        break;

    case MLNX_UDF_MATCH_TYPE_IPv6:
        strcpy(str, "IPv6");
        break;

    default:
        strcpy(str, "unknown");
        break;
    }
}

static void SAI_dump_udf_sx_keys_to_str(_In_ const sx_acl_key_t *keys,
                                        _In_ uint32_t            key_count,
                                        _In_ uint32_t            str_length,
                                        _Out_ char              *str)
{
    uint32_t pos = 0, ii;

    assert(keys);
    assert(str);

    memset(str, 0, str_length);

    for (ii = 0; ii < key_count; ii++) {
        if (ii != key_count - 1) {
            pos = snprintf(str + pos, str_length, "%d, ", keys[ii]);
        } else {
            pos = snprintf(str + pos, str_length, "%d", keys[ii]);
        }

        str_length -= pos;

        if (str_length < pos) {
            break;
        }
    }
}

static void SAI_dump_udf_list_print(_In_ FILE *file, _In_ const uint32_t *udf_indexes, _In_ uint32_t udf_indexes_count)
{
    mlnx_udf_t                curr_udf;
    uint32_t                  udf_db_index, ii;
    char                      base_str[LINE_LENGTH];
    dbg_utils_table_columns_t udf_clmns[] = {
        {"db idx",      11, PARAM_UINT32_E, &udf_db_index},
        {"sai obj id",  16, PARAM_UINT64_E, &curr_udf.sai_object},
        {"base",        16, PARAM_STRING_E, &base_str},
        {"group index", 16, PARAM_UINT32_E, &curr_udf.group_index},
        {"match index", 16, PARAM_UINT32_E, &curr_udf.match_index},
        {NULL,          0,  0,              NULL}
    };

    assert(file);
    assert(udf_indexes);

    dbg_utils_print_table_headline(file, udf_clmns);

    for (ii = 0; ii < udf_indexes_count; ii++) {
        udf_db_index = udf_indexes[ii];

        memcpy(&curr_udf, &udf_db_udf(udf_db_index), sizeof(curr_udf));

        SAI_dump_udf_base_to_str(curr_udf.base, base_str);

        dbg_utils_print_table_data_line(file, udf_clmns);
    }
}

static void SAI_dump_udfs_print(_In_ FILE *file)
{
    uint32_t *udf_indexes = NULL, udf_indexes_count, ii;

    assert(file);

    udf_indexes       = calloc(MLNX_UDF_COUNT_MAX, sizeof(uint32_t));
    udf_indexes_count = 0;

    for (ii = 0; ii < MLNX_UDF_COUNT_MAX; ii++) {
        if (udf_db_udf(ii).is_created) {
            udf_indexes[udf_indexes_count] = ii;
            udf_indexes_count++;
        }
    }

    dbg_utils_print_general_header(file, "UDFs");

    SAI_dump_udf_list_print(file, udf_indexes, udf_indexes_count);

    free(udf_indexes);
}

static void SAI_dump_udf_groups_print(_In_ FILE *file)
{
    mlnx_udf_group_t          curr_udf_group;
    uint32_t                  ii;
    char                      type_str[LINE_LENGTH];
    char                      sx_custom_bytes_str[LINE_LENGTH];
    dbg_utils_table_columns_t udf_group_clmns[] = {
        {"sai obj id",      16, PARAM_UINT64_E, &curr_udf_group.sai_object},
        {"type",            10, PARAM_STRING_E, &type_str},
        {"length",           8,  PARAM_UINT32_E, &curr_udf_group.length},
        {"refs",            11, PARAM_UINT32_E, &curr_udf_group.refs},
        {"sx keys created", 11, PARAM_UINT8_E,  &curr_udf_group.is_sx_custom_bytes_created},
        {"sx keys",         30, PARAM_STRING_E, &sx_custom_bytes_str},
        {NULL,               0,              0,  NULL}
    };

    assert(file);

    dbg_utils_print_general_header(file, "UDF Groups");

    for (ii = 0; ii < MLNX_UDF_GROUP_COUNT_MAX; ii++) {
        if (udf_db_group_ptr(ii)->is_created) {
            memcpy(&curr_udf_group, udf_db_group_ptr(ii), sizeof(curr_udf_group));

            SAI_dump_udf_group_type_to_str(udf_db_group_ptr(ii)->type, type_str);

            SAI_dump_udf_sx_keys_to_str(udf_db_group_ptr(ii)->sx_custom_bytes_keys,
                                        udf_db_group_ptr(ii)->length,
                                        LINE_LENGTH, sx_custom_bytes_str);

            dbg_utils_print_secondary_header(file, "Group[%d]", ii);

            dbg_utils_print_table_headline(file, udf_group_clmns);

            dbg_utils_print_table_data_line(file, udf_group_clmns);

            if (udf_db_group_udfs_ptr(ii)->count > 0) {
                dbg_utils_print_secondary_header(file, "Group [%d] UDFs", ii);

                SAI_dump_udf_list_print(file, udf_db_group_udfs_ptr(ii)->udf_indexes,
                                        udf_db_group_udfs_ptr(ii)->count);
            }
        }
    }
}

static void SAI_dump_udf_matches_print(_In_ FILE *file)
{
    mlnx_match_t              curr_match;
    uint32_t                  ii;
    char                      type_str[LINE_LENGTH];
    dbg_utils_table_columns_t udf_clmns[] = {
        {"db idx",      11, PARAM_UINT32_E, &ii},
        {"sai obj id",  16, PARAM_UINT64_E, &curr_match.sai_object},
        {"type",        16, PARAM_STRING_E, &type_str},
        {"priority",    16, PARAM_UINT32_E, &curr_match.priority},
        {"refs",        16, PARAM_UINT32_E, &curr_match.refs},
        {NULL,          0,  0,              NULL}
    };

    assert(file);

    dbg_utils_print_general_header(file, "UDF Matches");

    dbg_utils_print_table_headline(file, udf_clmns);

    for (ii = 0; ii < MLNX_UDF_MATCH_COUNT_MAX; ii++) {
        if (udf_db_match(ii).is_created) {
            memcpy(&curr_match, &udf_db_match(ii), sizeof(curr_match));

            SAI_dump_udf_match_type_to_str(curr_match.type, type_str);

            dbg_utils_print_table_data_line(file, udf_clmns);
        }
    }
}

void SAI_dump_udf(_In_ FILE *file)
{
    dbg_utils_print_module_header(file, "SAI UDF");

    SAI_dump_udf_groups_print(file);

    SAI_dump_udfs_print(file);

    SAI_dump_udf_matches_print(file);
}
