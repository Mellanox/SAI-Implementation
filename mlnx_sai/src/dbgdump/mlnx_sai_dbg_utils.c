/*
 *  Copyright (C) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "mlnx_sai_dbg.h"
#include "assert.h"

void SAI_dump_enums_to_str(_In_ mlnx_dbg_dump_enum_mapper_t *mapper,
                           _In_ int32_t                     *values,
                           _In_ size_t                       num,
                           _Out_ char                       *str,
                           _In_ uint32_t                     len)
{
    int32_t written = 0;

    if (num == 0) {
        sprintf(str, "<empty>");
        return;
    }
    for (size_t ii = 0; ii < num; ++ii) {
        if (mapper) {
            if (((size_t)values[ii] > mapper->size) || (values[ii] < 0)) {
                written += snprintf(str + written, len - written, "unknown [%d]", values[ii]);
            } else {
                if (mapper->map[values[ii]]) {
                    written += snprintf(str + written, len - written, "%s", mapper->map[values[ii]]);
                } else {
                    written += snprintf(str + written, len - written, "missed [%d]", values[ii]);
                }
            }
        } else {
            written += snprintf(str + written, len - written, "%d", values[ii]);
        }
        if (ii != num - 1) {
            written += snprintf(str + written, len - written, ", ");
        }
    }
}

void SAI_dump_u32list_to_str(_In_ uint32_t *values, _In_ size_t num, _Out_ char *str, _In_ uint32_t len)
{
    int32_t written = 0;

    if (num == 0) {
        written += snprintf(str + written, len - written, "<empty>");
        return;
    }
    for (size_t ii = 0; ii < num; ++ii) {
        written += snprintf(str + written, len - written, "%u", values[ii]);
        if (ii != num - 1) {
            written += snprintf(str + written, len - written, ", ");
        }
    }
}

static const char* SAI_dump_metadata_get_enum_value_shortname(_In_ const sai_enum_metadata_t* metadata, _In_ int value)
{
    if (metadata == NULL) {
        return NULL;
    }

    size_t i = 0;

    for (; i < metadata->valuescount; ++i) {
        if (metadata->values[i] == value) {
            return metadata->valuesshortnames[i];
        }
    }

    return NULL;
}

void SAI_dump_sai_enum_to_str(_In_ const sai_enum_metadata_t *metadata,
                              _In_ int32_t                   *values,
                              _In_ uint64_t                   values_num,
                              _Out_ char                     *str,
                              _In_ uint32_t                   len)
{
    uint32_t written = 0;

    assert(str);

    if (!values || !values_num) {
        written += snprintf(str + written, len - written, "<empty>");
        return;
    }

    for (uint64_t ii = 0; ii < values_num; ii++) {
        if ((uint64_t)values[ii] >= metadata->valuescount) {
            written += snprintf(str + written, len - written, "unknown [%d]",
                                values[ii]);
        } else {
            const char *short_name = SAI_dump_metadata_get_enum_value_shortname(metadata, values[ii]);
            if (short_name) {
                written += snprintf(str + written, len - written, "%s", short_name);
            } else {
                written += snprintf(str + written, len - written, "missed [%d]", values[ii]);
            }
        }
        if (ii != (values_num - 1)) {
            written += snprintf(str + written, len - written, ", ");
        }
    }
}

uint32_t mlnx_get_shm_rm_id(mlnx_shm_rm_array_idx_t idx)
{
    if (!MLNX_SHM_RM_ARRAY_IDX_IS_UNINITIALIZED(idx)) {
        return idx.idx;
    }

    return -1;
}

void oid_to_hex_str(char *str, sai_object_id_t oid)
{
    snprintf(str, OID_STR_MAX_SIZE, "0x%lX", oid);
}
