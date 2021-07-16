/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef _MLNX_SAI_DBG_H_
#define _MLNX_SAI_DBG_H_

#include <saimetadata.h>
#include <mlnx_sai.h>

typedef struct _mlnx_dbg_dump_enum_mapper_t {
    char **map;
    size_t size;
} mlnx_dbg_dump_enum_mapper_t;

void SAI_dump_u32list_to_str(_In_ uint32_t *values,
                             _In_ size_t    num,
                             _Out_ char    *str,
                             _In_ uint32_t  len);
void SAI_dump_enums_to_str(_In_ mlnx_dbg_dump_enum_mapper_t *mapper,
                           _In_ int32_t                     *values,
                           _In_ size_t                       num,
                           _Out_ char                       *str,
                           _In_ uint32_t                     len);
void SAI_dump_sai_enum_to_str(_In_ const sai_enum_metadata_t *metadata,
                              _In_ int32_t                   *values,
                              _In_ uint64_t                   values_num,
                              _Out_ char                     *str,
                              _In_ uint32_t                   len);

#endif /* _MLNX_SAI_DBG_H_ */
