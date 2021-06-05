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
