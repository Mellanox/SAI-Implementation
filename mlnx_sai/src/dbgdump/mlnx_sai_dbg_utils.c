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
