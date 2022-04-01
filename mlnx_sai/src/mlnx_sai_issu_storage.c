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

#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"
#include <sx/utils/crc16.h>
#include <complib/cl_fcntl.h>

#undef  __MODULE__
#define __MODULE__ SAI_ISSU_STORAGE

/* Internal defines */
#define MLNX_SAI_CRC_LENGTH                   (sizeof(uint16_t))
#define MLNX_SAI_CRC_POLY                     (0x1abf)
#define MLNX_SAI_ISSU_PATH_LEN_MAX            (SX_ISSU_PATH_LEN_MAX * 2)
#define MLNX_SAI_ISSU_PERSISTENT_DEFAULT_PATH "/var/"

typedef enum mlnx_sai_issu_pdb_file_version {
    MLNX_ISSU_PDB_FILE_VERSION_INVALID,
    MLNX_ISSU_PDB_FILE_VERSION_1, /* version 1*/
    MLNX_ISSU_PDB_FILE_MIN_VERSION = MLNX_ISSU_PDB_FILE_VERSION_1,
    MLNX_ISSU_PDB_FILE_MAX_VERSION = MLNX_ISSU_PDB_FILE_VERSION_1
} mlnx_sai_issu_pdb_file_version_e;

static const char* MLNX_ISSU_GP_REG_FILE_NAME = "mlnx_issu_gp_reg.dat";
static const char* MLNX_ISSU_PBH_TRANSITION_FILE_NAME = "static_pbhash";

/* Global variables */
static char g_issu_gp_reg_path[MLNX_SAI_ISSU_PATH_LEN_MAX] = {0};
static char g_issu_pbh_transition_flag_path[MLNX_SAI_ISSU_PATH_LEN_MAX] = {0};

/* Internal type definitions */
typedef struct _mlnx_sai_issu_gp_reg_arr {
    uint32_t                        version;
    uint32_t                        count;     /* number of elements in array */
    bool                           *is_gp_reg_in_use;
    mlnx_sai_issu_gp_reg_info_elem *gp_reg_arr;
} mlnx_sai_issu_gp_reg_info;

/* Global static variables */
static mlnx_sai_issu_gp_reg_info *g_gp_reg_info;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/* Internal function declarations */
static sai_status_t mlnx_sai_issu_prepare_paths(const char* persistent_path);
static sai_status_t mlnx_sai_issu_storage_open(_In_ const char *filename,
                                               _In_ const char *mode,
                                               _Out_ FILE     **stream);
static sai_status_t mlnx_sai_issu_storage_read(_In_ FILE  *stream,
                                               _Out_ void *info,
                                               _In_ size_t size,
                                               _In_ size_t num);
static sai_status_t mlnx_sai_issu_storage_write(_In_ FILE       *stream,
                                                _In_ const void *info,
                                                _In_ size_t      size,
                                                _In_ size_t      num);
static sai_status_t mlnx_sai_issu_storage_close(_In_ FILE **stream);
static sai_status_t mlnx_sai_issu_storage_checksum_calc(_In_ const mlnx_sai_issu_gp_reg_info *gp_reg_arr,
                                                        _Out_ uint16_t                       *chsum);
static sai_status_t mlnx_sai_issu_storage_checksum_store(_In_ FILE    *stream,
                                                         _In_ uint16_t chsum);
static sai_status_t mlnx_sai_issu_storage_checksum_restore(_In_ FILE     *stream,
                                                           _In_ uint16_t *chsum);
static sai_status_t mlnx_sai_issu_storage_gp_reg_info_store(_In_ FILE                            *stream,
                                                            _In_ const mlnx_sai_issu_gp_reg_info *gp_reg_info);
static sai_status_t mlnx_sai_issu_storage_gp_reg_alloc_db(_In_ FILE  *stream,
                                                          _In_ size_t file_size);
static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_detect_transition(void);
static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_allocate_transiton_db(void);
static sai_status_t mlnx_sai_issu_storage_gp_reg_info_restore(_In_ FILE *stream);
static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_construct_transition_db(void);
static sai_status_t mlnx_sai_issu_collect_ip_ident_info(_Inout_ mlnx_sai_issu_gp_reg_info *gp_reg_info);
static sai_status_t mlnx_sai_issu_storage_construct_pbh_info(_In_ uint32_t                         fields_count,
                                                             _In_ const mlnx_sai_fg_hash_field_t  *fields_list,
                                                             _In_ bool                             optimized,
                                                             _In_ mlnx_gp_reg_usage_t              gp_reg_usage_type,
                                                             _Out_ mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_item);
static sai_status_t mlnx_sai_issu_collect_pbh_info(_Inout_ mlnx_sai_issu_gp_reg_info *gp_reg_info,
                                                   _In_ mlnx_gp_reg_usage_t           gp_reg_usage);
static bool mlnx_sai_issu_storage_compare_pbh_info(_In_ const mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_a,
                                                   _In_ const mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_b);
static sai_status_t mlnx_sai_issu_collect_udf_info(_Inout_ mlnx_sai_issu_gp_reg_info *gp_reg_info);
static sai_status_t mlnx_sai_issu_storage_pre_shutdown_prepare_spc2(void);
static sai_status_t mlnx_sai_issu_restore_info_impl();
static sai_status_t mlnx_sai_issu_restore_info_spc2();
static sai_status_t mlnx_sai_issu_init(sai_switch_profile_id_t profile_id,
                                       mlnx_sai_boot_type_t    boot_type);
static void mlnx_sai_issu_storage_gp_reg_dealloc_db(void);

/* ISSU storage callback table */
typedef sai_status_t (*mlnx_sai_issu_pre_shutdown_fn)(void);
typedef sai_status_t (*mlnx_sai_issu_restore_info_fn)();
typedef sai_status_t (*mlnx_sai_issu_init_fn)(sai_switch_profile_id_t profile_id,
                                              mlnx_sai_boot_type_t    boot_type);

typedef struct _mlnx_issu_storage_cb_table_t {
    mlnx_sai_issu_init_fn         issu_init;
    mlnx_sai_issu_restore_info_fn issu_restore_info;
    mlnx_sai_issu_pre_shutdown_fn pre_shutdown_prepare;
} mlnx_issu_storage_cb_table_t;

static mlnx_issu_storage_cb_table_t mlnx_issu_storage_cb_spc = {
    NULL,
    NULL,
    NULL
};

static mlnx_issu_storage_cb_table_t mlnx_issu_storage_cb_spc2 = {
    mlnx_sai_issu_init,
    mlnx_sai_issu_restore_info_spc2,
    mlnx_sai_issu_storage_pre_shutdown_prepare_spc2,
};

static mlnx_issu_storage_cb_table_t *mlnx_issu_storage_cb = NULL;

/* Functions implementation */
sai_status_t mlnx_issu_storage_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_issu_storage_pre_shutdown_prepare_impl(void)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    assert(mlnx_issu_storage_cb);
    if (mlnx_issu_storage_cb->pre_shutdown_prepare) {
        sai_status = mlnx_issu_storage_cb->pre_shutdown_prepare();
    }
    return sai_status;
}

sai_status_t mlnx_sai_issu_init_impl(sai_switch_profile_id_t profile_id, mlnx_sai_boot_type_t boot_type)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    assert(mlnx_issu_storage_cb);
    if (mlnx_issu_storage_cb->issu_init) {
        sai_status = mlnx_issu_storage_cb->issu_init(profile_id, boot_type);
    }
    return sai_status;
}

sai_status_t mlnx_sai_issu_storage_cb_table_init(void)
{
    sx_chip_types_t chip_type = SX_CHIP_TYPE_UNKNOWN;

    chip_type = g_sai_db_ptr->sx_chip_type;

    switch (chip_type) {
    case SX_CHIP_TYPE_SPECTRUM:
    case SX_CHIP_TYPE_SPECTRUM_A1:
        mlnx_issu_storage_cb = &mlnx_issu_storage_cb_spc;
        break;

    case SX_CHIP_TYPE_SPECTRUM2:
        mlnx_issu_storage_cb = &mlnx_issu_storage_cb_spc2;
        break;

    case SX_CHIP_TYPE_SPECTRUM3:
        mlnx_issu_storage_cb = &mlnx_issu_storage_cb_spc2;
        break;

    case SX_CHIP_TYPE_SPECTRUM4:
        mlnx_issu_storage_cb = &mlnx_issu_storage_cb_spc2;
        break;

    default:
        MLNX_SAI_LOG_ERR("g_sai_db_ptr->sxd_chip_type = %s\n", SX_CHIP_TYPE_STR(chip_type));
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_issu_storage_pre_shutdown_prepare_spc2(void)
{
    sai_status_t              sai_status = SAI_STATUS_SUCCESS;
    uint32_t                  ii = 0;
    bool                      is_ip_ident_store = false;
    bool                      is_udf_store = false;
    bool                      is_pbh_one_store = false;
    bool                      is_pbh_two_store = false;
    uint32_t                  gp_reg_array_size = 0;
    mlnx_shm_rm_array_idx_t   gp_reg_array_idx = {0};
    mlnx_gp_reg_db_t         *gp_reg = NULL;
    mlnx_sai_issu_gp_reg_info gp_reg_info = {0};
    FILE                     *file_p = NULL;
    uint16_t                  chsum = 0;

    gp_reg_info.is_gp_reg_in_use = calloc(MLNX_UDF_GP_REG_COUNT, sizeof(*gp_reg_info.is_gp_reg_in_use));
    if (!gp_reg_info.is_gp_reg_in_use) {
        sai_status = SAI_STATUS_NO_MEMORY;
        SX_LOG_ERR("Failed to allocate memory\n");
        goto out;
    }
    gp_reg_info.gp_reg_arr = calloc(MLNX_UDF_GP_REG_COUNT, sizeof(*gp_reg_info.gp_reg_arr));
    if (!gp_reg_info.is_gp_reg_in_use) {
        sai_status = SAI_STATUS_NO_MEMORY;
        SX_LOG_ERR("Failed to allocate memory\n");
        goto out;
    }

    gp_reg_array_size = mlnx_shm_rm_array_size_get(MLNX_SHM_RM_ARRAY_TYPE_GP_REG);
    gp_reg_array_idx.type = MLNX_SHM_RM_ARRAY_TYPE_GP_REG;

    /* find out which info should be handled */
    for (ii = 0; ii < gp_reg_array_size; ++ii) {
        gp_reg_array_idx.idx = ii;
        sai_status = mlnx_gp_reg_db_idx_to_data(gp_reg_array_idx, &gp_reg);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        if (!gp_reg->mlnx_array.is_used) {
            continue;
        }

        switch (gp_reg->gp_usage) {
        case GP_REG_USED_NONE:
            break;

        case GP_REG_USED_HASH_1:
            is_pbh_one_store = true;
            break;

        case GP_REG_USED_HASH_2:
            is_pbh_two_store = true;
            break;

        case GP_REG_USED_UDF:
            is_udf_store = true;
            break;

        case GP_REG_USED_IP_IDENT:
            is_ip_ident_store = true;
            break;

        default:
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }
    }

    if (is_ip_ident_store) {
        sai_status = mlnx_sai_issu_collect_ip_ident_info(&gp_reg_info);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

    if (is_pbh_one_store) {
        sai_status = mlnx_sai_issu_collect_pbh_info(&gp_reg_info, GP_REG_USED_HASH_1);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

    if (is_pbh_two_store) {
        sai_status = mlnx_sai_issu_collect_pbh_info(&gp_reg_info, GP_REG_USED_HASH_2);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

    if (is_udf_store) {
        sai_status = mlnx_sai_issu_collect_udf_info(&gp_reg_info);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

    if (gp_reg_info.count) {
        gp_reg_info.version = MLNX_ISSU_PDB_FILE_VERSION_1;

        sai_status = mlnx_sai_issu_storage_checksum_calc(&gp_reg_info, &chsum);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        sai_status = mlnx_sai_issu_storage_open(g_issu_gp_reg_path, "wb", &file_p);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to create ISSU persistent file %s\n", g_issu_gp_reg_path);
            goto out;
        }

        sai_status = mlnx_sai_issu_storage_checksum_store(file_p, chsum);
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        sai_status = mlnx_sai_issu_storage_gp_reg_info_store(file_p, &gp_reg_info);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }
out:
    safe_free(gp_reg_info.is_gp_reg_in_use);
    safe_free(gp_reg_info.gp_reg_arr);
    if (file_p) {
        sai_status = mlnx_sai_issu_storage_close(&file_p);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to close ISSU persistent file\n");
        }
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_open(_In_ const char *filename, _In_ const char *mode, _Out_ FILE **stream)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    *stream = cl_fopen(filename, mode);
    if (*stream == NULL) {
        sai_status = SAI_STATUS_FAILURE;
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_checksum_calc(_In_ const mlnx_sai_issu_gp_reg_info *gp_reg_arr,
                                                        _Out_ uint16_t                       *chsum)
{
    sai_status_t  sai_status = SAI_STATUS_SUCCESS;
    crc16_table_t crc16_table = {0};
    size_t        data_len = 0;

    SX_LOG_ENTER();

    assert(gp_reg_arr);
    assert(gp_reg_arr->count);
    assert(gp_reg_arr->gp_reg_arr);
    assert(chsum);

    data_len = (sizeof(gp_reg_arr->gp_reg_arr[0]) * gp_reg_arr->count);

    crc16_table.table_init = FALSE;

    *chsum = crc_16(&crc16_table, (uint8_t*)gp_reg_arr->gp_reg_arr, data_len, MLNX_SAI_CRC_POLY);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_checksum_store(_In_ FILE *stream, _In_ uint16_t chsum)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    assert(stream);
    /* Checksum is being written in the first 16 bits (2 bytes) of the file: */
    if (fseek(stream, 0, SEEK_SET) != 0) {
        SX_LOG_ERR("Failed to set pointer to the beginning of gp register persistent file \n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_write(stream, &chsum, sizeof(chsum), 1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error writing Profile checksum to storage \n");
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_checksum_restore(_In_ FILE *stream, _In_ uint16_t *chsum)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();
    assert(stream);
    assert(chsum);

    /* Checksum is being written in the first 16 bits of the file: */
    if (fseek(stream, 0, SEEK_SET) != 0) {
        SX_LOG_ERR("Failed to set pointer to the beginning of gp register persistent file \n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_read(stream, chsum, sizeof(*chsum), 1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error writing Profile checksum to storage \n");
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_read(_In_ FILE *stream, _Out_ void *info, _In_ size_t size, _In_ size_t num)
{
    if (cl_fread(info, size, num, stream) == num) {
        return SAI_STATUS_SUCCESS;
    } else {
        return SAI_STATUS_FAILURE;
    }
}

static sai_status_t mlnx_sai_issu_storage_write(_In_ FILE       *stream,
                                                _In_ const void *info,
                                                _In_ size_t      size,
                                                _In_ size_t      num)
{
    if (cl_fwrite(info, size, num, stream) == num) {
        return SAI_STATUS_SUCCESS;
    } else {
        return SAI_STATUS_FAILURE;
    }
}

static sai_status_t mlnx_sai_issu_storage_close(_In_ FILE **stream)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    cl_status_t  cl_status = CL_SUCCESS;

    SX_LOG_ENTER();

    if (*stream != NULL) {
        cl_status = cl_fflush(*stream);
        if (cl_status != CL_SUCCESS) {
            SX_LOG_ERR("Failed to flush ISSU persistent file\n");
            sai_status = SAI_STATUS_FAILURE;
        }

        cl_status = cl_fsync(*stream);
        if (cl_status != CL_SUCCESS) {
            SX_LOG_ERR("Failed to sync ISSU persistent file\n");
            sai_status = SAI_STATUS_FAILURE;
        }

        cl_status = cl_fclose(*stream);
        if (cl_status != CL_SUCCESS) {
            SX_LOG_ERR("Failed to close ISSU persistent file handler\n");
            sai_status = SAI_STATUS_FAILURE;
        }
        *stream = NULL;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_gp_reg_info_store(_In_ FILE                            *stream,
                                                            _In_ const mlnx_sai_issu_gp_reg_info *gp_reg_info)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    assert(stream);
    assert(gp_reg_info);
    assert(gp_reg_info->count);

    /* GP reg info data is being written after the first 16 bits (2 bytes) of the file: */
    if (fseek(stream, MLNX_SAI_CRC_LENGTH, SEEK_SET) != 0) {
        SX_LOG_ERR("Failed to set pointer to the data offset in ISSU persistent file \n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_write(stream, &gp_reg_info->version, sizeof(gp_reg_info->version), 1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error writing version to storage \n");
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_write
                     (stream, gp_reg_info->gp_reg_arr, sizeof(gp_reg_info->gp_reg_arr[0]) * gp_reg_info->count, 1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error writing gp register array to storage \n");
        goto out;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

static void mlnx_sai_issu_storage_gp_reg_dealloc_db(void)
{
    if (g_gp_reg_info) {
        safe_free(g_gp_reg_info->is_gp_reg_in_use);
        safe_free(g_gp_reg_info->gp_reg_arr);
    }
    safe_free(g_gp_reg_info);
}

static sai_status_t mlnx_sai_issu_storage_gp_reg_alloc_db(_In_ FILE *stream, _In_ size_t file_size)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     version = 0;

    SX_LOG_ENTER();

    assert(stream);

    /* GP reg info data is being written after the first 16 bits (2 bytes) of the file: */
    if (fseek(stream, MLNX_SAI_CRC_LENGTH, SEEK_SET) != 0) {
        SX_LOG_ERR("Failed to set pointer to the data offset in ISSU persistent file \n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }
    file_size -= MLNX_SAI_CRC_LENGTH;

    g_gp_reg_info = calloc(1, sizeof(*g_gp_reg_info));
    if (!g_gp_reg_info) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_read(stream, &version, sizeof(g_gp_reg_info->version), 1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error reading version from storage \n");
        goto out;
    }
    g_gp_reg_info->version = version;
    file_size -= sizeof(g_gp_reg_info->version);

    if (file_size < sizeof(*(g_gp_reg_info->gp_reg_arr))) {
        sai_status = SAI_STATUS_FAILURE;
        SX_LOG_ERR("Persistent file size is less than entry size\n");
        goto out;
    }

    if (file_size > (sizeof(*(g_gp_reg_info->gp_reg_arr)) * MLNX_UDF_GP_REG_COUNT)) {
        sai_status = SAI_STATUS_FAILURE;
        SX_LOG_ERR("Persistent file size is greater than maximum number of entries\n");
        goto out;
    }

    if (0 != (file_size % sizeof(*(g_gp_reg_info->gp_reg_arr)))) {
        sai_status = SAI_STATUS_FAILURE;
        SX_LOG_ERR("Persistent file size is not aligned to entry size\n");
        goto out;
    }

    g_gp_reg_info->count = (uint32_t)file_size / sizeof(*(g_gp_reg_info->gp_reg_arr));

    g_gp_reg_info->is_gp_reg_in_use = calloc(MLNX_UDF_GP_REG_COUNT, sizeof(*(g_gp_reg_info->is_gp_reg_in_use)));
    if (!g_gp_reg_info->is_gp_reg_in_use) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    g_gp_reg_info->gp_reg_arr = calloc(g_gp_reg_info->count, sizeof(*(g_gp_reg_info->gp_reg_arr)));
    if (!g_gp_reg_info->gp_reg_arr) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

out:
    if (sai_status != SAI_STATUS_SUCCESS) {
        mlnx_sai_issu_storage_gp_reg_dealloc_db();
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_detect_transition(void)
{
    FILE        *f = NULL;
    cl_status_t  cl_status = CL_SUCCESS;
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    assert(!g_sai_db_ptr->is_issu_gp_reg_restore);

    SX_LOG_ENTER();

    f = cl_fopen(g_issu_pbh_transition_flag_path, "rb");
    if (f != NULL) {
        cl_status = cl_fclose(f);
        if (cl_status != CL_SUCCESS) {
            SX_LOG_ERR("Failed to close pbh transition file handler\n");
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }

        cl_status = cl_remove(g_issu_pbh_transition_flag_path);
        if (cl_status != CL_SUCCESS) {
            SX_LOG_ERR("Failed to remove pbh transition file\n");
            sai_status = SAI_STATUS_FAILURE;
            goto out;
        }

        g_sai_db_ptr->pbhash_transition = true;
        SX_LOG_NTC("Transition between static to dynamic PBH flag detected\n");
    }

out:
    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_allocate_transiton_db(void)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    assert(!g_sai_db_ptr->is_issu_gp_reg_restore);

    SX_LOG_ENTER();

    g_gp_reg_info = calloc(1, sizeof(*g_gp_reg_info));
    if (!g_gp_reg_info) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    g_gp_reg_info->version = 1;
    g_gp_reg_info->count = 1;

    g_gp_reg_info->is_gp_reg_in_use = calloc(MLNX_UDF_GP_REG_COUNT, sizeof(*(g_gp_reg_info->is_gp_reg_in_use)));
    if (!g_gp_reg_info->is_gp_reg_in_use) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    g_gp_reg_info->gp_reg_arr = calloc(g_gp_reg_info->count, sizeof(*(g_gp_reg_info->gp_reg_arr)));
    if (!g_gp_reg_info->gp_reg_arr) {
        sai_status = SAI_STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

out:
    if (sai_status != SAI_STATUS_SUCCESS) {
        mlnx_sai_issu_storage_gp_reg_dealloc_db();
    }
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_gp_reg_info_restore(_In_ FILE *stream)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();
    assert(g_gp_reg_info);

    sai_status = mlnx_sai_issu_storage_read
                     (stream,
                     &g_gp_reg_info->gp_reg_arr[0],
                     sizeof(*(g_gp_reg_info->gp_reg_arr)) * g_gp_reg_info->count,
                     1);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error reading gp register array from storage \n");
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_dynamic_pbh_construct_transition_db(void)
{
    sai_status_t                    sai_status = SAI_STATUS_SUCCESS;
    sx_gp_register_e                reg_id = SX_GP_REGISTER_LAST_E;
    sai_ip4_t                       ip4_mask = 0xffffffff;
    sai_ip6_t                       ip6_mask = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
    mlnx_sai_issu_gp_reg_info_elem *gp_reg_arr_entry = NULL;
    const uint32_t                  src_ipv4_idx = 0;
    const uint32_t                  dst_ipv4_idx = 1;
    const uint32_t                  src_ipv6_idx = 2;
    const uint32_t                  dst_ipv6_idx = 3;
    const uint32_t                  src_l4_idx = 4;
    const uint32_t                  dst_l4_idx = 5;
    const uint32_t                  ip_proto_idx = 6;

    SX_LOG_ENTER();

    assert(g_gp_reg_info);
    assert(g_gp_reg_info->is_gp_reg_in_use);
    assert(g_gp_reg_info->gp_reg_arr);
    assert(!g_sai_db_ptr->is_issu_gp_reg_restore);

    gp_reg_arr_entry = &(g_gp_reg_info->gp_reg_arr[0]);

    gp_reg_arr_entry->type = GP_REG_USED_HASH_1;
    /* 6 consequent registers*/
    gp_reg_arr_entry->gp_reg_bitmask = 0x3F;

    /* Fields to match optimized hash case */
    gp_reg_arr_entry->pbh.native_fields_list[src_ipv4_idx] = SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4;
    gp_reg_arr_entry->pbh.native_fields_list[dst_ipv4_idx] = SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4;
    gp_reg_arr_entry->pbh.native_fields_list[src_ipv6_idx] = SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6;
    gp_reg_arr_entry->pbh.native_fields_list[dst_ipv6_idx] = SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6;
    gp_reg_arr_entry->pbh.native_fields_list[src_l4_idx] = SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT;
    gp_reg_arr_entry->pbh.native_fields_list[dst_l4_idx] = SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT;
    gp_reg_arr_entry->pbh.native_fields_list[ip_proto_idx] = SAI_NATIVE_HASH_FIELD_INNER_IP_PROTOCOL;

    /* Masks to match optimized hash case */
    gp_reg_arr_entry->pbh.masks[src_ipv4_idx].ip4 = ip4_mask;
    gp_reg_arr_entry->pbh.masks[dst_ipv4_idx].ip4 = ip4_mask;
    memcpy(&(gp_reg_arr_entry->pbh.masks[src_ipv6_idx].ip6), ip6_mask,
           sizeof(gp_reg_arr_entry->pbh.masks[src_ipv6_idx].ip6));
    memcpy(&(gp_reg_arr_entry->pbh.masks[dst_ipv6_idx].ip6), ip6_mask,
           sizeof(gp_reg_arr_entry->pbh.masks[dst_ipv6_idx].ip6));

    gp_reg_arr_entry->pbh.sequence_ids[src_ipv4_idx] = 2;
    gp_reg_arr_entry->pbh.sequence_ids[dst_ipv4_idx] = 2;
    gp_reg_arr_entry->pbh.sequence_ids[src_ipv6_idx] = 3;
    gp_reg_arr_entry->pbh.sequence_ids[dst_ipv6_idx] = 3;
    gp_reg_arr_entry->pbh.sequence_ids[src_l4_idx] = 4;
    gp_reg_arr_entry->pbh.sequence_ids[dst_l4_idx] = 4;
    gp_reg_arr_entry->pbh.sequence_ids[ip_proto_idx] = 5;

    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_0_E] = src_ipv4_idx;
    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_1_E] = src_ipv4_idx;
    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_2_E] = dst_ipv4_idx;
    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_3_E] = dst_ipv4_idx;
    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_4_E] = src_l4_idx;
    gp_reg_arr_entry->pbh.gp_reg_fg_fields_map[SX_GP_REGISTER_5_E] = dst_l4_idx;

    for (reg_id = SX_GP_REGISTER_0_E; reg_id < SX_GP_REGISTER_6_E; ++reg_id) {
        g_gp_reg_info->gp_reg_arr[0].pbh.reg_ids[reg_id] = reg_id;
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_collect_ip_ident_info(_In_ mlnx_sai_issu_gp_reg_info *gp_reg_info)
{
    sai_status_t     sai_status = SAI_STATUS_SUCCESS;
    uint32_t         gp_reg_mask = 0;
    sx_gp_register_e gp_reg_idx = SX_GP_REGISTER_LAST_E;

    SX_LOG_ENTER();

    assert(gp_reg_info);
    assert(g_sai_acl_db_ptr->acl_settings_tbl->ip_ident_keys.refs);

    gp_reg_idx = MLNX_FLEX_ACL_KEY_TO_SX_GP_REG(g_sai_acl_db_ptr->acl_settings_tbl->ip_ident_keys.sx_keys[0]);
    assert(gp_reg_idx < SX_GP_REGISTER_LAST_E);
    gp_reg_mask |= (1 << gp_reg_idx);

    gp_reg_info->gp_reg_arr[gp_reg_info->count].gp_reg_bitmask = gp_reg_mask;

    gp_reg_info->gp_reg_arr[gp_reg_info->count].type = GP_REG_USED_IP_IDENT;

    gp_reg_info->count++;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_storage_construct_pbh_info(_In_ uint32_t                         fields_count,
                                                             _In_ const mlnx_sai_fg_hash_field_t  *fields_list,
                                                             _In_ bool                             optimized,
                                                             _In_ mlnx_gp_reg_usage_t              gp_reg_usage_type,
                                                             _Out_ mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_item)
{
    sai_status_t                    sai_status = SAI_STATUS_SUCCESS;
    const mlnx_sai_fg_hash_field_t *field_ptr[2] = {NULL};
    sx_gp_register_e                gp_reg_id = SX_GP_REGISTER_LAST_E;
    uint32_t                        ind = 0;
    uint32_t                        ii = 0;
    uint32_t                        jj = 0;
    uint32_t                        gp_reg_pos = 0;
    uint32_t                        shift = 0;
    uint32_t                        gp_reg_bitmask = 0;
    uint16_t                        mask = 0;

    SX_LOG_ENTER();
    assert(fields_list);
    assert(gp_reg_info_item);

    for (ind = 0, gp_reg_pos = 0; ind < fields_count; ++ind) {
        /* not symmetric - no gp registers allocated */
        if (fields_list[ind].sequence_id != fields_list[ind + 1].sequence_id) {
            gp_reg_info_item->pbh.native_fields_list[ind] = fields_list[ind].field;
            memcpy(&(gp_reg_info_item->pbh.masks[ind]), &(fields_list[ind].ip_mask), sizeof(fields_list[ind].ip_mask));
            gp_reg_info_item->pbh.sequence_ids[ind] = fields_list[ind].sequence_id;
            continue;
        }

        /* when fieldA.sequence_id == fieldB.sequence_id then (fieldA, fieldB) set == (fieldB, fieldA) set */
        /* sort by enum value to always have (fieldA, fieldB) set */
        if (fields_list[ind].field < fields_list[ind + 1].field) {
            field_ptr[0] = &(fields_list[ind]);
            field_ptr[1] = &(fields_list[ind + 1]);
        } else {
            field_ptr[0] = &(fields_list[ind + 1]);
            field_ptr[1] = &(fields_list[ind]);
        }

        for (ii = 0; ii < 2; ++ii) {
            uint32_t field_list_idx = ind + ii;
            gp_reg_info_item->pbh.native_fields_list[field_list_idx] = field_ptr[ii]->field;
            memcpy(&(gp_reg_info_item->pbh.masks[field_list_idx]), &(field_ptr[ii]->ip_mask),
                   sizeof(field_ptr[ii]->ip_mask));
            gp_reg_info_item->pbh.sequence_ids[field_list_idx] = field_ptr[ii]->sequence_id;

            switch (field_ptr[ii]->field) {
            case SAI_NATIVE_HASH_FIELD_DST_IPV4:
            case SAI_NATIVE_HASH_FIELD_SRC_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
                for (jj = 0, shift = 16; jj < 2; ++jj, shift -= 16) {
                    mask = (uint16_t)(field_ptr[ii]->ip_mask.ip4 >> shift);
                    if (0 != mask) {
                        gp_reg_id = field_ptr[ii]->reg_id[jj].key.gp_reg.reg_id;
                        gp_reg_info_item->pbh.gp_reg_fg_fields_map[gp_reg_id] = field_list_idx;
                        gp_reg_info_item->pbh.reg_ids[gp_reg_pos] = gp_reg_id;
                        gp_reg_bitmask |= (1 << gp_reg_id);
                        ++gp_reg_pos;
                    }
                }
                break;

            case SAI_NATIVE_HASH_FIELD_DST_IPV6:
            case SAI_NATIVE_HASH_FIELD_SRC_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
            case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
                if (!optimized) {
                    for (jj = 0; jj < 16; jj += 2) {
                        if ((0 != (field_ptr[ii]->ip_mask.ip6[jj] & 0xFF)) ||
                            (0 != (field_ptr[ii]->ip_mask.ip6[jj + 1] & 0xFF))) {
                            gp_reg_id = field_ptr[ii]->reg_id[jj / 2].key.gp_reg.reg_id;
                            gp_reg_info_item->pbh.gp_reg_fg_fields_map[gp_reg_id] = field_list_idx;
                            gp_reg_info_item->pbh.reg_ids[gp_reg_pos] = gp_reg_id;
                            gp_reg_bitmask |= (1 << gp_reg_id);
                            ++gp_reg_pos;
                        }
                    }
                }
                break;

            case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT:
            case SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT:
                gp_reg_id = field_ptr[ii]->reg_id[0].key.gp_reg.reg_id;
                gp_reg_info_item->pbh.gp_reg_fg_fields_map[gp_reg_id] = field_list_idx;
                gp_reg_info_item->pbh.reg_ids[gp_reg_pos] = gp_reg_id;
                gp_reg_bitmask |= (1 << gp_reg_id);
                ++gp_reg_pos;
                break;

            default:
                break;
            }
        }
        ++ind;
    }

    gp_reg_info_item->type = gp_reg_usage_type;
    gp_reg_info_item->gp_reg_bitmask = gp_reg_bitmask;

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_collect_pbh_info(_Inout_ mlnx_sai_issu_gp_reg_info *gp_reg_info,
                                                   _In_ mlnx_gp_reg_usage_t           gp_reg_usage_type)
{
    sai_status_t                       sai_status = SAI_STATUS_SUCCESS;
    mlnx_switch_usage_hash_object_id_t hash_obj_id = SAI_HASH_MAX_OBJ_ID;
    sai_object_id_t                    hash_id = SAI_NULL_OBJECT_ID;
    uint32_t                           hash_index = 0;
    uint32_t                           fields_num = 0;
    uint32_t                           ind = 0;
    const mlnx_sai_fg_hash_field_t    *fields_list = NULL;
    bool                               optimized_hash = false;
    mlnx_sai_issu_gp_reg_info_elem    *gp_reg_arr_item = NULL;

    SX_LOG_ENTER();

    assert(gp_reg_info);
    assert(gp_reg_info->gp_reg_arr);

    switch (gp_reg_usage_type) {
    case GP_REG_USED_HASH_1:
        hash_obj_id = SAI_HASH_FG_1_ID;
        break;

    case GP_REG_USED_HASH_2:
        hash_obj_id = SAI_HASH_FG_2_ID;
        break;

    default:
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    hash_id = g_sai_db_ptr->oper_hash_list[hash_obj_id];
    assert(hash_id != SAI_NULL_OBJECT_ID);

    sai_status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(sai_status)) {
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    fields_list = &(g_sai_db_ptr->hash_list[hash_index].fg_fields[0]);

    for (ind = 0; ind < MLNX_SAI_FG_HASH_FIELDS_MAX_COUNT; ++ind) {
        if (fields_list[ind].fg_field_id != SAI_NULL_OBJECT_ID) {
            ++fields_num;
        }
    }

    optimized_hash = mlnx_sai_hash_check_optimized_hash_use_case(hash_index, fields_num);
    gp_reg_arr_item = &(gp_reg_info->gp_reg_arr[gp_reg_info->count]);

    sai_status = mlnx_sai_issu_storage_construct_pbh_info(fields_num,
                                                          fields_list,
                                                          optimized_hash,
                                                          gp_reg_usage_type,
                                                          gp_reg_arr_item);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    gp_reg_info->count++;

out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_collect_udf_info(_Inout_ mlnx_sai_issu_gp_reg_info *gp_reg_info)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     ii = 0;
    uint32_t     db_size = 0;
    uint32_t     count = 0;

    SX_LOG_ENTER();
    assert(gp_reg_info);

    sai_status = mlnx_udf_db_udf_group_size_get(&db_size);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    for (ii = 0; ii < db_size; ++ii) {
        count = 0;
        sai_status = mlnx_sai_udf_get_gp_reg_issu_info_from_udf_db
                         (ii, &(gp_reg_info->gp_reg_arr[gp_reg_info->count]), &count);
        if (SAI_ERR(sai_status)) {
            goto out;
        }
        gp_reg_info->count += count;
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_prepare_paths(const char* persistent_path)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    size_t       len = 0;
    size_t       size_to_cat = 0;

    SX_LOG_ENTER();

    if ((persistent_path == NULL) || !strcmp(persistent_path, "")) {
        strcpy(g_issu_gp_reg_path, MLNX_SAI_ISSU_PERSISTENT_DEFAULT_PATH);
    } else {
        strncpy(g_issu_gp_reg_path, persistent_path, SX_ISSU_PATH_LEN_MAX - 1);
        len = strlen(persistent_path) - 1;
        if (persistent_path[len] != '/') {
            strcat(g_issu_gp_reg_path, "/");
        }
    }
    strncpy(g_issu_pbh_transition_flag_path, g_issu_gp_reg_path, MLNX_SAI_ISSU_PATH_LEN_MAX - 1);
    g_issu_pbh_transition_flag_path[MLNX_SAI_ISSU_PATH_LEN_MAX - 1] = '\0';

    len = strlen(g_issu_pbh_transition_flag_path);
    size_to_cat = MLNX_SAI_ISSU_PATH_LEN_MAX - len - 1;
    strncat(g_issu_pbh_transition_flag_path, MLNX_ISSU_PBH_TRANSITION_FILE_NAME, size_to_cat);
    len = strlen(g_issu_gp_reg_path);
    size_to_cat = MLNX_SAI_ISSU_PATH_LEN_MAX - len - 1;
    strncat(g_issu_gp_reg_path, MLNX_ISSU_GP_REG_FILE_NAME, size_to_cat);

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_restore_info_spc2()
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    sai_status_t sai_status_2 = SAI_STATUS_SUCCESS;
    cl_status_t  rc = CL_SUCCESS;
    FILE        *file_p = NULL;
    size_t       file_size = 0;
    uint16_t     old_chsum = 0;
    uint16_t     new_chsum = 0;

    SX_LOG_ENTER();

    sai_status = mlnx_sai_issu_storage_open(g_issu_gp_reg_path, "rb", &file_p);
    if (SAI_ERR(sai_status)) {
        SX_LOG_NTC("ISSU persistent file does not exist\n");
        sai_status = SAI_STATUS_SUCCESS;
        goto out;
    }

    rc = cl_file_size(file_p, &file_size);
    if (rc != CL_SUCCESS) {
        SX_LOG_ERR("Checking for file size failed, err - %s \n", CL_STATUS_MSG(rc));
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_checksum_restore(file_p, &old_chsum);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_gp_reg_alloc_db(file_p, file_size);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_gp_reg_info_restore(file_p);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    sai_status = mlnx_sai_issu_storage_checksum_calc(g_gp_reg_info, &new_chsum);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    if (new_chsum != old_chsum) {
        SX_LOG_ERR("Persistent file is corrupted. ISSU for gp registers failed\n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (MLNX_ISSU_PDB_FILE_VERSION_1 != g_gp_reg_info->version) {
        SX_LOG_ERR("Unexpected version of persistent file. ISSU for gp registers failed\n");
        sai_status = SAI_STATUS_FAILURE;
        goto out;
    }

    g_sai_db_ptr->is_issu_gp_reg_restore = true;

out:
    if (file_p) {
        sai_status_2 = mlnx_sai_issu_storage_close(&file_p);
        if (SAI_ERR(sai_status_2)) {
            SX_LOG_WRN("Failed to close persistent issu storage\n");
        }
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_restore_info_impl()
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    assert(mlnx_issu_storage_cb);
    if (mlnx_issu_storage_cb->issu_restore_info) {
        sai_status = mlnx_issu_storage_cb->issu_restore_info();
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_issu_init(sai_switch_profile_id_t profile_id, mlnx_sai_boot_type_t boot_type)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    const char  *issu_path = NULL;

    SX_LOG_ENTER();

    issu_path = g_mlnx_services.profile_get_value(profile_id, SAI_KEY_WARM_BOOT_WRITE_FILE);

    sai_status = mlnx_sai_issu_prepare_paths(issu_path);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    if ((BOOT_TYPE_WARM != boot_type) || !g_sai_db_ptr->issu_enabled) {
        goto out;
    }

    sai_status = mlnx_sai_issu_restore_info_impl();
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    if (!g_sai_db_ptr->is_issu_gp_reg_restore) {
        sai_status = mlnx_sai_issu_storage_dynamic_pbh_detect_transition();
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

    if (g_sai_db_ptr->pbhash_transition) {
        sai_status = mlnx_sai_issu_storage_dynamic_pbh_allocate_transiton_db();
        if (SAI_ERR(sai_status)) {
            goto out;
        }

        sai_status = mlnx_sai_issu_storage_dynamic_pbh_construct_transition_db();
        if (SAI_ERR(sai_status)) {
            goto out;
        }
    }

out:
    cl_remove(g_issu_gp_reg_path);
    cl_remove(g_issu_pbh_transition_flag_path);
    SX_LOG_EXIT();
    return sai_status;
}

static bool mlnx_sai_issu_storage_compare_pbh_info(_In_ const mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_a,
                                                   _In_ const mlnx_sai_issu_gp_reg_info_elem *gp_reg_info_b)
{
    bool is_equal = false;

    assert(gp_reg_info_a);
    assert(gp_reg_info_b);

    is_equal = (!memcmp(&(gp_reg_info_a->pbh.masks[0]),
                        &(gp_reg_info_b->pbh.masks[0]),
                        sizeof(gp_reg_info_a->pbh.masks)) &&
                !memcmp(&(gp_reg_info_a->pbh.native_fields_list[0]),
                        &(gp_reg_info_b->pbh.native_fields_list[0]),
                        sizeof(gp_reg_info_a->pbh.native_fields_list)));
    if (!g_sai_db_ptr->pbhash_transition) {
        is_equal = is_equal && !memcmp(&(gp_reg_info_a->pbh.sequence_ids[0]),
                                       &(gp_reg_info_b->pbh.sequence_ids[0]),
                                       sizeof(gp_reg_info_a->pbh.sequence_ids));
    }

    return is_equal;
}

sai_status_t mlnx_sai_issu_storage_get_pbh_stored_gp_reg_usage(_In_ uint32_t                        fields_count,
                                                               _In_ const mlnx_sai_fg_hash_field_t *fields_list,
                                                               _In_ bool                            optimized,
                                                               _Out_ mlnx_gp_reg_usage_t           *gp_reg_usage_prev)
{
    sai_status_t                   sai_status = SAI_STATUS_SUCCESS;
    mlnx_sai_issu_gp_reg_info_elem gp_reg_info_item = {0};
    mlnx_gp_reg_usage_t            gp_reg_usage = GP_REG_USED_NONE;
    uint32_t                       ii = 0;
    mlnx_gp_reg_usage_t            gp_reg_usage_type = 0;

    SX_LOG_ENTER();

    assert(fields_list);
    assert(gp_reg_usage_prev);

    sai_status = mlnx_sai_issu_storage_construct_pbh_info(fields_count,
                                                          fields_list,
                                                          optimized,
                                                          gp_reg_usage,
                                                          &gp_reg_info_item);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    for (ii = 0; ii < g_gp_reg_info->count; ++ii) {
        gp_reg_usage_type = g_gp_reg_info->gp_reg_arr[ii].type;
        if ((GP_REG_USED_HASH_1 != gp_reg_usage_type) &&
            (GP_REG_USED_HASH_2 != gp_reg_usage_type)) {
            continue;
        }

        if (g_gp_reg_info->is_gp_reg_in_use[g_gp_reg_info->gp_reg_arr[ii].pbh.reg_ids[0]]) {
            continue;
        }

        if (mlnx_sai_issu_storage_compare_pbh_info(&gp_reg_info_item, &(g_gp_reg_info->gp_reg_arr[ii]))) {
            gp_reg_usage = gp_reg_usage_type;
            goto out;
        }
    }

    sai_status = SAI_STATUS_ITEM_NOT_FOUND;

out:
    *gp_reg_usage_prev = gp_reg_usage;
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_issu_storage_pbh_gp_reg_idx_lookup(_In_ sai_native_hash_field_t field,
                                                         _In_ mlnx_gp_reg_usage_t     type,
                                                         _Out_ sx_gp_register_e      *reg_id_out)
{
    sai_status_t     sai_status = SAI_STATUS_SUCCESS;
    uint32_t         ii = 0;
    uint32_t         jj = 0;
    uint32_t         gp_reg_num = 0;
    sx_gp_register_e reg_id = SX_GP_REGISTER_LAST_E;
    uint8_t          field_idx = 0;

    SX_LOG_ENTER();

    assert(g_sai_db_ptr->is_issu_gp_reg_restore || g_sai_db_ptr->pbhash_transition);
    assert(g_gp_reg_info);
    assert(g_gp_reg_info->is_gp_reg_in_use);
    assert(g_gp_reg_info->gp_reg_arr);

    for (ii = 0; ii < g_gp_reg_info->count; ++ii) {
        if (type != g_gp_reg_info->gp_reg_arr[ii].type) {
            continue;
        }

        for (jj = 0; jj < MLNX_UDF_GP_REG_COUNT; ++jj) {
            if (g_gp_reg_info->gp_reg_arr[ii].gp_reg_bitmask & (1 << jj)) {
                ++gp_reg_num;
            }
        }

        for (jj = 0; jj < gp_reg_num; ++jj) {
            reg_id = g_gp_reg_info->gp_reg_arr[ii].pbh.reg_ids[jj];
            if (g_gp_reg_info->is_gp_reg_in_use[reg_id]) {
                continue;
            }

            field_idx = g_gp_reg_info->gp_reg_arr[ii].pbh.gp_reg_fg_fields_map[reg_id];

            if (g_gp_reg_info->gp_reg_arr[ii].pbh.native_fields_list[field_idx] != field) {
                continue;
            }

            g_gp_reg_info->is_gp_reg_in_use[reg_id] = true;
            *reg_id_out = reg_id;
            goto out;
        }
    }

    sai_status = SAI_STATUS_ITEM_NOT_FOUND;

out:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_issu_storage_ip_ident_gp_reg_idx_lookup(_Out_ sx_gp_register_e *reg_id)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     ii = 0;
    uint32_t     jj = 0;

    SX_LOG_ENTER();

    assert(reg_id);
    assert(g_sai_db_ptr->is_issu_gp_reg_restore);
    assert(g_gp_reg_info);
    assert(g_gp_reg_info->is_gp_reg_in_use);
    assert(g_gp_reg_info->gp_reg_arr);

    for (ii = 0; ii < g_gp_reg_info->count; ++ii) {
        if (GP_REG_USED_IP_IDENT != g_gp_reg_info->gp_reg_arr[ii].type) {
            continue;
        }

        for (jj = 0; jj < MLNX_UDF_GP_REG_COUNT; ++jj) {
            if (g_gp_reg_info->gp_reg_arr[ii].gp_reg_bitmask & (1 << jj)) {
                if (g_gp_reg_info->is_gp_reg_in_use[jj]) {
                    continue;
                }
                g_gp_reg_info->is_gp_reg_in_use[jj] = true;
                *reg_id = jj;
                goto out;
            }
        }
    }

    sai_status = SAI_STATUS_ITEM_NOT_FOUND;

out:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_issu_storage_udf_gp_reg_idx_lookup(_Out_ sx_gp_register_e *reg_id, _In_ uint32_t group_db_index)
{
    sai_status_t              sai_status = SAI_STATUS_SUCCESS;
    mlnx_issu_gp_reg_udf_info udf_info = {0};
    uint32_t                  ii = 0;
    uint32_t                  jj = 0;

    SX_LOG_ENTER();

    assert(reg_id);
    assert(g_sai_db_ptr->is_issu_gp_reg_restore);
    assert(g_gp_reg_info);
    assert(g_gp_reg_info->is_gp_reg_in_use);
    assert(g_gp_reg_info->gp_reg_arr);

    sai_status = mlnx_sai_udf_get_issu_udf_info(group_db_index, &udf_info);
    if (SAI_ERR(sai_status)) {
        goto out;
    }

    for (ii = 0; ii < g_gp_reg_info->count; ++ii) {
        if (GP_REG_USED_UDF != g_gp_reg_info->gp_reg_arr[ii].type) {
            continue;
        }

        /* mismatch between udfs configuration, non relevant or incomplete
         * (if two blocks of memory are not equal memcmp returns non 0)*/
        if (memcmp(&udf_info, &(g_gp_reg_info->gp_reg_arr[ii].udf), sizeof(udf_info))) {
            continue;
        }

        for (jj = 0; jj < MLNX_UDF_GP_REG_COUNT; ++jj) {
            if (g_gp_reg_info->gp_reg_arr[ii].gp_reg_bitmask & (1 << jj)) {
                if (g_gp_reg_info->is_gp_reg_in_use[jj]) {
                    continue;
                }
                g_gp_reg_info->is_gp_reg_in_use[jj] = true;
                *reg_id = jj;
                goto out;
            }
        }
    }

    sai_status = SAI_STATUS_ITEM_NOT_FOUND;

out:
    SX_LOG_EXIT();
    return sai_status;
}

sai_status_t mlnx_sai_issu_storage_check_gp_reg_is_set_to_hw()
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;
    uint32_t     ii = 0;
    uint32_t     jj = 0;
    uint32_t     gp_reg_hw_cnt = 0;
    uint32_t     gp_reg_db_cnt = 0;

    SX_LOG_ENTER();

    assert(g_gp_reg_info);

    /* number of gp registers configured in hw */
    for (ii = 0; ii < MLNX_UDF_GP_REG_COUNT; ++ii) {
        if (g_gp_reg_info->is_gp_reg_in_use[ii]) {
            ++gp_reg_hw_cnt;
        }
    }

    for (ii = 0; ii < g_gp_reg_info->count; ++ii) {
        for (jj = 0; jj < MLNX_UDF_GP_REG_COUNT; ++jj) {
            if (g_gp_reg_info->gp_reg_arr[ii].gp_reg_bitmask & (1 << jj)) {
                ++gp_reg_db_cnt;
            }
        }
    }

    if (gp_reg_hw_cnt != gp_reg_db_cnt) {
        sai_status = SAI_STATUS_FAILURE;
    }

    mlnx_sai_issu_storage_gp_reg_dealloc_db();
    SX_LOG_EXIT();
    return sai_status;
}
