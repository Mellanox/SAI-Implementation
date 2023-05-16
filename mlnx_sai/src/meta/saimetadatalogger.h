/**
 * Copyright (c) 2014 Microsoft Open Technologies, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 *    Microsoft would like to thank the following companies for their review and
 *    assistance with these files: Intel Corporation, Mellanox Technologies Ltd,
 *    Dell Products, L.P., Facebook, Inc., Marvell International Ltd.
 *
 * @file    saimetadatalogger.h
 *
 * @brief   This module defines SAI Metadata Logger
 */

#ifndef __SAIMETADATALOGGER_H_
#define __SAIMETADATALOGGER_H_

/**
 * @defgroup SAIMETADATALOGGER SAI - Metadata Logger Definitions
 *
 * @{
 */

/**
 * @brief Log level function definition.
 *
 * User can specify his own function that will be called when message log level
 * will be greater or equal to #sai_metadata_log_level.
 *
 * @param[in] log_level Log level
 * @param[in] file Source file
 * @param[in] line Line number in file
 * @param[in] function Function name
 * @param[in] format Format of logging
 * @param[in] ... Variable parameters
 */
typedef void (*sai_metadata_log_fn)(
        _In_ sai_log_level_t log_level,
        _In_ const char *file,
        _In_ int line,
        _In_ const char *function,
        _In_ const char *format,
        _In_ ...);

/**
 * @brief User specified log function.
 *
 * TODO: add a set function to update this?
 */
extern volatile sai_metadata_log_fn sai_metadata_log;

/**
 * @brief Log level for SAI metadata macros.
 *
 * Log level can be changed by user at any time.
 *
 * TODO: add a set function to update this?
 */
extern volatile sai_log_level_t sai_metadata_log_level;

/**
 * @brief Helper log macro definition
 *
 * If logger function is NULL, stderr is used to print messages. Also, fprintf
 * function will validate parameters at compilation time.
 */
#define SAI_META_LOG(loglevel,format,...)                                                       \
    if (loglevel >= sai_metadata_log_level)                                                     \
{                                                                                               \
    if (sai_metadata_log == NULL) /* or syslog? */                                              \
        fprintf(stderr, "%s:%d %s: " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    else                                                                                        \
        sai_metadata_log(loglevel, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__);        \
}

/*
 * Helper macros.
 */

#define SAI_META_LOG_ENTER()                SAI_META_LOG(SAI_LOG_LEVEL_DEBUG,    ":> enter");
#define SAI_META_LOG_DEBUG(format,...)      SAI_META_LOG(SAI_LOG_LEVEL_DEBUG,    ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_INFO(format,...)       SAI_META_LOG(SAI_LOG_LEVEL_INFO,     ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_NOTICE(format,...)     SAI_META_LOG(SAI_LOG_LEVEL_NOTICE,   ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_WARN(format,...)       SAI_META_LOG(SAI_LOG_LEVEL_WARN,     ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_ERROR(format,...)      SAI_META_LOG(SAI_LOG_LEVEL_ERROR,    ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_CRITICAL(format,...)   SAI_META_LOG(SAI_LOG_LEVEL_CRITICAL, ":- " format, ##__VA_ARGS__)
#define SAI_META_LOG_EXIT()                 SAI_META_LOG(SAI_LOG_LEVEL_DEBUG,    ":< exit");

/**
 * @}
 */
#endif /** __SAIMETADATALOGGER_H_ */
