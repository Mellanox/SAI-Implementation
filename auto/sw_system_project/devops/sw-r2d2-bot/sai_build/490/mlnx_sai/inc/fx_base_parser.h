/* Copyright (C) 2019-present. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Machine level APIs for flexible, programmable control of Mellanox switches.
 * These APIs are extensions of the SX APIs from the SDK, and are intended to
 * be a relatively stable interface to an auto-generated implementation.
 * Additional auto generated human friendly SDK and SAI APIs are build on top
 * of these basic APIs.
 *
 * Currently device support: Spectrum
 *
 */

#ifndef _FX_BASE_PARSER_INIT_H_
#define _FX_BASE_PARSER_INIT_H_

#include <stdint.h>

/* flextrum */
#include <fx_base_api.h>


#ifdef __cplusplus
extern "C"{
#endif

sx_status_t fx_device_init(fx_handle_t handle, char* pci_dev);
sx_status_t fx_device_deinit(fx_handle_t handle);
sx_status_t fx_parser_init(fx_handle_t handle);
sx_status_t fx_parser_deinit(fx_handle_t handle);

/* TODO - auto generate other adabe based functions */
typedef enum _fx_span_header_type
{
        FX_SPAN_HEADER_TYPE_MIN = 0,
        /** mirroring header V0 (different between ETH/IB) - same as BAZ */
        FX_SPAN_HEADER_TYPE_V0 = FX_PIPE_TYPE_MIN,
        /** mirroring header V1 (same for ETH/IB) */
        FX_SPAN_HEADER_TYPE_V1,
        /** No mirroring header */
        FX_SPAN_HEADER_TYPE_NONE,
        /** mirror header V2 - Spectrum 2 and above */
        FX_SPAN_HEADER_TYPE_V2,
        FX_SPAN_HEADER_TYPE_MAX
} fx_span_header_type_t;

/* not necessarily the same as SDK, but appears to be so */
typedef uint8_t sx_span_session_id_t;
#define FX_SPAN_SESSION_ALL 0xFF

sx_status_t fx_span_header_type_set(fx_span_header_type_t type, sx_span_session_id_t session);

#ifdef __cplusplus
}
#endif

#endif /* _FX_BASE_PARSER_INIT_H_ */
