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

#ifndef _FX_BASE_ACTION_INIT_H_
#define _FX_BASE_ACTION_INIT_H_

#include <stdint.h>

/* flextrum */
#include <fx_base_api.h>


#ifdef __cplusplus
extern "C"{
#endif

sx_status_t fx_action_span_init(fx_handle_t handle);
sx_status_t fx_action_span_deinit(fx_handle_t handle);


#ifdef __cplusplus
}
#endif

#endif /* _FX_BASE_BITMAP_H_ */
