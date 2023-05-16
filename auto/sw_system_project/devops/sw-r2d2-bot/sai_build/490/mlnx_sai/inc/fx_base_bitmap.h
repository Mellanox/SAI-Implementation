/* Copyright (C) 2017-present. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

#ifndef _FX_BASE_BITMAP_H_
#define _FX_BASE_BITMAP_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

typedef unsigned char* fx_bitmap_t;

void alloc_bitmap(fx_bitmap_t *bitmap, uint64_t size);
void free_bitmap(fx_bitmap_t bitmap);
void set_bitmap(fx_bitmap_t bitmap, uint64_t pos);
void reset_bitmap(fx_bitmap_t bitmap, uint64_t pos);
int get_bitmap(fx_bitmap_t bitmap, uint64_t pos) ;
void clear_all_bitmap(fx_bitmap_t bitmap, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif /* _FX_BASE_BITMAP_H_ */
