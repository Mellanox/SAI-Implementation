/*
Copyright 2018 Mellanox.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "fx_base_bitmap.h"

void alloc_bitmap(fx_bitmap_t *bitmap, uint64_t size) {
	int num_of_bytes = (size % CHAR_BIT == 0) ? size / CHAR_BIT : size / CHAR_BIT + 1;
	*bitmap = (fx_bitmap_t) calloc(num_of_bytes, 1);
	return;
}

void free_bitmap(fx_bitmap_t bitmap) {
	free(bitmap);
}

void set_bitmap(fx_bitmap_t bitmap, uint64_t pos) {
	bitmap[pos/CHAR_BIT] |= 1 << (pos % CHAR_BIT); 
}

void reset_bitmap(fx_bitmap_t bitmap, uint64_t pos) {
	bitmap[pos/CHAR_BIT] &= ~(1 << (pos % CHAR_BIT)); 
}

int get_bitmap(fx_bitmap_t bitmap, uint64_t pos) {
	return (bitmap[pos/CHAR_BIT] >> (pos%CHAR_BIT)) & 1;
}

void clear_all_bitmap(fx_bitmap_t bitmap, uint64_t size) {
	int num_of_bytes = (size % CHAR_BIT == 0) ? size / CHAR_BIT : size / CHAR_BIT + 1;
	memset(bitmap, 0, num_of_bytes);
}
