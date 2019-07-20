#ifndef _MLNX_FLEX_BITMAP_H
#define _MLNX_FLEX_BITMAP_H

#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#define FX_BITMAP_SIZE_MAX 4000

typedef unsigned char fx_bitmap_t[FX_BITMAP_SIZE_MAX/CHAR_BIT + 1];

void alloc_bitmap(fx_bitmap_t *bitmap, uint64_t size) {
    //size_t num_of_bytes = (size % CHAR_BIT == 0) ? size / CHAR_BIT : size / CHAR_BIT + 1;
    assert(size < FX_BITMAP_SIZE_MAX);
    //*bitmap = (fx_bitmap_t) calloc(num_of_bytes, 1);
    memset(bitmap, 0, sizeof(fx_bitmap_t));
	return;
}

void free_bitmap(fx_bitmap_t bitmap) {
    memset(bitmap, 0, sizeof(fx_bitmap_t));
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
    //size_t num_of_bytes = (size % CHAR_BIT == 0) ? size / CHAR_BIT : size / CHAR_BIT + 1;
    memset(bitmap, 0, sizeof(fx_bitmap_t));
}

#endif /* _MLNX_FLEX_BITMAP_H */
