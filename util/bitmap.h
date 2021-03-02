
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */
#ifndef _ACCFG_BITMAP_H_
#define _ACCFG_BITMAP_H_

#include <util/size.h>
#include <ccan/short_types/short_types.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BIT(nr)			(1UL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

uint64_t *bitmap_alloc(uint64_t nbits);
void bitmap_set(uint64_t *map, unsigned int start, int len);
void bitmap_clear(uint64_t *map, unsigned int start, int len);
int test_bit(unsigned int nr, const volatile uint64_t *addr);
uint64_t find_next_bit(const uint64_t *addr, uint64_t size,
			    uint64_t offset);
uint64_t find_next_zero_bit(const uint64_t *addr, uint64_t size,
				 uint64_t offset);
int bitmap_full(const uint64_t *src, unsigned int nbits);


#endif /* _ACCFG_BITMAP_H_ */
