/*
 * Copyright(c) 2019 Intel Corporation. All rights reserved.
 * Copyright(c) 2009 Akinobu Mita. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/* originally copied from the Linux kernel bitmap implementation */

#include <stdlib.h>
#include <util/size.h>
#include <util/util.h>
#include <util/bitmap.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <ccan/short_types/short_types.h>

uint64_t *bitmap_alloc(uint64_t nbits)
{
	return calloc(BITS_TO_LONGS(nbits), sizeof(uint64_t));
}

void bitmap_set(uint64_t *map, unsigned int start, int len)
{
	uint64_t *p = map + BIT_WORD(start);
	const unsigned int size = start + len;
	int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
	uint64_t mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (len - bits_to_set >= 0) {
		*p |= mask_to_set;
		len -= bits_to_set;
		bits_to_set = BITS_PER_LONG;
		mask_to_set = ~0UL;
		p++;
	}
	if (len) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		*p |= mask_to_set;
	}
}

void bitmap_clear(uint64_t *map, unsigned int start, int len)
{
	uint64_t *p = map + BIT_WORD(start);
	const unsigned int size = start + len;
	int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
	uint64_t mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

	while (len - bits_to_clear >= 0) {
		*p &= ~mask_to_clear;
		len -= bits_to_clear;
		bits_to_clear = BITS_PER_LONG;
		mask_to_clear = ~0UL;
		p++;
	}
	if (len) {
		mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
		*p &= ~mask_to_clear;
	}
}

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
int test_bit(unsigned int nr, const volatile uint64_t *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

/*
 * This is a common helper function for find_next_bit and
 * find_next_zero_bit.  The difference is the "invert" argument, which
 * is XORed with each fetched word before searching it for one bits.
 */
static uint64_t _find_next_bit(const uint64_t *addr,
		uint64_t nbits, uint64_t start, uint64_t invert)
{
	uint64_t tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return min(start + __builtin_ffsl(tmp), nbits);
}

/*
 * Find the next set bit in a memory region.
 */
uint64_t find_next_bit(const uint64_t *addr, uint64_t size,
			    uint64_t offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

uint64_t find_next_zero_bit(const uint64_t *addr, uint64_t size,
				 uint64_t offset)
{
	return _find_next_bit(addr, size, offset, ~0UL);
}

int bitmap_full(const uint64_t *src, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return ! (~(*src) & BITMAP_LAST_WORD_MASK(nbits));

	return find_next_zero_bit(src, nbits, 0UL) == nbits;
}
