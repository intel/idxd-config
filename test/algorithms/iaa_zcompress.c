// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "algorithms/iaa_zcompress.h"

static int iaa_zcompress_get_random_value(void)
{
	static int extra_seed;

	srand(time(NULL) + (extra_seed++));
	return rand();
}

static uint16_t iaa_zcompress16_get_word_pattern(uint64_t pattern)
{
	uint16_t word_pattern = 0;
	int position = (iaa_zcompress_get_random_value() % 4);

	word_pattern = (uint16_t)((pattern & (0xFFFF << (16 * position))) >> (16 * position));
	return word_pattern;
}

void iaa_zcompress16_randomize_input(void *dst, uint64_t pattern, int len)
{
	int i;
	int num_words = len / 2;

	for (i = 0; i < num_words; i++) {
		if (iaa_zcompress_get_random_value() % 2)
			((uint16_t *)dst)[i] = iaa_zcompress16_get_word_pattern(pattern);
		else
			((uint16_t *)dst)[i] = 0;
	}
}
