// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include "iaa_compress.h"

static void dump_stream(z_stream *stream)
{
	printf("inflate: avail_in=%d, total_in=%ld, avail_out=%d, total_out=%ld, next_out=0x%p\n",
	       stream->avail_in,
	       stream->total_in,
	       stream->avail_out,
	       stream->total_out,
	       stream->next_out);
}

int iaa_do_decompress(void *dst, void *src, int src_len, int *out_len)
{
	int ret = 0;
	z_stream stream;

	memset(&stream, 0, sizeof(z_stream));

	/* allocate inflate state */
	ret = inflateInit2(&stream, -MAX_WBITS);
	if (ret) {
		printf("Error inflateInit2 status %d\n", ret);
		return ret;
	}

	stream.avail_in = src_len;
	stream.next_in = src;
	stream.avail_out = IAA_COMPRESS_MAX_DEST_SIZE;
	stream.next_out = dst;
	dump_stream(&stream);

	do {
		ret = inflate(&stream, Z_NO_FLUSH);
		dump_stream(&stream);

		if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
			inflateEnd(&stream);
			printf("Error inflate status %d\n", ret);
			return ret;
		}
	} while (ret != Z_STREAM_END);

	ret = inflateEnd(&stream);
	if (ret) {
		printf("Error inflateEnd status %d\n", ret);
		return ret;
	}

	*out_len = stream.total_out;
	return ret;
}
