/**
 * Seccomp Library hash code
 *
 */

/*
 * This code is based on MurmurHash3.cpp from Austin Appleby and is placed in
 * the public domain.
 *
 * https://github.com/aappleby/smhasher
 *
 */

#include <stdlib.h>
#include <inttypes.h>

#include "hash.h"

static inline uint32_t getblock32(const uint32_t *p, int i)
{
	return p[i];
}

static inline uint32_t rotl32(uint32_t x, int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

static inline uint32_t fmix32(uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

/* NOTE: this is an implementation of MurmurHash3_x86_32 */
uint32_t hash(const void *key, size_t length)
{
	const uint8_t *data = (const uint8_t *)key;
	const uint32_t *blocks;
	const uint8_t *tail;
	const int nblocks = length / 4;
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	uint32_t k1;
	uint32_t k2 = 0;
	int i;

	/* NOTE: we always force a seed of 0 */
	uint32_t h1 = 0;

	/* body */
	blocks = (const uint32_t *)(data + nblocks * 4);
	for(i = -nblocks; i; i++) {
		k1 = getblock32(blocks, i);

		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	/* tail */
	tail = (const uint8_t *)(data + nblocks * 4);
	switch(length & 3) {
	case 3:
		k2 ^= tail[2] << 16;
	case 2:
		k2 ^= tail[1] << 8;
	case 1:
		k2 ^= tail[0];
		k2 *= c1;
		k2 = rotl32(k2, 15);
		k2 *= c2;
		h1 ^= k2;
	};

	/* finalization */
	h1 ^= length;
	h1 = fmix32(h1);

	return h1;
}
