/**
 * Seccomp Library hash code
 *
 * See hash.c for information on the implementation.
 *
 */

#ifndef _HASH_H
#define _HASH_H

#include <inttypes.h>

uint32_t hash(const void *key, size_t length);

#endif

