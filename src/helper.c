/**
 * Helper functions for libseccomp
 *
 * Copyright (c) 2017 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <stdlib.h>
#include <string.h>

#include "helper.h"

/**
 * Allocate memory
 * @param size the size of the buffer to allocate
 *
 * This function allocates a buffer of the given size, initializes it to zero,
 * and returns a pointer to buffer on success.  NULL is returned on failure.
 *
 */
void *zmalloc(size_t size)
{
	/* NOTE: unlike malloc() zero size allocations always return NULL */
	if (size == 0)
		return NULL;

	return calloc(1, size);
}

/**
 * Change the size of an allocated buffer
 * @param ptr pointer to the allocated buffer.  If NULL it is equivalent to zmalloc.
 * @param old_size the current size of the allocated buffer
 * @param size the new size of the buffer
 *
 * This function changes the size of an allocated memory buffer and return a pointer
 * to the buffer on success, the new buffer portion is initialized to zero.  NULL is
 * returned on failure.  The returned buffer could be different than the specified
 * ptr param.
 *
 */
void *zrealloc(void *ptr, size_t old_size, size_t size)
{
	/* NOTE: unlike malloc() zero size allocations always return NULL */
	if (size == 0)
		return NULL;

	ptr = realloc(ptr, size);
	if (!ptr)
		return NULL;
	memset(ptr + old_size, 0, size - old_size);
	return ptr;
}
