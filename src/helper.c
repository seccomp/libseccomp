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
	void *ptr;

	/* NOTE: unlike malloc() zero size allocations always return NULL */
	if (size == 0)
		return NULL;

	ptr = malloc(size);
	if (!ptr)
		return NULL;
	memset(ptr, 0, size);

	return ptr;
}
