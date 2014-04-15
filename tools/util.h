/**
 * Tool utility functions
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
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

#ifndef _UTIL_H
#define _UTIL_H

#include <inttypes.h>

extern uint32_t arch;

void exit_usage(const char *program);

uint16_t ttoh16(uint32_t arch, uint16_t val);
uint32_t ttoh32(uint32_t arch, uint32_t val);

uint32_t htot32(uint32_t arch, uint32_t val);
uint64_t htot64(uint32_t arch, uint64_t val);

#endif
