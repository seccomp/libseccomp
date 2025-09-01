/**
 * Seccomp Library
 *
 * Copyright (c) 2025 Oracle and/or its affiliates.
 * Author: Tom Hromatka <tom.hromatka@oracle.com>
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

#ifndef _SECCOMP_H
#error "do not include seccomp-kvers.h directly, use seccomp.h instead"
#endif

/**
 * Kernel versions
 */
enum scmp_kver {
	__SCMP_KV_NULL = 0,
	SCMP_KV_UNDEF = 1,
	SCMP_KV_3_0 = 2,
	SCMP_KV_3_1 = 3,
	SCMP_KV_3_2 = 4,
	SCMP_KV_3_3 = 5,
	SCMP_KV_3_4 = 6,
	SCMP_KV_3_5 = 7,
	SCMP_KV_3_6 = 8,
	SCMP_KV_3_7 = 9,
	SCMP_KV_3_8 = 10,
	SCMP_KV_3_9 = 11,
	SCMP_KV_3_10 = 12,
	SCMP_KV_3_11 = 13,
	SCMP_KV_3_12 = 14,
	SCMP_KV_3_13 = 15,
	SCMP_KV_3_14 = 16,
	SCMP_KV_3_15 = 17,
	SCMP_KV_3_16 = 18,
	SCMP_KV_3_17 = 19,
	SCMP_KV_3_18 = 20,
	SCMP_KV_3_19 = 21,
	SCMP_KV_4_0 = 22,
	SCMP_KV_4_1 = 23,
	SCMP_KV_4_2 = 24,
	SCMP_KV_4_3 = 25,
	SCMP_KV_4_4 = 26,
	SCMP_KV_4_5 = 27,
	SCMP_KV_4_6 = 28,
	SCMP_KV_4_7 = 29,
	SCMP_KV_4_8 = 30,
	SCMP_KV_4_9 = 31,
	SCMP_KV_4_10 = 32,
	SCMP_KV_4_11 = 33,
	SCMP_KV_4_12 = 34,
	SCMP_KV_4_13 = 35,
	SCMP_KV_4_14 = 36,
	SCMP_KV_4_15 = 37,
	SCMP_KV_4_16 = 38,
	SCMP_KV_4_17 = 39,
	SCMP_KV_4_18 = 40,
	SCMP_KV_4_19 = 41,
	SCMP_KV_4_20 = 42,
	SCMP_KV_5_0 = 43,
	SCMP_KV_5_1 = 44,
	SCMP_KV_5_2 = 45,
	SCMP_KV_5_3 = 46,
	SCMP_KV_5_4 = 47,
	SCMP_KV_5_5 = 48,
	SCMP_KV_5_6 = 49,
	SCMP_KV_5_7 = 50,
	SCMP_KV_5_8 = 51,
	SCMP_KV_5_9 = 52,
	SCMP_KV_5_10 = 53,
	SCMP_KV_5_11 = 54,
	SCMP_KV_5_12 = 55,
	SCMP_KV_5_13 = 56,
	SCMP_KV_5_14 = 57,
	SCMP_KV_5_15 = 58,
	SCMP_KV_5_16 = 59,
	SCMP_KV_5_17 = 60,
	SCMP_KV_5_18 = 61,
	SCMP_KV_5_19 = 62,
	SCMP_KV_6_0 = 63,
	SCMP_KV_6_1 = 64,
	SCMP_KV_6_2 = 65,
	SCMP_KV_6_3 = 66,
	SCMP_KV_6_4 = 67,
	SCMP_KV_6_5 = 68,
	SCMP_KV_6_6 = 69,
	SCMP_KV_6_7 = 70,
	SCMP_KV_6_8 = 71,
	SCMP_KV_6_9 = 72,
	SCMP_KV_6_10 = 73,
	SCMP_KV_6_11 = 74,
	SCMP_KV_6_12 = 75,
	SCMP_KV_6_13 = 76,
	SCMP_KV_6_14 = 77,
	SCMP_KV_6_15 = 78,
	SCMP_KV_6_16 = 79,
	__SCMP_KV_MAX,
};
