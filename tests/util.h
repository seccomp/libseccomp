/**
 * Seccomp Library utility code for tests
 *
 * Copyright IBM Corp. 2012
 * Author: Corey Bryant <coreyb@linux.vnet.ibm.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _UTIL_TEST_H
#define _UTIL_TEST_H

int util_getopt(int argc, char *argv[], int *bpf);

#endif
