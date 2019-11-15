#!/bin/bash

#
# libseccomp regression test automation data
#
# Copyright (c) 2019 Oracle and/or its affiliates.  All rights reserved.
# Author: Tom Hromatka <tom.hromatka@oracle.com>
#

####
# functions

#
# Dependency check
#
# Arguments:
#     1    Dependency to check for
#
function check_deps() {
	[[ -z "$1" ]] && return
	which "$1" >& /dev/null
	return $?
}

#
# Dependency verification
#
# Arguments:
#     1    Dependency to check for
#
function verify_deps() {
	[[ -z "$1" ]] && return
	if ! check_deps "$1"; then
		echo "error: install \"$1\" and include it in your \$PATH"
		exit 1
	fi
}

####
# functions

verify_deps diff

# compare output to the known good output, fail if different
./55-basic-pfc_binary_tree | \
	diff -q ${srcdir:=.}/55-basic-pfc_binary_tree.pfc - > /dev/null
