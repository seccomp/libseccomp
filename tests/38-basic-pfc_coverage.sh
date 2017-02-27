#!/bin/bash

#
# libseccomp regression test automation data
#
# Copyright (c) 2017 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <paul@paul-moore.com>
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
./38-basic-pfc_coverage | \
	diff -q ${srcdir:=.}/38-basic-pfc_coverage.pfc - > /dev/null
