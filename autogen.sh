#!/bin/sh -e

test -d m4 || mkdir m4
autoreconf -fi;
rm -Rf autom4te.cache;
# do not call configure - this is unexpected
