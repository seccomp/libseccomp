# -*- Makefile -*-

noinst_LTLIBRARIES = util.la
util_la_SOURCES = util.c util.h
util_la_LDFLAGS = -module

bin_PROGRAMS    = scmp_sys_resolver
noinst_PROGRAMS = scmp_arch_detect scmp_bpf_disasm scmp_bpf_sim

scmp_sys_resolver_LDADD   = ../src/libseccomp.la
scmp_arch_detect_LDADD    = ../src/libseccomp.la
scmp_bpf_disasm_LDADD = util.la
scmp_bpf_sim_LDADD = util.la
