include $(top_srcdir)/example/Makefile.inc

bindir=${exec_prefix}/odp/bin
bin_PROGRAMS = odp_l3fwd
odp_l3fwd_LDFLAGS = $(AM_LDFLAGS)
odp_l3fwd_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_l3fwd_SOURCES = odp_l3fwd.c odp_l3fwd_ctrl.c
