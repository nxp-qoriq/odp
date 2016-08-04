include $(top_srcdir)/example/Makefile.inc

bindir=${exec_prefix}/odp/bin
bin_PROGRAMS = odp_cmdif_demo
odp_cmdif_demo_LDFLAGS = $(AM_LDFLAGS) -static
odp_cmdif_demo_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_cmdif_demo_SOURCES = odp_cmdif_demo.c
