include $(top_srcdir)/example/Makefile.inc

bindir=${exec_prefix}/odp/bin
bin_PROGRAMS = odp_kni_demo
odp_kni_demo_LDFLAGS = $(AM_LDFLAGS) -static
odp_kni_demo_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_kni_demo_SOURCES = odp_kni_demo.c
