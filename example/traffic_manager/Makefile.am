include $(top_srcdir)/example/Makefile.inc

bindir=${exec_prefix}/odp/bin
bin_PROGRAMS = odp_tm$(EXEEXT)
odp_tm_LDFLAGS = $(AM_LDFLAGS) -static
odp_tm_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_tm_SOURCES = odp_tm.c odp_tm_ctrl.c

if test_example
if HAVE_PCAP
TESTS = tm_run.sh
endif
endif
EXTRA_DIST = tm_run.sh udp64.pcap
