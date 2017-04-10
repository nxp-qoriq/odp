include $(top_srcdir)/example/Makefile.inc

bindir=${exec_prefix}/odp/bin
bin_PROGRAMS = odp_ipsec_proto$(EXEEXT)
odp_ipsec_proto_LDFLAGS = $(AM_LDFLAGS) -static
odp_ipsec_proto_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/ipsec_proto/odp_ipsec_proto_cache.h \
		  $(top_srcdir)/example/ipsec_proto/odp_ipsec_proto_fwd_db.h \
		  $(top_srcdir)/example/ipsec_proto/odp_ipsec_proto_misc.h \
		  $(top_srcdir)/example/ipsec_proto/odp_ipsec_proto_sa_db.h \
		  $(top_srcdir)/example/ipsec_proto/odp_ipsec_proto_sp_db.h \
		  $(top_srcdir)/example/example_debug.h

dist_odp_ipsec_proto_SOURCES = odp_ipsec_proto.c \
			 odp_ipsec_proto_sa_db.c \
			 odp_ipsec_proto_sp_db.c \
			 odp_ipsec_proto_fwd_db.c \
			 odp_ipsec_proto_cache.c
