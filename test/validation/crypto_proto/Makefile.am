include ../Makefile.inc

noinst_LTLIBRARIES = libtestproto.la
libtestproto_la_SOURCES = proto.c \
		       odp_proto_test_inp.c

bin_PROGRAMS = proto_main$(EXEEXT)
dist_proto_main_SOURCES = proto_main.c
proto_main_LDADD = libtestproto.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = proto.h odp_proto_test_inp.h test_vectors.h test_vectors_len.h
