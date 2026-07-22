AM_CPPFLAGS =  -I$(top_srcdir)/src
LDADD = $(top_srcdir)/src/libckpool.a

bin_PROGRAMS = sha256 pow cashaddr

TESTS = sha256 pow cashaddr

sha256_SOURCES = sha256.c
pow_SOURCES = pow.c
cashaddr_SOURCES = cashaddr.c
#sha256_LDADD = libckpool.a
cashaddr_LDADD = $(top_srcdir)/src/libckpool.a $(top_srcdir)/src/jansson-2.14/src/.libs/libjansson.a -lm
