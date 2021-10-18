AM_CPPFLAGS = -I$(top_srcdir)
check_PROGRAMS = parser
TESTS_ENVIRONMENT = $(builddir)/parser
parser_SOURCES = parser.c
parser_LDADD = $(top_builddir)/libnbdclt.la $(top_builddir)/libcliserv.la
TESTS = empty noopts singleopt multiopt ipv6
EXTRA_DIST=$(TESTS)
