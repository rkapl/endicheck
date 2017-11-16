include $(top_srcdir)/Makefile.tool-tests.am

check_PROGRAMS =
EXTRA_DIST =

check_PROGRAMS += simple_correct
EXTRA_DIST += simple_correct.stderr.exp simple_correct.vgtest

check_PROGRAMS += simple_incorrect
EXTRA_DIST += simple_incorrect.vgtest simple_incorrect.stderr.exp

check_PROGRAMS += memcmpy_correct
EXTRA_DIST += memcmpy_correct.vgtest memcmpy_correct.stderr.exp

check_PROGRAMS += bitop
EXTRA_DIST += bitop.vgtest bitop.stderr.exp
