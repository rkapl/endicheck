include $(top_srcdir)/Makefile.tool-tests.am

check_PROGRAMS =
EXTRA_DIST =

check_PROGRAMS += simple_correct
EXTRA_DIST += simple_correct.stderr.exp simple_correct.vgtest

check_PROGRAMS += simple_incorrect
EXTRA_DIST += simple_incorrect.vgtest simple_incorrect.stderr.exp

check_PROGRAMS += memcpy_correct
EXTRA_DIST += memcpy_correct.vgtest memcpy_correct.stderr.exp

check_PROGRAMS += bitop
EXTRA_DIST += bitop.vgtest bitop.stderr.exp

check_PROGRAMS += shift
EXTRA_DIST += shift.vgtest shift.stderr.exp

check_PROGRAMS += bitpack
EXTRA_DIST += bitpack.vgtest bitpack.stderr.exp

check_PROGRAMS += origins
EXTRA_DIST += origins.vgtest origins.stderr.exp

check_PROGRAMS += protection
EXTRA_DIST += protection.vgtest protection.stderr.exp

check_PROGRAMS += load_store
if VGCONF_ARCHS_INCLUDE_AMD64
load_store_CFLAGS = -mavx
endif
EXTRA_DIST += load_store.vgtest load_store.stderr.exp

check_PROGRAMS += calloc_is_any
EXTRA_DIST += calloc_is_any.vgtest calloc_is_any.stderr.exp

check_PROGRAMS += casted_byte
EXTRA_DIST += casted_byte.vgtest casted_byte.stderr.exp

check_PROGRAMS += openttd
EXTRA_DIST += openttd.vgtest openttd.stderr.exp
