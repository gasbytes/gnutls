# Copyright (C) 2002-2008 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the specification of how gnulib-tool is used.
# It acts as a cache: It is written and read by gnulib-tool.
# In projects using CVS, this file is meant to be stored in CVS,
# like the configure.ac and various Makefile.am files.


# Specification in the form of a command-line invocation:
#   gnulib-tool --import --dir=. --local-dir=lgl/override --lib=liblgnu --source-base=lgl --m4-base=lgl/m4 --doc-base=doc --aux-dir=build-aux --lgpl=2 --libtool --macro-prefix=lgl --no-vc-files crypto/gc crypto/gc-arcfour crypto/gc-arctwo crypto/gc-camellia crypto/gc-des crypto/gc-hmac-md5 crypto/gc-md2 crypto/gc-md4 crypto/gc-md5 crypto/gc-pbkdf2-sha1 crypto/gc-random crypto/gc-rijndael crypto/gc-sha1 fseeko func gettext memmem-simple memmove minmax read-file snprintf socklen stdint strverscmp sys_socket sys_stat time_r unistd vasprintf

# Specification in the form of a few gnulib-tool.m4 macro invocations:
gl_LOCAL_DIR([lgl/override])
gl_MODULES([crypto/gc crypto/gc-arcfour crypto/gc-arctwo crypto/gc-camellia crypto/gc-des crypto/gc-hmac-md5 crypto/gc-md2 crypto/gc-md4 crypto/gc-md5 crypto/gc-pbkdf2-sha1 crypto/gc-random crypto/gc-rijndael crypto/gc-sha1 fseeko func gettext memmem-simple memmove minmax read-file snprintf socklen stdint strverscmp sys_socket sys_stat time_r unistd vasprintf])
gl_AVOID([])
gl_SOURCE_BASE([lgl])
gl_M4_BASE([lgl/m4])
gl_PO_BASE([])
gl_DOC_BASE([doc])
gl_TESTS_BASE([tests])
gl_LIB([liblgnu])
gl_LGPL([2])
gl_MAKEFILE_NAME([])
gl_LIBTOOL
gl_MACRO_PREFIX([lgl])
gl_PO_DOMAIN([])
gl_VC_FILES([false])
