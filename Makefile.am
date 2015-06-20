AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = autogen.sh csplugin-audit.conf csplugin-audit.spec

AM_CXXFLAGS = ${CXXFLAGS}

lib_LTLIBRARIES = libcsplugin-audit.la

libcsplugin_audit_la_SOURCES = csplugin-audit.cpp
libcsplugin_audit_la_CXXFLAGS = ${AM_CXXFLAGS}
