# Makefile.am -- Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) \
           -I$(srcdir)/../inc -I$(srcdir)/../inc/sai \
           -I$(APP_LIB_PATH)/include

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS = -g
endif

CFLAGS = @CFLAGS@ $(CFLAGS_SAI_INTERFACE_COMMON) $(DBGFLAGS)

lib_LTLIBRARIES = libsai.la

libsai_la_SOURCES = \
                       mlnx_sai_fdb.c \
                       mlnx_sai_interfacequery.c \
                       mlnx_sai_neighbor.c \
                       mlnx_sai_nexthop.c \
                       mlnx_sai_nexthopgroup.c \
                       mlnx_sai_port.c \
                       mlnx_sai_route.c \
                       mlnx_sai_router.c \
                       mlnx_sai_switch.c \
                       mlnx_sai_utils.c \
                       mlnx_sai_vlan.c \
                       mlnx_sai_rif.c \
					   mlnx_sai_host_interface.c
					   
libsai_la_LIBADD = \
                   -L$(APP_LIB_PATH)/lib -lsxapi

libsai_apiincludedir = $(includedir)/sai
libsai_apiinclude_HEADERS = \
	$(top_srcdir)/inc/sai/sainexthop.h \
	$(top_srcdir)/inc/sai/sainexthopgroup.h \
	$(top_srcdir)/inc/sai/sai.h \
	$(top_srcdir)/inc/sai/sairouter.h \
	$(top_srcdir)/inc/sai/saivlan.h \
	$(top_srcdir)/inc/sai/saineighbor.h \
	$(top_srcdir)/inc/sai/saifdb.h \
	$(top_srcdir)/inc/sai/saiport.h \
	$(top_srcdir)/inc/sai/saiqos.h \
	$(top_srcdir)/inc/sai/saiacl.h \
	$(top_srcdir)/inc/sai/saiswitch.h \
	$(top_srcdir)/inc/sai/saistatus.h \
	$(top_srcdir)/inc/sai/sairoute.h \
	$(top_srcdir)/inc/sai/saitypes.h \
	$(top_srcdir)/inc/sai/sairouterintf.h \
	$(top_srcdir)/inc/sai/saihostintf.h \
	\
	$(top_srcdir)/inc/sai_windows.h


libsai_api_version=$(shell grep LIBVERSION= $(top_srcdir)/sai_interface.ver | sed 's/LIBVERSION=//')
libsai_la_LDFLAGS = -version-info $(libsai_api_version)
