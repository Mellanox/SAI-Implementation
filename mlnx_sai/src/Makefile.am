# Makefile.am -- Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) \
           -I$(srcdir)/../inc -I$(srcdir)/../inc/sai -I$(srcdir)/../inc/experimental -I$(srcdir)/../inc/sdk \
           -I$(APP_LIB_PATH)/include \
           -I$(XML2_LIB_PATH)/include/libxml2 \
           -I$(XML2_LIB_PATH)/include/libnl3 \
		   -I$(srcdir)/meta

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS = -g
endif

CFLAGS = @CFLAGS@ $(CFLAGS_SAI_INTERFACE_COMMON) $(DBGFLAGS)

if CONFIG_SYSLOG
CFLAGS += -DCONFIG_SYSLOG
endif

pythonlibdir=$(APP_PY_PATH)
pythonlib_SCRIPTS= \
                vxlandifftool.py \
                vxlandifftool_test.py

lib_LTLIBRARIES = libsai.la

dist_data_DATA = sai_7800.xml \
                 sai_8700.xml \
                 sai_9700.xml

libsai_la_DEPENDENCIES =
libsai_la_SOURCES = \
                       dbgdump/mlnx_sai_dbg_port.c \
                       dbgdump/mlnx_sai_dbg_utils.c \
                       mlnx_sai_interfacequery.c \
                       mlnx_sai_interfacequery_ib.c \
                       mlnx_sai_object.c \
                       mlnx_sai_object_ib.c \
                       mlnx_sai_switch_common.c \
                       mlnx_sai_utils.c \
                       mlnx_sai_utils_ib.c \
                       meta/saimetadata.c \
                       meta/saimetadatautils.c \
                       meta/saiserialize.c \
                       mlnx_sai_switch_ib.c \
                       mlnx_sai_port_ib.c \
                       mlnx_sai_prm_api.c \
                       mlnx_sai_swid_api.c

if XML2_ELDK5_LA_WA
SAI_LIBXML2_ADD = ${XML2_LIB_PATH}/lib/libxml2.so
else
SAI_LIBXML2_ADD = -lxml2
endif

libsai_la_LIBADD = \
                   -L$(APP_LIB_PATH)/lib -lsxapi -lsw_rm -lnl-genl-3\
                   ${SAI_LIBXML2_ADD}

libsai_apiincludedir = $(includedir)/sai
libsai_apiinclude_HEADERS = \
        $(top_srcdir)/inc/sai/sai.h \
        $(top_srcdir)/inc/sai/saiacl.h \
        $(top_srcdir)/inc/sai/saibfd.h \
        $(top_srcdir)/inc/sai/saibridge.h \
        $(top_srcdir)/inc/sai/saibuffer.h \
        $(top_srcdir)/inc/sai/saicounter.h \
        $(top_srcdir)/inc/sai/saidebugcounter.h \
        $(top_srcdir)/inc/sai/saidtel.h \
        $(top_srcdir)/inc/sai/saifdb.h \
        $(top_srcdir)/inc/sai/saihash.h \
        $(top_srcdir)/inc/sai/saihostif.h \
        $(top_srcdir)/inc/sai/saiipmc.h \
        $(top_srcdir)/inc/sai/saiipmcgroup.h \
        $(top_srcdir)/inc/sai/saiipsec.h \
        $(top_srcdir)/inc/sai/saiisolationgroup.h \
        $(top_srcdir)/inc/sai/sail2mc.h \
        $(top_srcdir)/inc/sai/sail2mcgroup.h \
        $(top_srcdir)/inc/sai/sailag.h \
        $(top_srcdir)/inc/sai/saimacsec.h \
        $(top_srcdir)/inc/sai/saimcastfdb.h \
        $(top_srcdir)/inc/sai/saimirror.h \
        $(top_srcdir)/inc/sai/saimpls.h \
        $(top_srcdir)/inc/sai/saimymac.h \
        $(top_srcdir)/inc/sai/sainat.h \
        $(top_srcdir)/inc/sai/saineighbor.h \
        $(top_srcdir)/inc/sai/sainexthop.h \
        $(top_srcdir)/inc/sai/sainexthopgroup.h \
        $(top_srcdir)/inc/sai/saiobject.h \
        $(top_srcdir)/inc/sai/saipolicer.h \
        $(top_srcdir)/inc/sai/saiport.h \
        $(top_srcdir)/inc/sai/saiqosmap.h \
        $(top_srcdir)/inc/sai/saiqueue.h \
        $(top_srcdir)/inc/sai/sairoute.h \
        $(top_srcdir)/inc/sai/sairouterinterface.h \
        $(top_srcdir)/inc/sai/sairpfgroup.h \
        $(top_srcdir)/inc/sai/saisamplepacket.h \
        $(top_srcdir)/inc/sai/saischeduler.h \
        $(top_srcdir)/inc/sai/saischedulergroup.h \
        $(top_srcdir)/inc/sai/saisrv6.h \
        $(top_srcdir)/inc/sai/saistatus.h \
        $(top_srcdir)/inc/sai/saistp.h \
        $(top_srcdir)/inc/sai/saiswitch.h \
        $(top_srcdir)/inc/sai/saisystemport.h \
        $(top_srcdir)/inc/sai/saitam.h \
        $(top_srcdir)/inc/sai/saitunnel.h \
        $(top_srcdir)/inc/sai/saitypes.h \
        $(top_srcdir)/inc/sai/saiudf.h \
        $(top_srcdir)/inc/sai/saiversion.h \
        $(top_srcdir)/inc/sai/saivirtualrouter.h \
        $(top_srcdir)/inc/sai/saivlan.h \
        $(top_srcdir)/inc/sai/saiwred.h \
		\
        $(top_srcdir)/inc/experimental/saiexperimentalbmtor.h \
        $(top_srcdir)/inc/experimental/saiextensions.h \
        $(top_srcdir)/inc/experimental/saiswitchextensions.h \
        $(top_srcdir)/inc/experimental/saitypesextensions.h \
        \
        $(top_srcdir)/inc/sai_windows.h \
        $(top_srcdir)/inc/mlnx_sai.h \
        $(top_builddir)/config.h \
        \
        $(top_srcdir)/inc/flextrum_types.h \
        $(top_srcdir)/inc/fx_base_api.h \
        $(top_srcdir)/inc/fx_base_range_match.h \
        $(top_srcdir)/inc/mlnx_flex_bitmap.h \
        $(top_srcdir)/inc/mlnx_flex_types.h \
        $(top_srcdir)/inc/sharedlib.h \
        \
        $(top_srcdir)/inc/sdk/sx_api_bmtor.h \
        $(top_srcdir)/inc/sdk/sx_bmtor.h \
        $(top_srcdir)/inc/mlnx_sai_prm_api.h

libsai_api_version=$(shell grep LIBVERSION= $(top_srcdir)/sai_interface.ver | sed 's/LIBVERSION=//')
libsai_la_LDFLAGS = -version-info $(libsai_api_version)
