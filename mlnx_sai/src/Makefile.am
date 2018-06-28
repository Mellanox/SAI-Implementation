# Makefile.am -- Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) \
           -I$(srcdir)/../inc -I$(srcdir)/../inc/sai \
           -I$(APP_LIB_PATH)/include \
           -I$(XML2_LIB_PATH)/include/libxml2 \
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

lib_LTLIBRARIES = libsai.la

dist_data_DATA = sai_1710.xml \
                 sai_2700.xml \
                 sai_2740.xml \
                 sai_2410.xml \
                 sai_2420.xml \
                 sai_2100.xml \
                 sai_2010.xml
				 
libsai_la_DEPENDENCIES =

libsai_la_SOURCES = \
                       dbgdump/mlnx_sai_dbg_acl.c \
                       dbgdump/mlnx_sai_dbg_buffer.c \
                       dbgdump/mlnx_sai_dbg_hash.c \
                       dbgdump/mlnx_sai_dbg_hostintf.c \
                       dbgdump/mlnx_sai_dbg_policer.c \
                       dbgdump/mlnx_sai_dbg_port.c \
                       dbgdump/mlnx_sai_dbg_qosmaps.c \
                       dbgdump/mlnx_sai_dbg_queue.c \
                       dbgdump/mlnx_sai_dbg_samplepacket.c \
                       dbgdump/mlnx_sai_dbg_scheduler.c \
                       dbgdump/mlnx_sai_dbg_stp.c \
                       dbgdump/mlnx_sai_dbg_tunnel.c \
                       dbgdump/mlnx_sai_dbg_vlan.c \
                       dbgdump/mlnx_sai_dbg_wred.c \
                       dbgdump/mlnx_sai_dbg_bridge.c \
                       dbgdump/mlnx_sai_dbg_udf.c \
                       mlnx_sai_acl.c \
                       mlnx_sai_bridge.c \
                       mlnx_sai_buffer.c \
                       mlnx_sai_fdb.c \
                       mlnx_sai_hash.c \
                       mlnx_sai_host_interface.c \
                       mlnx_sai_interfacequery.c \
                       mlnx_sai_lag.c \
                       mlnx_sai_mirror.c \
                       mlnx_sai_neighbor.c \
                       mlnx_sai_nexthop.c \
                       mlnx_sai_nexthopgroup.c \
                       mlnx_sai_object.c \
                       mlnx_sai_policer.c \
                       mlnx_sai_port.c \
                       mlnx_sai_qosmaps.c \
                       mlnx_sai_queue.c \
                       mlnx_sai_rif.c \
                       mlnx_sai_route.c \
                       mlnx_sai_router.c \
                       mlnx_sai_samplepacket.c \
                       mlnx_sai_scheduler.c \
                       mlnx_sai_scheduler_group.c \
                       mlnx_sai_stp.c \
                       mlnx_sai_switch.c \
                       mlnx_sai_tunnel.c \
                       mlnx_sai_utils.c \
                       mlnx_sai_vlan.c \
                       mlnx_sai_wred.c \
                       mlnx_sai_udf.c \
                       meta/saimetadata.c \
                       meta/saimetadatautils.c \
                       meta/saiserialize.c

if XML2_ELDK5_LA_WA
SAI_LIBXML2_ADD = ${XML2_LIB_PATH}/lib/libxml2.so
else
SAI_LIBXML2_ADD = -lxml2
endif

libsai_la_LIBADD = \
                   -L$(APP_LIB_PATH)/lib -lsxapi -lsw_rm\
		   ${SAI_LIBXML2_ADD}

libsai_apiincludedir = $(includedir)/sai
libsai_apiinclude_HEADERS = \
        $(top_srcdir)/inc/sai/sai.h \
        $(top_srcdir)/inc/sai/saiacl.h \
        $(top_srcdir)/inc/sai/saibfd.h \
        $(top_srcdir)/inc/sai/saibridge.h \
        $(top_srcdir)/inc/sai/saibuffer.h \
        $(top_srcdir)/inc/sai/saidtel.h \
        $(top_srcdir)/inc/sai/saifdb.h \
        $(top_srcdir)/inc/sai/saihash.h \
        $(top_srcdir)/inc/sai/saihostif.h \
        $(top_srcdir)/inc/sai/saiipmc.h \
        $(top_srcdir)/inc/sai/saiipmcgroup.h \
        $(top_srcdir)/inc/sai/sail2mc.h \
        $(top_srcdir)/inc/sai/sail2mcgroup.h \
        $(top_srcdir)/inc/sai/sailag.h \
        $(top_srcdir)/inc/sai/saimcastfdb.h \
        $(top_srcdir)/inc/sai/saimirror.h \
        $(top_srcdir)/inc/sai/saimpls.h \
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
        $(top_srcdir)/inc/sai/saisegmentroute.h \
        $(top_srcdir)/inc/sai/saistatus.h \
        $(top_srcdir)/inc/sai/saistp.h \
        $(top_srcdir)/inc/sai/saiswitch.h \
        $(top_srcdir)/inc/sai/saitam.h \
        $(top_srcdir)/inc/sai/saitunnel.h \
        $(top_srcdir)/inc/sai/saitypes.h \
        $(top_srcdir)/inc/sai/saiuburst.h \
        $(top_srcdir)/inc/sai/saiudf.h \
        $(top_srcdir)/inc/sai/saivirtualrouter.h \
        $(top_srcdir)/inc/sai/saivlan.h \
        $(top_srcdir)/inc/sai/saiwred.h \
        \
        $(top_srcdir)/inc/sai_windows.h \
        $(top_srcdir)/inc/mlnx_sai.h


libsai_api_version=$(shell grep LIBVERSION= $(top_srcdir)/sai_interface.ver | sed 's/LIBVERSION=//')
libsai_la_LDFLAGS = -version-info $(libsai_api_version)
