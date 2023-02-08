# Makefile.am -- Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) \
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

lib_LTLIBRARIES = libfx_base.la libsx_fx_sdk.la libsai.la

dist_data_DATA = sai_1710.xml \
                 sai_2010.xml \
                 sai_2100.xml \
                 sai_2201.xml \
                 sai_2410.xml \
                 sai_2420.xml \
                 sai_2700.xml \
                 sai_2700split.xml \
                 sai_2700_8x50g_28x100g.xml \
                 sai_2700_56ports.xml \
                 sai_2740.xml \
                 sai_3420.xml \
                 sai_3700.xml \
                 sai_37001G.xml \
                 sai_3700_56ports.xml \
                 sai_3700_perport_ip_counter.xml \
                 sai_3800.xml \
                 sai_380050G.xml \
                 sai_3800_pb_hash.xml \
                 sai_3800_120ports.xml \
                 sai_4410.xml \
                 sai_4600.xml \
                 sai_4600C.xml \
                 sai_4600C_120ports.xml \
                 sai_4700.xml \
                 sai_4800.xml \
                 sai_4700_pld.xml \
                 sai_4700_pld_4.xml \
                 sai_4700_1G.xml \
                 sai_4700_100G.xml \
                 sai_4700_56ports.xml \
                 sai_5600.xml

libsai_la_DEPENDENCIES =

libsai_la_SOURCES = \
                       dbgdump/mlnx_sai_dbg_acl.c \
                       dbgdump/mlnx_sai_dbg_bridge.c \
                       dbgdump/mlnx_sai_dbg_bfd.c \
                       dbgdump/mlnx_sai_dbg_buffer.c \
                       dbgdump/mlnx_sai_dbg_debug_counter.c \
                       dbgdump/mlnx_sai_dbg_hash.c \
                       dbgdump/mlnx_sai_dbg_hostintf.c \
                       dbgdump/mlnx_sai_dbg_isolation_group.c \
                       dbgdump/mlnx_sai_dbg_mirror.c \
                       dbgdump/mlnx_sai_dbg_policer.c \
                       dbgdump/mlnx_sai_dbg_port.c \
                       dbgdump/mlnx_sai_dbg_qosmaps.c \
                       dbgdump/mlnx_sai_dbg_queue.c \
                       dbgdump/mlnx_sai_dbg_samplepacket.c \
                       dbgdump/mlnx_sai_dbg_scheduler.c \
                       dbgdump/mlnx_sai_dbg_stp.c \
                       dbgdump/mlnx_sai_dbg_tunnel.c \
                       dbgdump/mlnx_sai_dbg_udf.c \
                       dbgdump/mlnx_sai_dbg_utils.c \
                       dbgdump/mlnx_sai_dbg_vlan.c \
                       dbgdump/mlnx_sai_dbg_wred.c \
                       dbgdump/mlnx_sai_dbg_gp_reg.c \
                       dbgdump/mlnx_sai_dbg_nhg_nhgm.c \
                       mlnx_sai_acl.c \
                       mlnx_sai_bfd.c \
                       mlnx_sai_bridge.c \
                       mlnx_sai_buffer.c \
                       mlnx_sai_counter.c \
                       mlnx_sai_debug_counter.c \
                       mlnx_sai_fdb.c \
                       mlnx_sai_hash.c \
                       mlnx_sai_host_interface.c \
                       mlnx_sai_interfacequery.c \
                       mlnx_sai_interfacequery_eth.c \
                       mlnx_sai_isolation_group.c \
                       mlnx_sai_lag.c \
                       mlnx_sai_l2mcgroup.c \
                       mlnx_sai_mirror.c \
                       mlnx_sai_neighbor.c \
                       mlnx_sai_nexthop.c \
                       mlnx_sai_nexthopgroup.c \
                       mlnx_sai_object.c \
                       mlnx_sai_object_eth.c \
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
                       mlnx_sai_udf.c \
                       mlnx_sai_utils.c \
                       mlnx_sai_utils_eth.c \
                       mlnx_sai_vlan.c \
                       mlnx_sai_wred.c \
                       mlnx_sai_issu_storage.c \
                       meta/saimetadata.c \
                       meta/saimetadatautils.c \
                       meta/saiserialize.c

libfx_base_la_SOURCES = \
                       fx_base_api.c \
                       fx_base_acl_validation.c \
                       fx_base_action_init.c \
                       fx_base_bitmap.c \
                       fx_base_range_match.c \
                       fx_base_user_init.c \
                       fx_parser.c

libfx_base_la_CFLAGS = --std=gnu99 -Wno-sign-compare -Wno-vla -Wno-missing-field-initializers

CFLAGS += $(CFLAGS_ASAN)
LDFLAGS += $(LDFLAGS_ASAN)

libsx_fx_sdk_la_CFLAGS = --std=gnu99 -Wno-sign-compare -Wno-vla -Wno-missing-field-initializers
libsx_fx_sdk_la_SOURCES = sdk/sx_api_bmtor.c
libsx_fx_sdk_la_LIBADD = -L$(APP_LIB_PATH) -ldl libfx_base.la

if XML2_ELDK5_LA_WA
SAI_LIBXML2_ADD = ${XML2_LIB_PATH}/lib/libxml2.so
else
SAI_LIBXML2_ADD = -lxml2
endif

libsai_la_LIBADD = \
                   -L$(APP_LIB_PATH)/lib -lsxapi -lsw_rm -lnl-genl-3\
                   ${SAI_LIBXML2_ADD} libfx_base.la libsx_fx_sdk.la

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
        $(top_srcdir)/inc/sdk/sx_bmtor.h

libsai_api_version=$(shell grep LIBVERSION= $(top_srcdir)/sai_interface.ver | sed 's/LIBVERSION=//')
libsai_la_LDFLAGS = -version-info $(libsai_api_version)
