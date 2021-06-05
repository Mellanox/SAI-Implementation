#!/usr/bin/env python

import sys
import errno
import os
from pprint import pprint
from python_sdk_api.sx_api import *
sys.path.insert(1, "/usr/bin")
from test_infra_common import *

# Converts SAI VR OID to SX VR ID
def get_sx_vrid(vrf_oid):
    vrid = socket.ntohl(vrf_oid) << 32 | (vrf_oid >> 32)
    # Hardcoded SAI_OBJECT_TYPE_VIRTUAL_ROUTER
    if ((vrid & 0xffffffff00000000) >> 32) != 0x03000000:
        print "OID type is not VIRTUAL_ROUTER"
        exit(1)
    vrid = vrid & ~0xff00000000000000
    return vrid

# See sx_api_router_uc_routes_dump_all.py
def get_all_routes_of_vrid(vrf_oid, version):
    vrid = get_sx_vrid(vrf_oid)
    rc, handle = sx_api_open(None)
    if (rc != SX_STATUS_SUCCESS):
        print "Failed to open api handle.\nPlease check that SDK is running."
        sys.exit(errno.EACCES)

    uc_route_arr = new_sx_uc_route_get_entry_t_arr(64)
    network_addr_p = new_sx_ip_prefix_t_p()
    network_addr = sx_ip_prefix_t()
    data_cnt_p = new_uint32_t_p()
    routes = []
    uint32_t_p_assign(data_cnt_p, 20)
    if version == SX_IP_VERSION_IPV4:
        network_addr.version = SX_IP_VERSION_IPV4
        network_addr.prefix.ipv4.addr.s_addr = 0
    else:
        network_addr.version = SX_IP_VERSION_IPV6
        for i in range(0, 15):
            uint8_t_arr_setitem(network_addr.prefix.ipv6.addr.__in6_u.__u6_addr8, i, 0)

    sx_ip_prefix_t_p_assign(network_addr_p, network_addr)
    rc = sx_api_router_uc_route_get(handle, SX_ACCESS_CMD_GET_FIRST, vrid, network_addr_p, None, uc_route_arr, data_cnt_p)
    data_cnt = uint32_t_p_value(data_cnt_p)
    if rc != 0:
        # check if router module initialize
        if rc == SX_STATUS_MODULE_UNINITIALIZED:
            print "####################################"
            print "# Router is not initialized "
            print "####################################"
            exit()
        return

    read_number = 0
    while (data_cnt == 20):
        for i in range(0, data_cnt):
            route = sx_uc_route_get_entry_t_arr_getitem(uc_route_arr, i)
            if route.network_addr.version == version:
                routes.append(ip_prefix_to_str(route.network_addr) + "/" + str(mask_len(route.network_addr)))

        sx_ip_prefix_t_p_assign(network_addr_p, route.network_addr)
        rc = sx_api_router_uc_route_get(handle, SX_ACCESS_CMD_GETNEXT, vrid, network_addr_p, None, uc_route_arr, data_cnt_p)
        if rc != 0:
            print "An error was found in sx_api_router_uc_route_get. rc: %d" % (rc)
            exit()
        data_cnt = uint32_t_p_value(data_cnt_p)
        read_number = read_number + 1

    for i in range(0, data_cnt):
        route = sx_uc_route_get_entry_t_arr_getitem(uc_route_arr, i)
        if route.network_addr.version == version:
            routes.append(ip_prefix_to_str(route.network_addr) + "/" + str(mask_len(route.network_addr)))

    sx_api_close(handle)

    return routes

# Helper function
def Diff(li1, li2):
    return (list(set(li1).difference(set(li2))))

# Entry point of the module
def CompareRoutes(vrid, sonic_routes):
    sdk_routes = get_all_routes_of_vrid(vrid, SX_IP_VERSION_IPV4)
    return Diff(sonic_routes, sdk_routes), Diff(sdk_routes, sonic_routes)
