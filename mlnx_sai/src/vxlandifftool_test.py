#!/usr/bin/env python

import sys
from vxlandifftool import CompareRoutes

def TestCompareRoutes(vrf, sonic_routes, msai, msonic):
    actual_msai, actual_msonic = CompareRoutes(vrf, sonic_routes)
    match = (set(actual_msai) == set(msai)) and (set(actual_msonic) == set(msonic))
    return match

def OneVnetNoPeering(vrf):
    sys.exit(0 if TestCompareRoutes(vrf,
                ["192.168.0.0/24","192.168.2.0/24"],
                ["192.168.2.0/24"],
                ["192.168.1.0/24"]) else 1)


def OneVnetNoPeeringNegative(vrf):
    sys.exit(0 if TestCompareRoutes(vrf,
                ["192.168.0.0/24","192.168.2.0/24"],
                [],
                []) else 1)

def FullScaleTest(ii, vrf, tunnel_routes_num):
    routes = []
    msai = []
    msonic = []

    # RIF route
    routes.append("10.0.{}.0/24".format(ii))
    # Tunnel routes
    for i in range(ii, tunnel_routes_num, 32):
        routes.append("192.{}.{}.{}/32".format(168 + ((i / 0x10000) % 0x100), (i / 0x100) % 0x100, i % 0x100))
    # Local routes
    for i in range(ii, 72, 32):
        routes.append("193.184.{}.0/24".format(i % 256))

    msonic.append(routes[-1])
    del routes[-1]

    msai.append("24.75.41.00/32")
    routes.append(msai[0])

    if TestCompareRoutes(vrf, routes, msai, msonic) == False:
        sys.exit(1)

    del routes[0]
    sys.exit(0 if TestCompareRoutes(vrf, routes, msai, msonic) == False else 1)

