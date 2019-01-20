# -*- coding: utf-8 -*-
"""
Generate DOT format list of AS links from RIPE data
"""

import sys
import fileinput
import getopt
import re
from functools import reduce
# import logging

import rpsl
import ripeapi

USAGE_MSG = """
Make DOT format list of AS links 
using data from RIPE stats and DB
(c) elsv-v.ru 2018

Usage:
    dotlinks.py [-a] <file>|STDIN

Options:
    -a|--all  - Generate all links even with ASn not presents in input

Input file (or STDIN) format is an ASn in each line
"""

SUCCESS = 0
ERR_IO = 2
ERR_GETOPT = 3
ERR_GETASN = 4


def get_whois_asn_list(import_records):

    def lambda_get_peerases(asn_list, record):
        if asn_list is None:
            return None
        elif rpsl.RE_ASSET_ANY in asn_list:
            return {rpsl.RE_ASSET_ANY}

        return asn_list.union(rpsl.get_peerases(record))

    return reduce(lambda_get_peerases, import_records, set())


_rtype_uplinks = "uplinks"
_rtype_downlinks = "downlinks"
_rtype_peers = "peers"
_rtype_import = "import"
_rtype_export = "export"
_rtype_mpimport = "mp-import"
_rtype_mpexport = "mp-export"

_ltype_uplinksrir = "uplinks_rir"
_ltype_downlinksrir = "downlins_rir"
_ltype_peersrir = "peers_rir"
_ltype_uplinks = "uplinks"
_ltype_downlinks = "downlinks"
_ltype_peers = "peers"
_ltype_uplinksext = "uplinks_ext"
_ltype_downlinksext = "downlinks_ext"
_ltype_peersext = "peers_ext"


def get_dot_links(asn_links):

    asn_list = set(asn_links.keys())
    asn_doted = set()

    dot_links = {_ltype_uplinksrir: set(), _ltype_downlinksrir: set(), _ltype_peersrir: set(),
                 _ltype_uplinks: set(), _ltype_downlinks: set(), _ltype_peers: set(),
                 _ltype_uplinksext: set(), _ltype_downlinksext: set(), _ltype_peersext: set()}

    for asn in asn_list:
        asn_doted.add(asn)
        peer_asn_list = asn_list.difference(asn_doted)

        asn_peers = set()
        for asnpeer in peer_asn_list:
            is_peering = asnpeer in (asn_links[asn][_rtype_import] | asn_links[asn][_rtype_export] |
                                     asn_links[asn][_rtype_mpimport] | asn_links[asn][_rtype_mpexport] |
                                     asn_links[asn][_rtype_downlinks] | asn_links[asn][_rtype_uplinks] |
                                     asn_links[asn][_rtype_peers]) or \
                         asn in (asn_links[asnpeer][_rtype_import] | asn_links[asnpeer][_rtype_export] |
                                 asn_links[asnpeer][_rtype_mpimport] | asn_links[asnpeer][_rtype_mpexport] |
                                 asn_links[asnpeer][_rtype_downlinks] | asn_links[asnpeer][_rtype_uplinks] |
                                 asn_links[asnpeer][_rtype_peers])
            if is_peering:
                asn_peers.add(asnpeer)
            else:
                continue

            is_rir_mutual = (asnpeer in asn_links[asn][_rtype_import] and
                             asn in asn_links[asnpeer][_rtype_export] and
                             asnpeer in asn_links[asn][_rtype_mpimport] and
                             asn in asn_links[asnpeer][_rtype_mpexport]) or \
                            (asnpeer in asn_links[asn][_rtype_import] and
                             asn in asn_links[asnpeer][_rtype_export] and
                             asnpeer not in asn_links[asn][_rtype_mpimport] and
                             asn not in asn_links[asnpeer][_rtype_mpexport]) or \
                            (asnpeer not in asn_links[asn][_rtype_import] and
                             asn not in asn_links[asnpeer][_rtype_export] and
                             asnpeer in asn_links[asn][_rtype_mpimport] and
                             asn in asn_links[asnpeer][_rtype_mpexport])

            is_uplink = asn in asn_links[asnpeer][_rtype_downlinks] and asnpeer in asn_links[asn][_rtype_uplinks]
            is_downlink = asn in asn_links[asnpeer][_rtype_uplinks] and asnpeer in asn_links[asn][_rtype_downlinks]
            # is_peer = asn in asn_links[asnpeer][_rtype_peers] and asnpeer in asn_links[asn][_rtype_peers]

            if is_uplink and is_rir_mutual:
                dot_links[_ltype_uplinksrir].add((asn, asnpeer,))
            elif is_downlink and is_rir_mutual:
                dot_links[_ltype_downlinksrir].add((asnpeer, asn,))
            elif is_rir_mutual:
                dot_links[_ltype_peersrir].add(sorted((asnpeer, asn,)))
            elif is_uplink:
                dot_links[_ltype_uplinks].add((asn, asnpeer,))
            elif is_downlink:
                dot_links[_ltype_downlinks].add((asnpeer, asn,))
            else:
                dot_links[_ltype_peers].add(sorted((asnpeer, asn,)))

    return dot_links


def print_dot_links(dot_links, opt_all):
    return


def main(opt_all=False):

    opt_list = "a"
    lopt_list = ("all",)

    input_flow_name = "-"

    err_id = SUCCESS

    try:
        opts, args = getopt.getopt(sys.argv[1:], opt_list, lopt_list)

        for opt, arg in opts:
            if opt in ("-a", "--all"):
                opt_all = True

        if len(args) > 0:
            input_flow_name = args[-1]

        asn_links = dict()

        for line in fileinput.input(input_flow_name):

            asn = line.strip()
            if not re.match(rpsl.RE_ASN, asn, re.IGNORECASE):
                continue

            whois_asn = ripeapi.get_whois_top(asn)

            if whois_asn is not None:
                asn_links[asn] = dict()

                for record_type in ("import", "export", "default", "mp-import", "mp-export", "mp-default",):

                    if record_type in whois_asn:
                        asn_list = get_whois_asn_list(whois_asn[record_type])
                    else:
                        asn_list = set()

                    if asn_list is None:
                        err_id = ERR_GETASN
                        break
                    else:
                        if record_type == "default":
                            asn_links[asn][_rtype_export].update(asn_list)
                        elif record_type == "mp-default":
                            asn_links[asn][_rtype_mpexport].update(asn_list)
                        else:
                            asn_links[asn][record_type] = set()
                            asn_links[asn][record_type].update(asn_list)

                if err_id != SUCCESS:
                    break

                peers = ripeapi.get_neighbours(asn)
                if peers is not None:

                    def lambda_asn_prefix(asnum):
                        return "AS{}".format(asnum)

                    asn_links[asn][_rtype_uplinks] = set(map(lambda_asn_prefix, peers["left"]))
                    asn_links[asn][_rtype_downlinks] = set(map(lambda_asn_prefix, peers["right"]))
                    asn_links[asn][_rtype_peers] = set(map(lambda_asn_prefix, peers["uncertain"]))
                else:
                    err_id = ERR_GETASN
                    break

            else:
                err_id = ERR_GETASN
                break

        if err_id != SUCCESS:
            print("Break because is fatal error when get links via RIPE API")
        else:
            dot_links = get_dot_links(asn_links)
            print_dot_links(dot_links, opt_all)

    except IOError:
        print("Input read error in '{}'".format(input_flow_name))
        err_id = ERR_IO

    except getopt.GetoptError:
        print(USAGE_MSG)
        err_id = ERR_GETOPT

    finally:
        fileinput.close()

    return err_id


if __name__ == '__main__':
    exit(main())
