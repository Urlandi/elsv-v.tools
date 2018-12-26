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


def get_dot_links(asn_links):
    return


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
                            asn_links[asn]["import"].update(asn_list)
                        elif record_type == "mp-default":
                            asn_links[asn]["mp-import"].update(asn_list)
                        else:
                            asn_links[asn][record_type] = set()
                            asn_links[asn][record_type].update(asn_list)

                if err_id != SUCCESS:
                    break

                peers = ripeapi.get_neighbours(asn)
                if peers is not None:
                    asn_links[asn]["uplinks"] = peers["left"]
                    asn_links[asn]["downlinks"] = peers["right"]
                    asn_links[asn]["peers"] = peers["uncertain"]
                else:
                    err_id = ERR_GETASN
                    break

            else:
                err_id = ERR_GETASN
                break

        if err_id != SUCCESS:
            print ("Break because is fatal error then get links via RIPE API")
        else:
            dot_links = get_dot_links(asn_links)
            print_dot_links(dot_links, opt_all)

    except IOError:
        print ("Input read error in '{}'".format(input_flow_name))
        err_id = ERR_IO

    except getopt.GetoptError:
        print (USAGE_MSG)
        err_id = ERR_GETOPT

    finally:
        fileinput.close()

    return err_id


if __name__ == '__main__':
    exit(main())

