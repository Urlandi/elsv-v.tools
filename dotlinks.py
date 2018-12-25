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

        for line in fileinput.input(input_flow_name):

            rline = line.strip()
            if not re.match(rpsl.RE_ASN, rline, re.IGNORECASE):
                continue

            whois_asn = ripeapi.get_whois_top(rline)

            if whois_asn is not None:

                def get_whois_asn_list(_whois_asn_list, record_type):
                    if _whois_asn_list is None:
                        return None
                    elif rpsl.RE_ASSET_ANY in _whois_asn_list:
                        return {rpsl.RE_ASSET_ANY}

                    import_types = ("import", "export", "default", "mp-import", "mp-export", "mp-default",)

                    if record_type in import_types:
                        pass

                    return _whois_asn_list.union()

                whois_asn_list = set(reduce(get_whois_asn_list, whois_asn, set()))
                print(whois_asn_list)
            else:
                continue

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

