# -*- coding: utf-8 -*-
"""
Very simple RPSL import/export records decoder for finding peers ASn

Notes from RFC2622

<peering> - <as-expression> [<router-expression-1>] [at <router-expression-2>] | <peering-set-name>

where <as-expression> is an expression over AS numbers and AS sets
using operators AND, OR, and EXCEPT
. . .
         The binary "EXCEPT" operator is the set subtraction
operator and has the same precedence as the operator AND (it is
semantically equivalent to "AND NOT" combination).  That is "(AS1
OR AS2) EXCEPT AS2" equals "AS1"

If a <peering-set-name> is used, the peerings are listed in the
corresponding peering-set object.  Note that the peering-set
objects can be recursive.
---------------------------------------------------------------------
<import-factor> ::= from|to <peering-1> [action <action-1>]
                    . . .
                    from|to <peering-N> [action <action-N>]
                    accept <filter>;

<import-term> ::=  <import-factor> |
                   LEFT-BRACE
                   <import-factor>
                   . . .
                   <import-factor>
                   RIGHT-BRACE

<import-expression> ::= <import-term>                           |
                        <import-term> EXCEPT <import-expression> |
                        <import-term> REFINE <import-expression>

import|export: [protocol <protocol1>] [into <protocol2>]
               <import-expression>
---------------------------------------------------------------------
default: to <peering> [action <action>] [networks <filter>]
"""

import re

from ripeapi import get_asset_members, get_whois_top


RE_ASN = "AS[0-9]{1,6}"
RE_ASSET_NAME = "AS-[A-Z0-9-_]*[A-Z0-9]"
RE_ASSET = "((" + RE_ASN + "|" + RE_ASSET_NAME + "):){0,}" + RE_ASSET_NAME
RE_ASSET_ANY = "AS-ANY"

RE_ASNEXPR = "((" + RE_ASN + "|" + RE_ASSET + ")(\s+(OR|AND|EXCEPT)\s+(" + RE_ASN + "|" + RE_ASSET + "))*)"

RE_ASN_FACTOR = "(from|to)\s+(" + RE_ASNEXPR + ")"

DEF_ASN_COUNT_MAX = 100
DEF_ASSET_DEEP_MAX = 5


def uncover_asset(asset_name, asn_count_max=DEF_ASN_COUNT_MAX, asset_deep_max=DEF_ASSET_DEEP_MAX, asset_deep=0):

    uncovered = set()

    asn_list = set()

    asset = get_asset_members(asset_name)

    if asset is None:
        return None

    for asn in asset:

        if asn in uncovered:
            continue

        uncovered.add(asn)

        if re.fullmatch(RE_ASSET_ANY, asn, re.IGNORECASE):
            continue

        if re.fullmatch(RE_ASSET, asn, re.IGNORECASE):
            if asset_deep_max < asset_deep:
                continue

            asn_inside = uncover_asset(asn, 
                                       asn_count_max, asset_deep_max, 
                                       asset_deep+1)

            if asn_inside is None:
                return None
            elif RE_ASSET_ANY in asn_inside:
                return asn_inside

            asn_list.update(asn_inside)

        elif re.fullmatch(RE_ASN, asn, re.IGNORECASE):
            asn_list.add(asn)
        else:
            return None

        asn_count = len(asn_list)

        if asn_count_max < asn_count:
            asn_list.clear()
            asn_list.add(RE_ASSET_ANY)
            break

    return asn_list


def uncover_peeringset (prngset_name):
    pass


REVAR_ASNEXPR = 1
def get_peerases(peering_rules):

    asn_list = set()

    adv_peering_list = re.findall(RE_ASN_FACTOR, peering_rules, re.IGNORECASE)

    for adv_peering in adv_peering_list:
        peering_asn = adv_peering[REVAR_ASNEXPR]
        if re.fullmatch(RE_ASN, peering_asn, re.IGNORECASE):
            asn_list.add(peering_asn)
        elif re.fullmatch(RE_ASSET, peering_asn, re.IGNORECASE):
            asn_list.update(uncover_asset(peering_asn))
        else:
            continue

    return asn_list


whois_51032 = get_whois_top("AS51032")
for export in whois_51032["export"]:
    print(get_peerases(export))
