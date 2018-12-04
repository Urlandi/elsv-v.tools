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
import boolean

from ripeapi import get_asset_members, get_peeringset_expr


RE_ASN = r"AS[0-9]{1,6}"
RE_ASSET_NAME = r"AS-[A-Z0-9-_]*[A-Z0-9]"
RE_ASSET = r"((" + RE_ASN + r"|" + RE_ASSET_NAME + r"):)*" + RE_ASSET_NAME
RE_ASSET_ANY = r"AS-ANY"

RE_PEERINGSET_NAME = r"PRNG-[A-Z0-9-_]*[A-Z0-9]"
RE_PEERINGSET = "((" + RE_ASN + "|" + RE_ASSET_NAME + "):)*" + RE_PEERINGSET_NAME

RE_ASNEXPR = r"([\s(]*(" + RE_ASSET + "|" + RE_ASN + \
             r")([\s()]+(OR|AND|EXCEPT)[\s(]+(" + RE_ASSET + r"|" + RE_ASN + r"))*[\s)]*)"

RE_PEERING = r"(" + RE_PEERINGSET + r"|" + RE_ASNEXPR + r")"
RE_IMPORT_FACTOR = r"(from|to)\s+" + RE_PEERING

DEF_SET_COUNT_MAX = 1000
DEF_SET_DEEP_MAX = 5


def uncover_asset(asset_name, asn_count_max=DEF_SET_COUNT_MAX, asset_deep_max=DEF_SET_DEEP_MAX, asset_deep=0):

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


def split_peering(peering):
    peering_list = set()

    asn_logic = re.sub(r"([\s(])EXCEPT([\s)])", r"\1AND NOT\2", peering, flags=re.IGNORECASE)

    asnexpr = boolean.BooleanAlgebra()

    try:
        asnexpr_parsed = asnexpr.parse(asn_logic)
        asnexpr_list = asnexpr.dnf(asnexpr_parsed)

    except boolean.ParseError as e:
        print(e)
        peering_list.clear()

    return peering_list


def uncover_peering(peering_rule,
                    peering_count_max=DEF_SET_COUNT_MAX, peering_deep_max=DEF_SET_DEEP_MAX, peering_deep=0):
    uncovered = set()

    peering_asn_list = set()

    if re.fullmatch(RE_PEERINGSET, peering_rule, re.IGNORECASE):
        peeringset = get_peeringset_expr(peering_rule)
    else:
        peeringset = (peering_rule,)

    if peeringset is None:
        return None

    for peering in peeringset:
        peer_list = split_peering(peering)

        for peering_asn in peer_list:

            if peering_asn in uncovered:
                continue

            uncovered.add(peering_asn)

            peer = set()

            if re.fullmatch(RE_PEERINGSET, peering_asn, re.IGNORECASE):
                if peering_deep_max < peering_deep:
                    continue

                peeringset_inside = uncover_peering(peering_asn,
                                                    peering_count_max, peering_deep_max,
                                                    peering_deep + 1)

                if peeringset_inside is None:
                    return None
                elif RE_ASSET_ANY in peeringset_inside:
                    return peeringset_inside

                peer = peeringset_inside

            elif re.fullmatch(RE_ASSET, peering_asn, re.IGNORECASE):
                peer = uncover_asset(peering_asn)
            elif re.fullmatch(RE_ASN, peering_asn, re.IGNORECASE):
                peer.add(peering_asn)

            else:
                return None

            if peer is None:
                return None
            peering_asn_list.update(peer)

    return peering_asn_list


REVAR_ASNEXPR = 1


def get_peerases(peering_rules):

    asn_list = set()
    peeringset_list = set()

    adv_peering_list = re.findall(RE_IMPORT_FACTOR, peering_rules, re.IGNORECASE)

    for adv_peering in adv_peering_list:
        peering_rule = adv_peering[REVAR_ASNEXPR]

        if peering_rule in peeringset_list:
            continue
        if re.fullmatch(RE_PEERINGSET, peering_rule, re.IGNORECASE):
            peeringset_list.add(peering_rule)

        peer = uncover_peering(peering_rule)
        if peer is None:
            return None
        asn_list.update(peer)

    return asn_list


print(get_peerases("from AS13646 EXCEPT (AS-SET)"))
