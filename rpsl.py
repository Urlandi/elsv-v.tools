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
from functools import reduce, partial

from ripeapi import get_asset_members, get_peeringset_expr
from utils import in_cache


RE_ASN = r"AS[0-9]{1,6}"
RE_ASSET_NAME = r"AS-[A-Z0-9-_]*[A-Z0-9]"
RE_ASSET = r"(((" + RE_ASN + r"|" + RE_ASSET_NAME + r"):)*" + RE_ASSET_NAME + r")"
RE_ASSET_ANY = r"AS-ANY"

RE_PEERINGSET_NAME = r"PRNG-[A-Z0-9-_]*[A-Z0-9]"
RE_PEERINGSET = r"(((" + RE_ASN + r"|" + RE_ASSET_NAME + r"):)*" + RE_PEERINGSET_NAME + r")"

RE_ASNEXPR = r"([\s(]*(" + RE_ASSET + "|" + RE_ASN + \
             r")([\s)]+(OR|AND|EXCEPT)[\s(]+(" + RE_ASSET + r"|" + RE_ASN + r"))*[\s)]*)"

RE_PEERING = r"(" + RE_PEERINGSET + r"|" + RE_ASNEXPR + r")"
RE_IMPORT_FACTOR = r"(from|to)\s+" + RE_PEERING

DEF_SET_DEEP_MAX = 5

_cache_uncovered = dict()


@in_cache(_cache_uncovered)
def uncover_asset(asset_name, asset_deep_max=DEF_SET_DEEP_MAX, asset_deep=0,
                  asset_uncovered: set=None, asset_init: set=None):

    uncovered = set()
    if asset_uncovered is not None:
        uncovered.update(asset_uncovered)

    asn_list = set()

    asset_defined = asset_init

    if re.fullmatch(RE_ASSET, asset_name, re.IGNORECASE) or asset_defined is not None:

        if asset_defined is None:
            asset_defined = get_asset_members(asset_name)

        if asset_defined is None:
            return None
        elif RE_ASSET_ANY in asset_defined:
            return {RE_ASSET_ANY}

        asn_list.update(set(filter(lambda asn_filter: re.fullmatch(RE_ASN, asn_filter, re.IGNORECASE),
                                   asset_defined)))

        if asset_deep < asset_deep_max:

            uncovered.add(asset_name)

            asset_list = set(filter(lambda asset_filter: re.fullmatch(RE_ASSET, asset_filter, re.IGNORECASE) and
                                    asset_filter not in uncovered,
                                    asset_defined))

            uncovered.update(asset_list)

            def lambda_uncover_asset(members: set, asset, **kwargs):
                if members is None:
                    return None
                elif RE_ASSET_ANY in members:
                    return {RE_ASSET_ANY}
                return members.union(uncover_asset(asset, **kwargs))

            reduce_uncover_asset = partial(lambda_uncover_asset,
                                           asset_deep_max=asset_deep_max,
                                           asset_deep=asset_deep+1,
                                           asset_uncovered=uncovered)

            asn_members = reduce(reduce_uncover_asset, asset_list, set())

            if asn_members is None:
                return None
            elif RE_ASSET_ANY in asn_list:
                return {RE_ASSET_ANY}

            asn_list.update(asn_members)

    return asn_list


def split_peering(peering):
    asn_list = set()

    if re.fullmatch(RE_ASN, peering, flags=re.IGNORECASE):
        return peering
    elif re.fullmatch(RE_ASSET, peering, flags=re.IGNORECASE):
        return uncover_asset(peering)

    asn_logic = re.sub(r"([\s(])EXCEPT([\s)])", r"\1AND NOT\2", peering, flags=re.IGNORECASE)

    asset_list = set(map(lambda findall_list: findall_list[0], re.findall(RE_ASSET, peering, re.IGNORECASE)))

    if 0 < len(asset_list):
        def replace_asset(_asn_logic, _asset_name):

            if _asn_logic is None:
                return None

            asset_asn_list = uncover_asset(_asset_name)

            if asset_asn_list is None:
                return None
            if 0 < len(asset_asn_list):
                asset_members = "(" + " OR ".join(asset_asn_list) + ")"
                return re.sub(_asset_name + r"([\s)]|$)", asset_members + r"\1", _asn_logic, count=1,
                              flags=re.IGNORECASE)

            return _asn_logic

        asn_logic = str(reduce(replace_asset, asset_list, asn_logic))

        if asn_logic is None:
            return None

    asn_expr = boolean.BooleanAlgebra()

    try:
        asnexpr_parsed = asn_expr.parse(asn_logic)
        asnexpr_list = asn_expr.dnf(asnexpr_parsed)

        def reduce_asnexpr(_asn_list, _expr):
            peer_asn_list = set()
            present_asn_expr = set(filter(lambda literal: type(literal) is not asn_expr.NOT, _expr.literals))
            present_asn = set(map(lambda asn: str(asn), present_asn_expr))
            if 0 < len(present_asn):
                if RE_ASSET_ANY in present_asn:
                    return RE_ASSET_ANY

                peer_asn_list = set(filter(lambda asn: re.match(RE_ASN, asn, re.IGNORECASE), present_asn))
            return _asn_list.union(peer_asn_list)

        if type(asnexpr_list) is asn_expr.OR:
            asn_list = reduce(reduce_asnexpr, asnexpr_list.args, asn_list)
        elif asnexpr_list == asn_expr.FALSE:
            asn_list.clear()
        elif asnexpr_list == asn_expr.TRUE:
            asn_list = {RE_ASSET_ANY}
        else:
            asn_list = reduce_asnexpr(asn_list, asnexpr_list)

    except boolean.ParseError:
        asn_list.clear()

    return asn_list


@in_cache(_cache_uncovered)
def uncover_peeringset(peeringset_name, peeringset_deep_max=DEF_SET_DEEP_MAX, peeringset_deep=0,
                       peeringset_uncovered: set=None):

    uncovered = set()
    if peeringset_uncovered is not None:
        uncovered.update(peeringset_uncovered)

    asn_list = set()

    if re.fullmatch(RE_PEERINGSET, peeringset_name, re.IGNORECASE):
        peerings_expr = get_peeringset_expr(peeringset_name)

        if peerings_expr is None:
            return None

        peerings_defined = set(map(lambda _peering: re.findall(RE_PEERING, _peering, re.IGNORECASE)[0][0],
                               peerings_expr))

        asnexpr_list = set(filter(lambda asnexpr_filter: re.fullmatch(RE_ASNEXPR, asnexpr_filter, re.IGNORECASE),
                           peerings_defined))

        def lambda_split_peering(_asnexpr_asn_list: set, asnexpr):
            if _asnexpr_asn_list is None:
                return None
            elif RE_ASSET_ANY in _asnexpr_asn_list:
                return {RE_ASSET_ANY}
            return _asnexpr_asn_list.union(split_peering(asnexpr))

        asnexpr_asn_list = reduce(lambda_split_peering, asnexpr_list, set())

        if asnexpr_asn_list is None:
            return None
        elif RE_ASSET_ANY in asnexpr_asn_list:
            return {RE_ASSET_ANY}

        asn_list.update(asnexpr_asn_list)

        if peeringset_deep < peeringset_deep_max:
            uncovered.add(peeringset_name)

            peeringset_list = set(filter(lambda peeringset_filter: re.fullmatch(RE_PEERINGSET, peeringset_filter,
                                                                                re.IGNORECASE) and
                                                                   peeringset_filter not in uncovered,
                                         peerings_defined))

            uncovered.update(peeringset_list)

            def lambda_uncover_peeringset(members: set, peeringset, **kwargs):
                if members is None:
                    return members
                elif RE_ASSET_ANY in members:
                    return {RE_ASSET_ANY}

                return members.union(uncover_peeringset(peeringset, **kwargs))

            reduce_uncover_peeringset = partial(lambda_uncover_peeringset,
                                                peeringset_deep_max=peeringset_deep_max,
                                                peeringset_deep=peeringset_deep+1,
                                                peeringset_uncovered=uncovered)

            peeringset_asn_list = reduce(reduce_uncover_peeringset, peeringset_list, set())

            if peeringset_asn_list is None:
                return None
            elif RE_ASSET_ANY in peeringset_asn_list:
                return {RE_ASSET_ANY}

            asn_list.update(peeringset_asn_list)

    return asn_list


def get_peerases(peering_rules):

    revar_asnexpr = 1
    asn_list = set()

    adv_peering_list = re.findall(RE_IMPORT_FACTOR, peering_rules, re.IGNORECASE)
    import_factor_list = set(map(lambda import_factor: import_factor[revar_asnexpr], adv_peering_list))

    peeringset_list = set(filter(lambda import_factor: re.match(RE_PEERINGSET, import_factor, re.IGNORECASE),
                                 import_factor_list))

    def get_peeringset_asn(_asn_list: set, peeringset):
        if _asn_list is None:
            return None
        elif RE_ASSET_ANY in _asn_list:
            return {RE_ASSET_ANY}

        return _asn_list.union(uncover_peeringset(peeringset))

    asn_list = reduce(get_peeringset_asn, peeringset_list, asn_list)

    if asn_list is None:
        return None
    elif RE_ASSET_ANY in asn_list:
        return RE_ASSET_ANY

    expression_list = import_factor_list.difference(peeringset_list)

    def get_asn(_asn_list: set, asnexpr):
        if _asn_list is None:
            return _asn_list
        elif RE_ASSET_ANY in _asn_list:
            return {RE_ASSET_ANY}

        return _asn_list.union(split_peering(asnexpr))

    asn_list = reduce(get_asn, expression_list, asn_list)

    return asn_list
