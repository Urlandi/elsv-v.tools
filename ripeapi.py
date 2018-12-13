# -*- coding: utf-8 -*-
"""
RIPE API https://stat.ripe.net/data/ wrapper
"""

import requests
import json
from functools import reduce

RIPE_API_URL = "https://stat.ripe.net/data/"
RIPE_SEARCH_URL = "https://rest.db.ripe.net/ripe/"

_cache_asset = dict()
_cache_peeringset = dict()


def _ripe_get(data_path, data_parameters):

    data = None

    try:
        data = requests.get(RIPE_API_URL + data_path + '/data.json', params=data_parameters).json()
    except requests.exceptions.RequestException:
        pass
    except json.decoder.JSONDecodeError:
        pass

    return data


def _ripe_search(data_path, data_name):

    data = None

    try:
        data = requests.get(RIPE_SEARCH_URL + data_path + '/' + data_name + ".json").json()
    except requests.exceptions.RequestException:
        pass
    except json.decoder.JSONDecodeError:
        pass

    return data


def get_whois_top(asn):

    whois_object = {}

    data = _ripe_get("whois", {"resource": asn})

    try:
        if data is None:
            whois_object = None
        else:
            for record in data["data"]["records"][0]:
                record_type = record["key"]
                record_value = record["value"]

                if record_type not in whois_object:
                    whois_object[record_type] = set()

                whois_object[record_type].add(record_value)

    except KeyError or TypeError:
        whois_object.clear()

    return whois_object


def get_neighbours(asn, power_min=10):

    neighbours = {"left": set(), "right": set(), "uncertain": set()}

    data = _ripe_get("asn-neighbours", {"resource": asn})

    try:
        if data is None:
            neighbours = None
        else:
            for neighbour in data["data"]["neighbours"]:
                power = neighbour["power"]
                peer_type = neighbour["type"]
                peer_asn = neighbour["asn"]

                if power_min < power:
                    neighbours[peer_type].add(peer_asn)

    except KeyError or TypeError:
        neighbours["left"].clear()
        neighbours["right"].clear()
        neighbours["uncertain"].clear()

    return neighbours


def get_asset_members(asset):

    members = set()

    if asset not in _cache_asset:

        data = _ripe_search("as-set", asset)

        try:
            if data is None:
                members = None
            else:
                records = data["objects"]["object"][0]["attributes"]["attribute"]

                def find_members(_members, record):
                    record_type = record["name"]
                    record_value = record["value"]

                    if record_type == "members":
                        return _members.union(set(record_value.split(',')))
                    else:
                        return _members

                members.update(reduce(find_members, records, set()))
                _cache_asset[asset] = members

        except KeyError or TypeError:
            members.clear()
    else:
        members = _cache_asset[asset]

    return members


def get_peeringset_expr(peeringset):
    peerings = set()

    if peeringset not in _cache_peeringset:
        data = _ripe_search("peering-set", peeringset)

        try:
            if data is None:
                peerings = None
            else:
                records = data["objects"]["object"][0]["attributes"]["attribute"]

                def find_peerings(_peerings, record):
                    record_type = record["name"]
                    record_value = record["value"]

                    if record_type == "peering" or record_type == "mp-peering":
                        return _peerings.union({record_value})
                    else:
                        return _peerings

                peerings.update(reduce(find_peerings, records, set()))
                _cache_peeringset[peeringset] = peerings

        except KeyError or TypeError:
            peerings.clear()
    else:
        peerings = _cache_peeringset[peeringset]

    return peerings
