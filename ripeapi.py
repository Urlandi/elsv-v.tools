# -*- coding: utf-8 -*-
"""
RIPE API https://stat.ripe.net/data/ wrapper
"""

import requests
import json

RIPE_API_URL = "https://stat.ripe.net/data/"
RIPE_SEARCH_URL = "https://rest.db.ripe.net/ripe/"


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
        whois_object = None

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
        neighbours = None

    return neighbours


def get_asset_members(asset):
    members = set()

    data = _ripe_search("as-set", asset)

    try:
        if data is None:
            members = None
        else:

            records = data["objects"]["object"][0]["attributes"]["attribute"]
            for record in records:
                record_type = record["name"]
                record_value = record["value"]

                if record_type == "members":
                    members.add(record_value)

    except KeyError or TypeError:
        members = None

    return members
