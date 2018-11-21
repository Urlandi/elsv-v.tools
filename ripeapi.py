# -*- coding: utf-8 -*-
"""
RIPE API https://stat.ripe.net/data/ wrapper
"""

import requests
import json

RIPE_API_URL = "https://stat.ripe.net/data/"


def _ripe_get(data_path, data_parameters):

    data = None

    try:
        data = requests.get(RIPE_API_URL + data_path + '/data.json', params=data_parameters).json()
    except requests.exceptions.RequestException:
        pass
    except json.decoder.JSONDecodeError:
        pass

    return data


def get_whois_top(asn):

    whois_object = {}

    data = _ripe_get("whois", {"resource": asn})

    if data is None:
        whois_object = None
    else:
        for record in data["data"]["records"][0]:
            record_type = record["key"]
            record_value = record["value"]

            if record_type not in whois_object:
                whois_object[record_type] = set()

            whois_object[record_type].add(record_value)

    return whois_object


def get_neighbours(asn, power_min=10):

    neighbours = {"left": set(), "right": set(), "uncertain": set()}

    data = _ripe_get("asn-neighbours", {"resource": asn})

    if data is None:
        neighbours = None
    else:
        for neighbour in data["data"]["neighbours"]:
            power = neighbour["power"]
            peer_type = neighbour["type"]
            peer_asn = neighbour["asn"]

            if power_min < power:
                neighbours[peer_type].add(peer_asn)

    return neighbours
