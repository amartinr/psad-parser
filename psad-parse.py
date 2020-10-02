#!/usr/bin/env python3

import GeoIP
import re
from itertools import islice, groupby


def parse(f):
    sections = groupby(f, lambda l: l.startswith("[+]"))

    # skip first section "[+] Version: psad v2.4.3"
    # start processing after  "[+] Top 50 signature matches:"
    signatures_section = islice(sections, 3, 4)
    # continue parsing after "[+] Top 25 attackers:"
    ip_section = islice(sections, 1, 2)
    # continue parsing after "[+] Top 20 scanned ports:"
    port_section = islice(sections, 1, 2)

    for header, lines in signatures_section:
        # '"MISC Microsoft SQL Server communication attempt" (tcp),  Count: 107,
        # Unique sources: 93,  Sid: 100205'
        signature_list = [re.sub("\s+\"(.*)\"\s\(\w+\),\s+\w+:\s(\d+),\s+\w+\s\w+:\s(\d+),\s+\w+:\s(\d+)\n", r"\1,\2,\3,\4", item) for item in list(lines)]

    for header, lines in ip_section:
        # '62.171.132.224  DL: 3, Packets: 50, Sig count: 7'
        ip_list = [re.sub("\s+(.*\d)\s+DL:\s+(\d+),\s+\w+:\s(\d+),\s+.*:\s+(\d+)\n", r"\1,\2,\3,\4", item) for item in list(lines)]

    for header, lines in port_section:
        # 'tcp 50050 102 packets'
        port_list = [ re.sub("\s+(\w+)\s+(\d+)\s+(\d+)\s+.*\n", r"\1,\2,\3", item) for item in list(lines) ]

    print(signature_list)
    print(ip_list)
    print(port_list)


gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

try:
    with open("analysis.out","r") as f:
        parse(f)
except IOError:
    # do what you want if there is an error with the file opening
    print("Error")

#ip="24.24.24.24"
#country_code=gi.country_code_by_addr("8.8.8.8").lower()
#
#print("{},{}".format(ip, country_code))
