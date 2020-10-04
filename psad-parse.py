#!/usr/bin/env python3

import GeoIP
import re
import csv
from itertools import islice, groupby


def parse_psad_output(file):
    sections = groupby(file, lambda l: l.startswith("[+]"))

    # skip first section "[+] Version: psad v2.4.3"
    # start processing after  "[+] Top 50 signature matches:"
    signatures_section = islice(sections, 3, 4)
    # continue parsing after "[+] Top 25 attackers:"
    ip_section = islice(sections, 1, 2)
    # continue parsing after "[+] Top 20 scanned ports:"
    port_section = islice(sections, 1, 2)

    return { "ips": ip_section, "ports": port_section, "signatures": signatures_section }

def format_psad_output(section):

    for header, lines in signatures_section:
        # '"MISC Microsoft SQL Server..." (tcp),  Count: 107,
        # Unique sources: 93,  Sid: 100205'
        signature_list = [re.sub("\s+(\".*\")\s\(\w+\),\s+\w+:\s(\d+),\s+\w+\s\w+:\s(\d+),\s+\w+:\s(\d+)\n", r"\1,\2,\3,\4", item) for item in list(lines)]

    for header, lines in ip_section:
        # '62.171.132.224  DL: 3, Packets: 50, Sig count: 7'
        ip_list = [re.sub("\s+(.*\d)\s+DL:\s+\d+,\s+\w+:\s(\d+),\s+.*:\s+(\d+)\n", r"\1,\2,\3", item) for item in list(lines)]

    for header, lines in port_section:
        # 'tcp 50050 102 packets'
        port_list = [ re.sub("\s+(\w+)\s+(\d+)\s+(\d+)\s+.*\n", r"\1,\2,\3", item) for item in list(lines) ]

def write_csv():

    with open('signatures.csv', 'w') as out_file:
        out_file.write("Signature,Count,Sources,Sigid\n")
        for item in signature_list:
            out_file.write("%s\n" % item)

    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    with open('ips.csv', 'w') as out_file:
        out_file.write("IP address,Packets,Sig. count\n")
        for item in ip_list:
            csv_line = list(csv.reader([ item ]))[0]
            if len(csv_line) > 0:
                ip = csv_line[0]
                country_code = str(gi.country_code_by_addr(ip)).lower()
                out_file.write("{},{},{},{}\n".format(ip,country_code,csv_line[1],csv_line[2]))

    with open('ports.csv', 'w') as out_file:
        out_file.write("Protocol,Port,Packets\n")
        for item in port_list:
            out_file.write("%s\n" % item)



#gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

try:
    with open("analysis.out","r") as file:
        section = parse_psad_output(file)

except IOError:
    # do what you want if there is an error with the file opening
    print("Error")

#ip="24.24.24.24"
#country_code=gi.country_code_by_addr("8.8.8.8").lower()
#
#print("{},{}".format(ip, country_code))
