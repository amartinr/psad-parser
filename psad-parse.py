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

    return { 'ips': ip_section, 'ports': port_section, 'signatures': signatures_section }

def format_psad_output(section):
    for header, lines in section['signatures']:
        # '"MISC Microsoft SQL Server..." (tcp),  Count: 107,
        # Unique sources: 93,  Sid: 100205'
        signature_list = [re.sub("\s+(\".*\")\s\(\w+\),\s+\w+:\s(\d+),\s+\w+\s\w+:\s(\d+),\s+\w+:\s(\d+)\n", r"\1,\2,\3,\4", item) for item in list(lines)]
    for header, lines in section['ips']:
        # '62.171.132.224  DL: 3, Packets: 50, Sig count: 7'
        ip_list = [re.sub("\s+(.*\d)\s+DL:\s+\d+,\s+\w+:\s(\d+),\s+.*:\s+(\d+)\n", r"\1,\2,\3", item) for item in list(lines)]
    for header, lines in section['ports']:
        # 'tcp 50050 102 packets'
        port_list = [ re.sub("\s+(\w+)\s+(\d+)\s+(\d+)\s+.*\n", r"\1,\2,\3", item) for item in list(lines) ]

    return { 'ips': ip_list, 'ports': port_list, 'signatures': signature_list }

def add_ip_country(ips):
    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

    ips_with_country_code = []

    for item in ips:
        csv_line = list(csv.reader([item]))[0]
        if len(csv_line) > 0:
            ip = csv_line[0]
            country_code = str(gi.country_code_by_addr(ip)).lower()
            new_ip_line = "{},{},{},{}".format(ip,
                                              country_code,
                                              csv_line[1],csv_line[2])
            ips_with_country_code.append(new_ip_line)
    return ips_with_country_code

#            out_file.write("{},{},{},{}\n".format(ip,
#                                                  country_code,
#                                                  csv_line[1],csv_line[2])


def write_csv(data, header, filename):
    with open(filename, 'w') as out_file:
        out_file.write(header)
        for line in data:
            out_file.write("%s\n" % line)


def main():
    try:
        with open("analysis.out","r") as file:
            raw_section = parse_psad_output(file)
            formatted_section = format_psad_output(raw_section)
            formatted_section['ips'] = add_ip_country(formatted_section['ips'])
            write_csv(formatted_section['ips'],
                      'IP address,Country,Packets,Sig. count\n',
                      'ips.csv')
            write_csv(formatted_section['signatures'],
                      'Signature,Count,Sources,Sigid\n',
                      'signatures.csv')
            write_csv(formatted_section['ports'],
                      'Protocol,Port,Packets\n',
                      'ports.csv')
    except IOError:
        # do what you want if there is an error with the file opening
        print("Error: file analysis.out not found")


if __name__ == "__main__":
    main()
