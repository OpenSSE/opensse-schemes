#!/usr/bin/env python3

# from optparse import OptionParser
import argparse
import re
import json
import csv

import matplotlib.pyplot as plt


def parse_file(f):
    lines = f.readlines()

    # We suppose that the benchark log has a spdlog format ending with %v
    pattern = r"(\{.*\})$"
    prog = re.compile(pattern)

    lats = []
    rows = []

    for l in lines:
        line = l.strip('\n\t')
        m = prog.search(line)

        json_data = json.loads(m.group(0))

        items = json_data['items']
        time = float(json_data['time'])
        time_per_item = float(json_data['time/item'])

        csv_line = [time, items, time_per_item]
        lats.append(time)
        rows.append(csv_line)
    return (rows, lats)


parser = argparse.ArgumentParser(
    description='Process a Diana server benchmark file.')

parser.add_argument("-i", "--input", dest="in_file", nargs=1,
                    required=True, help="Input file", type=argparse.FileType('r'))
parser.add_argument("-o", "--out", dest="out_file",
                    required=True, metavar='path',
                    help='output CSV file')

# parser.add_argument("-o", "--out", dest="out_file", nargs=1,
# required=True, help="Output file", type=argparse.FileType('w'))
args = parser.parse_args()

print("Parsing {0}, and outputting in {1}".format(
    args.in_file[0].name, args.out_file))
(rows, lats) = parse_file(args.in_file[0])

plt.hist(lats, bins=1000, density=True)
plt.show()

with open(args.out_file, 'w') as out_file:
    writer = csv.writer(out_file)
    writer.writerows(rows)


print("Done")
