#!/usr/bin/env python

# from optparse import OptionParser
import argparse
import math
import re
import json


def parse_file(f):
    stats = dict()
    lines = f.readlines()

    # We suppose that the benchark log has a spdlog format ending with %v
    pattern = r"(\{.*\})$"
    prog = re.compile(pattern)

    for l in lines:
        line = l.strip('\n\t')
        m = prog.search(line)

        json_data = json.loads(m.group(0))

        name = json_data['message']
        if not name in stats:
            stats[name] = dict()

        items = json_data['items']
        # time = float(json_data['time'])
        time_per_item = float(json_data['time/item'])

        if items in stats[name]:
            old_sum = stats[name][items]["sum"]
            old_square_sum = stats[name][items]["square_sum"]
            counter = stats[name][items]["counter"]
            min_v = stats[name][items]["min"]
            max_v = stats[name][items]["max"]
        else:
            old_sum = 0
            old_square_sum = 0
            counter = 0
            min_v = 1e9
            max_v = 0
            stats[name][items] = dict()

        stats[name][items]["sum"] = old_sum+time_per_item
        stats[name][items]["square_sum"] = old_square_sum + \
            time_per_item*time_per_item
        stats[name][items]["counter"] = counter+1
        stats[name][items]["min"] = min(min_v, time_per_item)
        stats[name][items]["max"] = max(max_v, time_per_item)

    return stats


def compute_mean_var(stats):
    res = {}
    for name in stats:
        res[name] = {}
        for key in stats[name]:
            res[name][key] = {}
            res[name][key]["mean"] = stats[name][key]["sum"] / \
                stats[name][key]["counter"]
            res[name][key]["dev"] = math.sqrt(
                stats[name][key]["square_sum"]/stats[name][key]["counter"] - res[name][key]["mean"]*res[name][key]["mean"])
            res[name][key]["min"] = stats[name][key]["min"]
            res[name][key]["max"] = stats[name][key]["max"]

    return res


def print_mean_var(stats, f):
    for name in stats:
        for key in sorted(stats[name].keys()):
            line = '{0} \t {1} \t {2} \t {3} \t {4} \t {5}\n'.format(name,
                                                                     key, stats[name][key]["mean"], stats[name][key]["dev"], stats[name][key]["min"], stats[name][key]["max"])
            f.write(line)
    f.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Process a Diana server benchmark file.')

    parser.add_argument("-i", "--input", dest="in_file", nargs=1,
                        required=True, help="Input file", type=argparse.FileType('r'))
    parser.add_argument("-o", "--out", dest="out_file", nargs=1,
                        required=True, help="Output file", type=argparse.FileType('w'))
    args = parser.parse_args()

    print("Parsing {0}, and outputting in {1}".format(
        args.in_file[0].name, args.out_file[0].name))
    stats = parse_file(args.in_file[0])
    means_var = compute_mean_var(stats)
    print_mean_var(means_var, args.out_file[0])

    print("Done")
