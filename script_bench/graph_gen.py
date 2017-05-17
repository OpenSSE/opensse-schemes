#!/usr/bin/env python

# from optparse import OptionParser
import argparse
import math


def parse_file(f):
    stats = dict()
    # with open(filepath) as f:
    lines = f.readlines()
    for l in lines:
        tokens = l.strip('\n\t').split(' \t')
        # print tokens

        keyword = tokens[0]
        value = float(tokens[1])
        # print 'keyword: {0}'.format(keyword)
        # print 'value: {0}'.format(value)
        
        if keyword in stats:
            old_sum = stats[keyword]["sum"]
            old_square_sum = stats[keyword]["square_sum"]
            counter = stats[keyword]["counter"]
            min_v = stats[keyword]["min"]
            max_v = stats[keyword]["max"]
        else:
            old_sum = 0
            old_square_sum = 0
            counter = 0
            min_v = 1e9
            max_v = 0
            stats[keyword] = dict()
            
        stats[keyword]["sum"] = old_sum+value
        stats[keyword]["square_sum"] = old_square_sum + value*value
        stats[keyword]["counter"] = counter+1
        stats[keyword]["min"] = min(min_v, value)
        stats[keyword]["max"] = max(max_v, value)
    
    return stats
    
def compute_mean_var(stats):
    res = {}
    for key in stats:
        res[key] = {}
        res[key]["mean"] = stats[key]["sum"]/stats[key]["counter"]
        res[key]["dev"] = math.sqrt(stats[key]["square_sum"]/stats[key]["counter"] - res[key]["mean"]*res[key]["mean"])
        res[key]["min"] = stats[key]["min"]
        res[key]["max"] = stats[key]["max"]

    return res


def print_mean_var(stats, f):
    # with open(filepath, 'w') as f:
    for key in sorted(stats.iterkeys()):
        line = '{0} \t {1} \t {2} \t {3} \t {4}\n'.format(key, stats[key]["mean"], stats[key]["dev"], stats[key]["min"], stats[key]["max"])
        f.write(line)
    f.close()
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process a Diane server benchmark file.')
    
    parser.add_argument("-i", "--input", dest="in_file",nargs=1, required=True, help ="Input file", type=argparse.FileType('r'))
    parser.add_argument("-o", "--out", dest="out_file", nargs=1, required=True, help ="Output file", type=argparse.FileType('w')) 
    args = parser.parse_args()
        
    print "Parsing {0}, and outputting in {1}".format(args.in_file[0].name, args.out_file[0].name)
    stats = parse_file(args.in_file[0])
    means_var = compute_mean_var(stats)
    # print stats
    # print "\n\n"
    print_mean_var(means_var,args.out_file[0])
    print "Done"