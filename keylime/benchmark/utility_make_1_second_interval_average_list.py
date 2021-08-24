'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import sys
import math
from collections import OrderedDict
import glob


def main(argv=sys.argv):

    parser = argparse.ArgumentParser(
        "keylime-utility-make_1_second_interval_average_list")
    parser.add_argument('-i', '--infile', action='store',
                        required=True, dest='infile')
    parser.add_argument('-o', '--outfile', action='store',
                        required=True, dest='outfile')

    args = parser.parse_args(argv[1:])

    infile = args.infile
    outfile = args.outfile

    number_map = OrderedDict()

    for each_file in glob.glob(infile + "*.txt"):
        # command line options can overwrite config values
        if each_file is not None:

            with open(each_file, encoding="utf-8") as input_file:
                content = [x.strip() for x in input_file.readlines()]
                index = 0
                for each_value in content:
                    _, integer_part = math.modf(float(each_value))
                    the_list = None
                    if integer_part not in list(number_map.keys()):
                        the_list = []
                        number_map[int(integer_part)] = the_list
                    else:
                        the_list = number_map[int(integer_part)]
                    the_list.append(float(each_value))
                    index = index + 1

    with open(outfile, "w", encoding="utf-8") as output_file:

        index = 0
        for _, each_list in number_map.items():

            output_file.write(str(len(each_list)) + "\n")

            index = index + 1


if __name__ == "__main__":
    main()
