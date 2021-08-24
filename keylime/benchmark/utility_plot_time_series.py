#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import sys

import pylab
import matplotlib
matplotlib.use('Agg')


def main(argv=sys.argv):

    parser = argparse.ArgumentParser("keylime-utility-plot_time_series")
    parser.add_argument('-i', '--infile', required=True,
                        action='store', dest='infile')
    parser.add_argument('-o', '--outfile', action='store', dest='outfile')

    args = parser.parse_args(argv[1:])

    infile = args.infile
    # infile = "time_series_log_file_776058270.txt"
    outfile = args.outfile

    cycle_quantity_per_second_list = []

    with open(infile, encoding="utf-8") as input_file:
        content = [x.strip() for x in input_file.readlines()]
        index = 0
        for cycle_quantity_per_second in content:
            # throw out the first two and the last 2
            # if index >= 5 and index <= (len(content) - 6):
            cycle_quantity_per_second_list.append(
                float(cycle_quantity_per_second.strip()))
            index = index + 1


#     for each_file in glob.glob(infile + "*.txt"):
#         if each_file is not None:
#             with open(each_file) as input_file:
#                 content = [x.strip() for x in input_file.readlines()]
#                 index = 0
#                 for timestamp in content:
#                     if index != 0 and index <= (len(content) - 3):
#                         dec_secs = float(content[index + 1]) - float(timestamp)
#                         msecs = dec_secs * 1000
#                         difference_list.append(msecs)
#                     index = index + 1
    pylab.clf()
    pylab.plot(cycle_quantity_per_second_list, "-x")
    pylab.ylim([0, max(cycle_quantity_per_second_list)])
    pylab.ylabel('cycles per second')
    pylab.xlabel('time')

    if outfile is not None:
        pylab.savefig(outfile)

    # plt.show()


#     if outfile is not None:
#         with open(outfile, "w") as output_file:
#
#             index = 0
#             last_index = len(number_map) - 1
#             for float_key, each_list in number_map.iteritems():
#                 if index != 0 and index != last_index:
#                     output_file.write(str(len(each_list)) + "\n")
#
#                 index = index + 1


if __name__ == "__main__":
    main()
