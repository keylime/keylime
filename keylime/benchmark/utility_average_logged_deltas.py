'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import sys
import glob
import numpy


def main(argv=sys.argv):
    parser = argparse.ArgumentParser("keylime-utility-average_logged_deltas")
    parser.add_argument('-f', '--filename', required=True,
                        action='store', dest='filename')
    parser.add_argument('-t', '--text_description',
                        action='store', dest='text_description')

    concat_content = []
    args = parser.parse_args(argv[1:])
    for each_file in glob.glob(args.filename + "*.txt"):
        # command line options can overwrite config values
        if each_file is not None:
            with open(each_file, encoding="utf-8") as f:
                content = [x.strip() for x in f.readlines()]
                # remove last element (could be weird)
                # del content[-1:]
                concat_content.extend(content)

    float_list = []
    for i in concat_content:
        float_list.append(float(i))

    float_list = numpy.array(float_list)

    if "ts_result" not in args.filename:
        # convert to milliseconds
        float_list = float_list * 1000

    # print "my list is %s"%(float_list[1:10])
    print("%s mean %.3f, std %.3f, min %.3f, med %.3f, max %.3f" % (args.text_description, numpy.average(
        float_list), numpy.std(float_list), numpy.min(float_list), numpy.median(float_list), numpy.max(float_list)))
    # print args.text_description + str() + " : " + str()
    # print args.text_description + str(average)


if __name__ == "__main__":
    main()
