'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import sys
import glob
import numpy


def main(argv=sys.argv):  #pylint: disable=dangerous-default-value
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
    print(f"{args.text_description} mean {numpy.average(float_list):.3f}, "
          f"std {numpy.std(float_list):.3f}, min {numpy.min(float_list):.3f}, "
          f"med {numpy.median(float_list):.3f}, max {numpy.max(float_list):.3f}")
    # print args.text_description + str() + " : " + str()
    # print args.text_description + str(average)


if __name__ == "__main__":
    main()
