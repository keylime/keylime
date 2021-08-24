'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import sys
import glob


def main(argv=sys.argv):
    parser = argparse.ArgumentParser("keylime-utility-smoother")
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

    time = float_list[-1] - float_list[0]
    print("%s %.3f" % (args.text_description, len(float_list) / time))


if __name__ == "__main__":
    main()
