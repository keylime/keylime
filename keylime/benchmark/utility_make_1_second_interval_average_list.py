'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

import argparse
import sys 
import math
from itertools import count
from collections import OrderedDict
import glob

def main(argv=sys.argv):
    
    parser = argparse.ArgumentParser("keylime-utility-make_1_second_interval_average_list")
    parser.add_argument('-i', '--infile',action='store', required=True ,dest='infile')
    parser.add_argument('-o', '--outfile',action='store', required=True, dest='outfile')
 
    args = parser.parse_args(argv[1:])
    
    infile = args.infile
    outfile = args.outfile
    
    number_map = OrderedDict()    
    
    for each_file in glob.glob(infile + "*.txt"):
    # command line options can overwrite config values
        if each_file is not None:
    
            with open(each_file) as input_file:
                content = [x.strip() for x in input_file.readlines()]
                index = 0
                for each_value in content:
                    last_value = len(content) - 1

                    decimal_part, integer_part = math.modf(float(each_value))
                    the_list = None
                    if integer_part not in list(number_map.keys()):
                        the_list = []
                        number_map[int(integer_part)] = the_list
                    else:
                        the_list = number_map[int(integer_part)]
                    the_list.append(float(each_value))
                    index = index + 1
                    
    with open(outfile, "w") as output_file:            
        
        index = 0
        last_index = len(number_map) - 1
        for float_key, each_list in number_map.items():

            output_file.write(str(len(each_list)) + "\n")
        
            index = index + 1



if __name__=="__main__":
    main()