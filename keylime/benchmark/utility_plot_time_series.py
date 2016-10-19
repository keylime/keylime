#!/usr/bin/python

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
import matplotlib
matplotlib.use('Agg')
import pylab
import glob



def main(argv=sys.argv):
    
    parser = argparse.ArgumentParser("keylime-utility-plot_time_series")
    parser.add_argument('-i', '--infile', required=True, action='store',dest='infile')
    parser.add_argument('-o', '--outfile',action='store',dest='outfile')
  
    args = parser.parse_args(argv[1:])
    
    infile = args.infile
    #infile = "time_series_log_file_776058270.txt" 
    outfile = args.outfile
    

    cycle_quantity_per_second_list = []

    with open(infile) as input_file:
        content = [x.strip() for x in input_file.readlines()]
        index = 0
        for cycle_quantity_per_second in content:
            #throw out the first two and the last 2
            #if index >= 5 and index <= (len(content) - 6):
            cycle_quantity_per_second_list.append(float(cycle_quantity_per_second.strip()))
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
    pylab.plot(cycle_quantity_per_second_list,"-x")
    pylab.ylim([0,max(cycle_quantity_per_second_list)])
    pylab.ylabel('cycles per second')
    pylab.xlabel('time')
    
    if outfile is not None:
        pylab.savefig(outfile)
    
    #plt.show()
    

  
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



if __name__=="__main__":
    main()