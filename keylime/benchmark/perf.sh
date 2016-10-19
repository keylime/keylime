#!/bin/bash

##########################################################################################
#
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for 
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in 
# this material are those of the author(s) and do not necessarily reflect the views of the 
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2015 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
# above. Use of this work other than as specifically authorized by the U.S. Government may 
# violate any copyrights that exist in this work.
#
##########################################################################################

# pass in a directory that has all the log files

if [ $# -lt 1 ]
then
echo "Usage:  `basename $0` dir_of_log_files" >&2
exit $NOARGS;
fi

python utility_average_logged_deltas.py -f $1/get_q_log_file -t     "get quote in ms: "
python utility_average_logged_deltas.py -f $1/provide_v_log_file -t "provide v in ms: "
python utility_make_1_second_interval_average_list.py -i $1/time_series_log_file -o $1/ts_result.txt
python utility_average_logged_deltas.py -f $1/ts_result -t          "quotes/s:        "
python utility_smoothed_ts.py -f $1/time_series_log_file -t         "overall q/s:     "
python utility_plot_time_series.py -i $1/ts_result.txt -o plot.pdf