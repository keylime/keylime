#!/bin/bash

################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

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
