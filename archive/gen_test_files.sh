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



if [ $# -lt 3 ]
then
    echo "Usage:  `basename $0` ip port_range_start number_of_entries" >&2
    exit $NOARGS;
fi


# usage ip port_start number

IP=$1
PORT_START=$2
NUM=$3


PORT_END=$(($PORT_START+$NUM))

# truncate files
> cloudagent_port.txt
> cloudagent_ip.txt

for i in `seq $PORT_START $PORT_END`
do
	echo $i >> cloudagent_port.txt
	echo $IP >> cloudagent_ip.txt
done