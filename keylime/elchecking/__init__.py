# This package implements event log checking.
# This checking is factored into two stages:
# 1. a policy maps a convenient expression of intended state into
#    a test to apply to event logs and PCR contents;
# 2. that test is applied to various log&PCRs pairs.

# Basic policies are built in.
# Additional policies are dynamically loaded according to config.
