# Owner       : oguri
# description : This is used to generate the cost report of Snowflake for last 6 months
# jobexecjob  : snowflake_cost_report

import snowflakeutil
import sys
sys.path.append()

snowflakeutil.snowflake_cost_utilization_report()

