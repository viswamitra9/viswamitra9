"""
Owner       : oguri
Description : Snowflake database refresh generate old databases which need to be deleted on every wednesday
"""
from datetime import datetime
import sys
sys.path.append('/g/dba/snowflake')
import snowflakeutil
import logging
import textwrap
import argparse

logfile = '/g/dba/logs/snowflake/snowflake_delete_refresh_databases_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = logging.getLogger()


def raise_radar_alert(alert_description):
    """
    PURPOSE:
        raise a radar alert when a backup deletion is failed
    """
    from arcesium.radar.client import SendAlertRequest
    from arcesium.radar.client import RadarService
    request = SendAlertRequest()
    request.alert_source      = 'dba'
    request.alert_class       = 'Page'
    request.alert_severity    = 'CRITICAL',
    request.alert_key         = 'Snowflake delete refresh databases'
    request.alert_summary     = "failed to delete databases generated from Snowflake refresh"
    request.alert_description = str(alert_description) + "Please check the documentation {} " \
                                "for more information.".format('http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Backup+and+Recovery')
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))
        raise Exception("Error occurred while raising radar alert {}".format(str(err)))


def delete_old_refresh_databases():
    """
    Description : This method is to delete backup databases created from weekend refresh
    """
    try:
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        logger.info("Created connection to DBMONITOR server to get old databases created out of refresh")
        # get list of accounts and pod details
        cur_sql_dest.execute("select distinct accountname,pod from dbainfra.dbo.snowflake_old_databases where deleted=0")
        result = cur_sql_dest.fetchall()
        if len(result) == 0:
            logger.info("There are no databases to delete")
            print("There are no databases to delete")
            return 2
        for i in result:
            accountname = i[0]
            pod         = i[1]
            # get list of databases present in the account(pod)
            logger.info("Get list of databases to delete from pod {}".format(pod))
            cur_sql_dest.execute("select dbname from dbainfra.dbo.snowflake_old_databases "
                                 "where deleted=0 and pod='{}' and accountname='{}'".format(pod,accountname))
            result_databases = cur_sql_dest.fetchall()
            logger.info("Creating DBA connection to pod {}".format(pod))
            dba_conn, dba_cur = snowflakeutil.get_admin_connection(accountname, pod)
            for db in result_databases:
                dbname = db[0]
                dba_cur.execute("drop database if exists {}".format(dbname))
                logger.info("dropped database {} from pod {}".format(dbname, pod))
                cur_sql_dest.execute("update dbainfra.dbo.snowflake_old_databases "
                                     "set deleted=1 where pod='{}' and accountname='{}' and dbname='{}'".format(pod, accountname, dbname))
        return 0
    except Exception as e:
        alert_description = "failed to delete the databases, please check logfile".format(logfile)
        raise_radar_alert(alert_description)
        logger.error("failed to delete databases generated from refresh")
        sys.exit(1)


# parse the input arguments
def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_delete_refresh_databases.py
    '''))
    return parser.parse_args()


def main():
    args   = parse_arguments()

    # implement logging
    global logger
    logger = snowflakeutil.setup_logging(logfile=logfile)
    return_code = delete_old_refresh_databases()
    if return_code == 0:
        logger.info("Successfully deleted the databases created from refresh")


if __name__ == "__main__":
    main()