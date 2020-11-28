"""
Owner       : oguri
Description : This script helps in taking database backup using zero copy clones of database.
"""
import textwrap
import argparse
from datetime import datetime
import sys
sys.path.append('/g/dba/snowflake')
import snowflakeutil
import logging

logfile = '/g/dba/logs/snowflake/snowflake_delete_expired_backup_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = logging.getLogger()


def raise_radar_alert(pod, alert_description):
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
    request.alert_key         = 'Snowflake delete expired backup'
    request.alert_summary     = "Snowflake delete expired backups from pod {} failed".format(pod)
    request.alert_description = str(alert_description) + "Please check the documentation {} " \
                                "for more information.".format('http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Backup+and+Recovery')
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def delete_expired_backups(account, pod):
    """
    Description : This method is to delete expired backups from pod (account)
    """
    try:
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        logger.info("Creating DBA connection")
        dba_conn, dba_cur = snowflakeutil.get_admin_connection(account, pod)
        logger.info("Created super user connection")
        cur_sql_dest.execute("select retention from dbainfra.dbo.snowflake_accounts where lower(pod)='{}'".format(str(pod).lower()))
        result = cur_sql_dest.fetchone()
        if len(result) == 0:
            logger.error("There is no retention entry for the pod {} in dbainfra.dbo.snowflake_accounts".format(pod))
            alert_description = "There is no retention entry for pod {} in dbainfra.dbo.snowflake_accounts".format(pod)
            raise_radar_alert(pod, alert_description)
            raise Exception("There is no retention entry for pod {} in dbainfra.dbo.snowflake_accounts".format(pod))
        retention = result[0]
        dba_cur.execute("select DATABASE_NAME from information_schema.databases "
                        "where database_name like 'BACKUP_%_%' and TIMESTAMPDIFF('DAY',CREATED,current_timestamp) > {}".format(retention))
        result = dba_cur.fetchall()
        if len(result) > 0:
            for i in result:
                dbname = i[0]
                logger.info("deleting database {} from pod {}".format(dbname, pod))
                dba_cur.execute("drop database if exists {}".format(dbname))
                logger.info("deleted database {} from pod {}".format(dbname, pod))
        if len(result) == 0:
            logger.info("There are no expired backups in pod {}".format(pod))
    except Exception as e:
        alert_description = "failed to delete the backups from pod {}".format(pod)
        raise_radar_alert(pod, alert_description)
        logger.error("failed to delete the backups from pod {}".format(pod))
        sys.exit(1)


# parse the input arguments
def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_delete_expired_backups.py --pod baamuat
                                  OR
    sudo -u sqlexec python snowflake_delete_expired_backups.py --env prod
    '''))
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to delete expired backup , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    return parser.parse_args()


def main():
    args   = parse_arguments()
    pod    = args.pod

    # implement logging
    global logger
    logger = snowflakeutil.setup_logging(logfile=logfile)

    instances = {}
    try:
        # create SQL connection to get information about instances
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        if args.pod:
            query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and lower(pod)='{}' and IsActive=1".format(str(args.pod).lower())
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]

        if args.env:
            query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and lower(Env)='{}' and IsActive=1".format(str(args.env).lower())
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]
        conn_sql_dest.close()

        logger.info("Backups to be deleted from accounts {}".format(instances))
        # Run the backup function for all instances
        for account in instances:
            pod = instances[account]
            logger.info("Taking backup of database in pod {}".format(pod))
            delete_expired_backups(account, pod)
    except Exception as e:
        alert_description = "Snowflake failed to delete the expired snapshots"
        raise_radar_alert(pod, alert_description)
        logger.error("Snowflake failed to delete the expired snapshots")
        raise Exception("Snowflake failed to delete the expired snapshots, please check logfile : {}".format(logfile))


if __name__ == "__main__":
    main()
