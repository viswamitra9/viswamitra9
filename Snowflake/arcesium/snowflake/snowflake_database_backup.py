"""
Owner       : oguri
Description : This script helps in taking database backup using zero copy clones of database.
"""
import textwrap
import argparse
from datetime import datetime
import sys
sys.path.append('/g/dba/oguri/dba/snowflake')
import snowflakeutil
import logging

logfile = '/g/dba/logs/snowflake/snowflake_database_backup_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = logging.getLogger()


def raise_radar_alert(pod, dbname):
    """
    PURPOSE:
        raise a radar alert when a database backup is failed
    Returns:
    """
    from arcesium.radar.client import SendAlertRequest
    from arcesium.radar.client import RadarService
    request = SendAlertRequest()
    request.alert_source = 'dba'
    request.alert_class = 'Page'
    request.alert_severity = 'CRITICAL',
    request.alert_key = 'Snowflake database backup'
    if dbname == 'none':
        request.alert_summary = "Snowflake database backup from pod {} failed".format(pod)
    else:
        request.alert_summary = "Snowflake database {} backup from pod {} failed".format(dbname, pod)
    request.alert_description = "Please check the documentation {} for more information.".format('http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Backup+and+Recovery')
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def backup_database(account, pod, dbname):
    """
    Description : This method is to take the backup of the databases in a pod (account), if the dbname is all then it
    will take backup of all database except internal databases
    Args:
        account: name of the account ex: arc1000
        pod: name of the pod ex: terra
        dbname: name of database arcesium_data_warehouse or all
    """
    try:
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        logger.info("Creating DBA connection")
        dba_conn, dba_cur = snowflakeutil.get_admin_connection(account, pod)
        logger.info("Created super user connection")
        if dbname == 'all':
            cur_sql_dest.execute("select dbname from dbainfra.dbo.snowflake_db_refresh_inventory where lower(pod)='{}'".format(str(pod).lower()))
            result = cur_sql_dest.fetchall()
            for db in result:
                backup_name = "backup_{}_{}".format(db[0], datetime.now().strftime("%d%b%Y"))
                dba_cur.execute("create database if not exists {} clone {}".format(backup_name, db[0]))
                logger.info("Backup {} created successfully for database {} in pod {}".format(backup_name, db[0], pod))
        if dbname != 'all':
            dba_cur.execute("select count(*) from information_schema.databases where lower(database_name)='{}'".format(str(dbname).lower()))
            result = dba_cur.fetchall()
            if result[0][0] == 0:
                logger.error("Database {} does not exists in pod {}".format(dbname, pod))
                raise Exception("Database {} does not exists in pod {}".format(dbname, pod))
            backup_name = "backup_{}_{}".format(dbname, datetime.now().strftime("%d%b%Y"))
            dba_cur.execute("create database if not exists {} clone {}".format(backup_name, dbname))
            logger.info("Backup {} created successfully for database {} in pod {}".format(backup_name, dbname, pod))
    except Exception as e:
        raise_radar_alert(pod, dbname)
        raise Exception("Failed to take backup of database in pod {} with error : {}".format(pod, str(e)))


# parse the input arguments
def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_database_backup.py --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_database_backup.py --env prod --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_database_backup.py --pod baamuat --dbname all
    '''))
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to backup , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--dbname', dest='dbname', help='Provide the db name, example: arcesium_data_warehouse',
                        required=True)
    return parser.parse_args()


def main():
    args   = parse_arguments()
    pod    = args.pod
    dbname = args.dbname

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

        logger.info("Accounts to be backed up are {}".format(instances))
        # Run the backup function for all instances
        for account in instances:
            pod = instances[account]
            logger.info("Taking backup of database in pod {}".format(pod))
            backup_database(account, pod, dbname)
    except Exception as e:
        raise_radar_alert(pod,dbname='none')
        logger.error("Failed to take database backup from pod {}, check logfile {}".format(pod, logfile))
        raise Exception("Failed to take database backup from pod {}, check logfile {}".format(pod, logfile))


if __name__ == "__main__":
    main()
