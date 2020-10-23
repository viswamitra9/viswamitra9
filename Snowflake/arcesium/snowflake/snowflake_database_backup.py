import textwrap
import argparse
import snowflake.connector
import logging
import subprocess
from datetime import datetime
import os, sys
import pyodbc

logfile = '/g/dba/logs/snowflake/snowflake_database_backup_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', filename=logfile, level=logging.INFO)


def backup_database(account, host, dbname, pod):
    try:
        backup_name = "backup_{}_{}".format(dbname, datetime.now().strftime("%d%b%Y%H%M%S"))
        logging.info("Creating DBA connection")
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        dba_conn, dba_cur = get_dba_connection(account, host, 'sa', sa_pass)
        logging.info("Created a database connection")
        dba_cur.execute("use role accountadmin")
        dba_cur.execute("select count(*) from information_schema.databases where lower(database_name)='{}';".format(
            str(dbname).lower()))
        result = dba_cur.fetchall()
        for db in result:
            if db[0] == 0:
                logging.error("Database {} does not exist in pod {}".format(dbname, pod))
                return
        dba_cur.execute("create database {} clone {}".format(backup_name, dbname))
        logging.info("Backup {} created successfully for {} in pod {}".format(backup_name, dbname, pod))
    except Exception as e:
        raise Exception("Failed to take backup of database {} in pod {} with error : {}".format(dbname, pod, str(e)))


# parse the infput arguments
def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_database_backup.py --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_database_backup.py --env prod --dbname arcesium_data_warehouse
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
    args = parse_arguments()
    pod = args.pod
    env = args.env
    dbname = args.dbname

    instances = {}
    try:
        # Alert details
        alert_source = "dba"
        alert_class = "Page"
        alert_severity = "CRITICAL",
        alert_key = "Snowflake database backup"
        alert_summary = "Snowflake database backup in pod {}".format(pod)
        # create SQL connection to get information about instances
        cur_sql_dest, conn_sql_dest = sql_connect()
        if args.pod:
            query = "select lower(Host),lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(
                args.pod)
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]

        if args.env:
            query = "select lower(Host),lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and lower(Env)='{}' and IsActive=1".format(
                str(args.env).lower())
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]
        conn_sql_dest.close()

        logging.info("Instances are {}".format(instances))
        # Run the backup function for all instances
        for host in instances:
            account = str(host).split('.')[0]
            pod = instances[host]
            logging.info("Taking backup of database {} in pod {}".format(dbname, pod))
            backup_database(account, host, dbname, pod)
    except Exception as e:
        alert_description = "Failed to take database {} backup from pod {}, check logfile {}".format(dbname, pod,
                                                                                                     logfile)
        #radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
        sys.exit(1)


if __name__ == "__main__":
    main()