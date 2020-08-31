#!/usr/bin/env python2

import argparse
import logging
import sys
import pyodbc

logger = logging.getLogger('pgsql-inventory')


def setup_logging(loglevel, logfile):
    logger.setLevel(logging.getLevelName(loglevel.upper()))
    if logfile == '-':
        ch = logging.StreamHandler(sys.stdout)
    elif logfile == 'STDERR':
        ch = logging.StreamHandler(sys.stderr)
    else:
        ch = logging.handlers.RotatingFileHandler(logfile,
                                                  maxBytes=20 * 1024 * 1024,
                                                  backupCount=1)
    formatter = logging.Formatter('%(asctime)s %(levelname)-7s %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def sql_connect():
    """
    PURPOSE:
        Create connection to DBMONITOR
    RETURNS:
        Returns connection and cursor
    """
    try:
        conn_sql = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};'
            'Server=dbmonitor1a.win.ia55.net;'
            'Failover_Partner=dbmonitor1b.win.ia55.net;'
            'DATABASE=dbainfra;UID=;PWD=;APP=postgres;ServerSPN=MSSQLSvc/dbmonitor1a.win.ia55.net@WIN.IA55.NET')
        cur_sql_dest = conn_sql.cursor()
        conn_sql.autocommit = True
        return cur_sql_dest, conn_sql
    except Exception as ex:
        logger.error("Connection to dbmonitor database is failed")
        logger.error(str(ex))
        sys.exit(1)


def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create a RDS instance")
    createordelete.add_argument("--delete", action='store_true', help="To delete a RDS instance")
    # Required arguments
    parser.add_argument('--stability', dest='stability', help='Give stability information example : uat, prod',
                        required=True)
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)
    # Optional arguments
    parser.add_argument("--backup_retention_days", dest='backup_retention_days', default=367,
                        help="Backup retention in days, example : 367")
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the instance creation")
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    return parser.parse_args()


def make_inventory_entry(pod, stability, backup_retention_days, dry_run):
    """
    make an entry into inventory tables
    Args:
        pod: ex: balyuat
        stability: ex: uat
        backup_retention_days: ex: 367
        dry_run:
    Returns:
    """
    alias = pod + 'dbpg1'
    dataserver = 'dbpostgres.' + pod + '.c.ia55.net'
    tier = 'Tier 1:<<BR>>Arcesium'
    query = "insert into dbainfra.dbo.database_server_inventory(Tier, Dataserver, Env, Alias, Description, " \
            "Host, HasDR,DRStrategy, DRDataserver, DRHost, IsActive, Monitor, ServerType, FriendlyName, " \
            "Pod, ClientDbState, ssl_enabled) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    if dry_run:
        logger.info("dry run: run the below query in dbmonitor SQL server for create entry")
        logger.info("dry run: insert into dbainfra.dbo.database_server_inventory values('" + tier + "','" + dataserver +
                    "','" + stability + "','" + alias + "','" + pod + "','" + dataserver +
                    "', 'n/a', 'n/a', 'n/a', 'n/a', 0, 'Yes', 'PGDB','" + dataserver + "','" + pod + "','onboarding',0)")
        logger.info("dry run: insert into dbainfra.dbo.database_server_inventory(pod,retention_in_days) values('{}',{})".
                    format(pod, backup_retention_days))

    else:
        cursor, conn = sql_connect()
        # Making inventory entry for server inventory
        rows = cursor.execute("select count(1) from dbainfra.dbo.database_server_inventory where dataserver='{}'"
                              .format(dataserver))
        row = rows.fetchone()
        if row[0] == 0:
            cursor.execute(query, (tier, dataserver, stability, alias, pod, dataserver, 'n/a', 'n/a', 'n/a', 'n/a',
                                   1, 'Yes', 'PGDB',dataserver, pod, 'onboarding', 0))
        else:
            logger.info("Inventory entry already exists for server inventory")

        # Making inventory entry for backup retention
        rows = cursor.execute("select count(1) from dbainfra.dbo.pg_monthly_snapshot_retention where pod='{}'"
                              .format(pod))
        row = rows.fetchone()
        if row[0] == 0:
            cursor.execute("insert into dbainfra.dbo.pg_monthly_snapshot_retention(pod,retention_in_days)"
                           " values ('{}',{})".format(pod,backup_retention_days))
        else:
            logger.info("Inventory entry already exists for backup retention")
        conn.close()


def delete_inventory_entry(pod, dry_run):
    """
    delete the entry from inventory tables
    Args:
        pod: ex: balyuat
        dry_run:

    Returns:
    """
    dataserver = 'dbpostgres.' + pod + '.c.ia55.net'
    if dry_run:
        logger.info("dry run : run the below qury in dbmonitor1b SQL server")
        logger.info(
            "dry run : delete from dbainfra.dbo.database_server_inventory where dataserver='" + dataserver + "'")
        logger.info("dry run : delete from dbainfra.dbo.pg_monthly_snapshot_retention where pod='{}'".format(pod))
    else:
        cursor, conn = sql_connect()
        cursor.execute("delete from dbainfra.dbo.database_server_inventory where Dataserver='{}'".format(dataserver))
        cursor.execute("delete from dbainfra.dbo.pg_monthly_snapshot_retention where pod='{}'".format(pod))
        conn.commit()
        conn.close()


def main():
    # Get the user inputs
    args = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    stability 	          = args.stability
    pod 		          = args.pod
    dryrun 		          = args.dry_run
    backup_retention_days = args.backup_retention_days
    instance_action = ''

    if args.create:
        instance_action = 'create'
    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '
    else:
        dry_run = ''

    if instance_action == 'create':
        make_inventory_entry(pod, stability, backup_retention_days, dry_run)
    if instance_action == 'delete':
        delete_inventory_entry(pod, dry_run)


if __name__ == "__main__":
    main()
