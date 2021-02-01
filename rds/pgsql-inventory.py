#!/usr/bin/env python2

import argparse
import logging
import sys
import pyodbc

logger = logging.getLogger('pgsql-instance')


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


from retrying import retry
@retry(stop_max_attempt_number=5, wait_fixed=1000)
def sql_connect():
    # create a SQL connection to DBMONITOR1B database and return the connection and cursor object
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor5b.win.ia55.net;APP=Hammer;database=dbainfra')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logger.error("Failed to connect to DBMONITOR with error : {}, trying again".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create a RDS instance")
    createordelete.add_argument("--delete", action='store_true', help="To delete a RDS instance")
    # Required arguments
    parser.add_argument('--stability', dest='stability', help='Give stability information example : uat, prod',required=True)
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)
    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the instance creation")
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    return parser.parse_args()


def make_inventory_entry(pod, stability, dry_run):
    # function to make entry of RDS instance into repository
    alias      = pod + 'dbpg1'
    dataserver = 'dbpostgres.' + pod + '.c.ia55.net'
    tier       = 'Tier 1:<<BR>>Arcesium'
    query      = "insert into dbainfra.dbo.database_server_inventory(Tier, Dataserver, Env, Alias, Description, " \
                 "Host, HasDR, " \
                 "DRStrategy, DRDataserver, DRHost, IsActive, Monitor, ServerType, FriendlyName, Pod, ClientDbState, " \
                 "ssl_enabled) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    if dry_run:
        logger.info("dry run: run the below query in dbmonitor SQL server")
        logger.info("dry run: insert into dbainfra.dbo.database_server_inventory values(" + tier + "," + dataserver +
                    "," + stability + "," + alias + "," + pod + "," + dataserver +
                    ", 'n/a', 'n/a', 'n/a', 'n/a', 0, 'Yes', 'PGDB'," + dataserver + "," + pod + "'onboarding',0)")
        if str(stability).lower() != 'prod':
            logger.info("dry run: insert into dbainfra.dbo.refresh_db_exclusion_list values('{}','carlin',CURRENT_TIMESTAMP,'9999-12-31 00:00:00.000','ArcTechOps#222891')".format(alias))
    else:
        cur_sql_dest, conn_sql_dest = sql_connect()
        query_cnt = "select count(1) from dbainfra.dbo.database_server_inventory where dataserver='" + dataserver + "'"
        rows = cur_sql_dest.execute(query_cnt)
        row  = rows.fetchone()
        if row[0] == 0:
            cur_sql_dest.execute(query, (tier, dataserver, stability, alias, pod, dataserver, 'n/a', 'n/a', 'n/a', 'n/a', 1, 'Yes', 'PGDB',dataserver, pod, 'onboarding', 0))
            conn_sql_dest.commit()
        else:
            logger.info("Inventory entry already exists")
        # Make entry for the databases which need to be excluded across pods and environments
        if str(stability).lower() != 'prod':
            query_cnt = "select count(1) from dbainfra.dbo.refresh_db_exclusion_list where lower(instancename)='{}' and dbname='carlin'".format(str(alias).lower())
            rows      = cur_sql_dest.execute(query_cnt)
            row       = rows.fetchone()
            if row[0] == 0:
                cur_sql_dest.execute("insert into dbainfra.dbo.refresh_db_exclusion_list values('{}','carlin',CURRENT_TIMESTAMP,'9999-12-31 00:00:00.000','ArcTechOps#222891')".format(str(alias).lower()))
                conn_sql_dest.commit()
            else:
                logger.info("Database exclusion entry already exists")
        conn_sql_dest.close()


def delete_inventory_entry(pod, stability,dry_run):
    # function to remove entry from repository
    dataserver = 'dbpostgres' + pod + '.c.ia55.net'
    alias      = pod + 'dbpg1'
    if dry_run:
        logger.info("dry run : run the below qury in dbmonitor1b SQL server")
        logger.info("dry run : delete from dbainfra.dbo.database_server_inventory where dataserver='" + dataserver + "'")
        if str(stability).lower() != 'prod':
            logger.info("dry run : delete from dbainfra.dbo.refresh_db_exclusion_list where lower(instancename)='{}' and dbname='carlin'".format(alias))
    else:
        query = "delete from dbainfra.dbo.database_server_inventory where dataserver=?"
        cur_sql_dest, conn_sql_dest = sql_connect()
        cur_sql_dest.execute(query, (dataserver))
        # Remove entry for database exclusion inventory
        if str(stability).lower() != 'prod':
            query = "delete from dbainfra.dbo.refresh_db_exclusion_list where lower(instancename)='{}' and dbname='carlin'".format(alias)
            cur_sql_dest.execute(query)
        conn_sql_dest.commit()
        conn_sql_dest.close()


def main():
    # Get the user inputs
    args = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    stability 	= args.stability
    pod 		= args.pod
    dryrun 		= args.dry_run
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
        make_inventory_entry(pod, stability, dry_run)
    if instance_action == 'delete':
        delete_inventory_entry(pod, stability, dry_run)


if __name__ == "__main__":
    main()
