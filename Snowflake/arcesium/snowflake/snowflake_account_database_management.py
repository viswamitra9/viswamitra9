import textwrap
import argparse
import sys
import arcesium.snowflake.snowflakeutil as snowflakeutil
from datetime import datetime

logfile = '/g/dba/logs/snowflake/snowflake_account_database_management_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = ''


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_manage_database_user.py --create_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_manage_database_user.py --delete_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_manage_database_user.py --prepare_account --account arc1500 --pod baamuat --region us-east-1 --account_env uat
    '''))
    # Parse the input task to be performed
    task = parser.add_mutually_exclusive_group(required=True)
    task.add_argument("--create_database", action='store_true', help="To create database")
    task.add_argument("--delete_database", action='store_true', help="To delete database")
    # account management options
    task.add_argument('--prepare_account', action='store_true', help="To prepare a new snowflake account")
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to create/delete , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--dbname', dest='dbname', help='Provide the db name, example: arcesium_data_warehouse')
    parser.add_argument('--account', dest='account', help='Provide the account , example: ama69523')
    parser.add_argument('--region', dest='region', help='Provide the region , example: us-east-1')
    parser.add_argument('--account_env',dest='account_env',help='Provide the environment of new account, example: shared-dev')
    return parser.parse_args()


def main():
    args             = parse_arguments()
    dbname           = args.dbname
    pod              = args.pod
    env              = args.env
    region           = args.region
    account          = args.account
    account_env      = args.account_env

    # implement logging
    global logger
    logger = snowflakeutil.setup_logging(logfile=logfile)

    if args.create_database:
        cmd = 'create_database'
    if args.delete_database:
        cmd = 'delete_database'
    if args.prepare_account:
        cmd = 'prepare_account'

    # database management commands
    if cmd == 'create_database' and args.dbname is None:
        print('Missing required field for database creation')
        print("example : sudo -u sqlexec python snowflake_manage_database_user.py --create_database --pod baamuat"
              " --dbname arcesium_data_warehouse")
        sys.exit(1)
    if cmd == 'delete_database' and args.dbname is None:
        print('Missing required field for database deletion')
        print("example : sudo -u sqlexec python snowflake_manage_database_user.py --delete_database --pod baamuat"
              " --dbname arcesium_data_warehouse")
        sys.exit(1)
    # account management commands
    if cmd == 'prepare_account' and (args.account is None or args.region is None or args.pod is None or
                                     args.account_env is None):
        print('Missing required field for prepare account')
        print("example : sudo -u sqlexec python snowflake_manage_database_user.py --prepare_account --account arc1500"
              " --pod baamuat --region us-east-1 --account_env uat")
        sys.exit(1)

    # account management operations
    if cmd == 'prepare_account':
        logger.info("Preparing new snowflake account {}".format(account))
        snowflakeutil.prepare_account(account,region,account_env,pod)
        logger.info("Prepared new snowflake account {} successfully".format(account))
        exit(0)

    # Get the list of instances on which the database needs to be created or dropped
    instances = {}
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    if args.pod:
        query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory " \
                "where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(args.pod)
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
    if args.env:
        query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory " \
                "where lower(ServerType)='snowflake' and IsActive=1"
        if args.env != 'all':
            query = "select lower(FriendlyName),lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and lower(Env)='{}' and" \
                    " IsActive=1".format(str(args.env).lower())
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
    conn_sql_dest.close()

    for account in instances:
        pod     = instances[account]
        if cmd == 'create_database':
            logger.info("Creating database: {} in account {}".format(dbname, account))
            snowflakeutil.create_database(account,dbname,pod)
        if cmd == 'delete_database':
            logger.info("Deleting database: {} in account {}".format(dbname, account))
            snowflakeutil.drop_database(account,dbname,pod)

if __name__ == "__main__":
    main()