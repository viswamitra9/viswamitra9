import textwrap
import argparse
import sys
import arcesium.snowflake.snowflakeutil as snowflakeutil
from datetime import datetime

logfile = '/g/dba/logs/snowflake/snowflake_database_user_management_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = snowflakeutil.setup_logging(logfile=logfile)


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_create_delete_database.py --create_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --delete_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username cocoa_app --dbname arcesium_data_warehouse --user_type app --appname cocoa --user_mail cocoa-dev@arcesium.com 
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username soguri --dbname arcesium_data_warehouse --user_type temporary --retention 90 --user_mail oguri@arcesium.com
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --delete_user --pod baamuat --username cocoa_app
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --prepare_account --account arc1500 --pod baamuat --region us-east-1 --env uat
    '''))
    # Parse the input task to be performed
    task = parser.add_mutually_exclusive_group(required=True)
    task.add_argument("--create_database", action='store_true', help="To create database")
    task.add_argument("--delete_database", action='store_true', help="To delete database")
    task.add_argument("--create_user", action='store_true', help="To create user")
    task.add_argument("--delete_user",action='store_true',help="To delete a user")
    task.add_argument('--prepare_account', action='store_true', help="To prepare a new snowflake account")
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to create/delete , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--dbname', dest='dbname', help='Provide the db name, example: test')
    parser.add_argument('--username', dest='username', help='Provide the user name, example: test')
    parser.add_argument('--user_mail', dest='user_mail', help='Provide the user name, example: test')
    parser.add_argument('--user_type', dest='user_type',choices=['app','third_party_app','customer','trm','temporary','app_team'],help='Provide the user type')
    parser.add_argument('--appname', dest='appname',help='Give the appname, example: iris')
    parser.add_argument('--retention', dest='retention', help='Retention period for the user, example: 90')
    parser.add_argument('--account', dest='account', help='Provide the account , example: ama69523')
    parser.add_argument('--region', dest='region', help='Provide the region , example: us-east-1')
    parser.add_argument('--account_env',dest='account_env',help='Provide the environment of new account, example: uat')
    return parser.parse_args()


def main():
    args             = parse_arguments()
    username         = args.username
    dbname           = args.dbname
    pod              = args.pod
    user_type        = args.user_type
    appname          = args.appname
    region           = args.region
    account          = args.account
    account_env      = args.account_env
    user_mail        = args.user_mail
    retention        = args.retention

    if args.create_database:
        cmd = 'create_database'
    if args.delete_database:
        cmd = 'delete_database'
    if args.create_user:
        cmd = 'create_user'
    if args.prepare_account:
        cmd = 'prepare_account'
    if args.delete_user:
        cmd = 'drop_user'

    if cmd == 'create_database' and args.dbname is None:
        print('Missing required field for database creation')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --create_database --pod baamuat --dbname arcesium_data_warehouse")
        sys.exit(1)
    if cmd == 'delete_database' and args.dbname is None:
        print('Missing required field for database deletion')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --delete_database --pod baamuat --dbname arcesium_data_warehouse")
        sys.exit(1)
    if cmd == 'create_user' and args.user_type is None:
        print("Missing user type , please give user type")
        sys.exit(1)
    if cmd == 'create_user' and args.user_type is not None:
        if args.user_type == 'app':
            if args.username is None or args.dbname is None or args.appname is None or args.user_mail is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username cocoa_app --dbname arcesium_data_warehouse --user_type app --appname cocoa --user_mail cocoa-dev@arcesium.com")
                sys.exit(1)
        if args.user_type in ['third_party_app','customer','trm','app_team']:
            if args.username is None or args.dbname is None or args.user_mail is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username looker_user --dbname arcesium_data_warehouse --user_type third_party_app --user_mail dba-ops-team@arcesium.com")
                sys.exit(1)
        if args.user_type == 'temporary':
            if args.username is None or args.dbname is None or args.user_mail is None or args.retention is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod terra --username soguri --dbname arcesium_data_warehouse --user_type temporary --retention 90 --user_mail oguri@arcesium.com")
                sys.exit(1)
    if cmd == 'drop_user' and args.username is None:
        print('Missing required field for drop user')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --delete_user --pod baamuat --username cocoa_app")
        sys.exit(1)
    if cmd == 'prepare_account' and (args.account is None or args.region is None or args.pod is None or args.account_env is None):
        print('Missing required field for prepare account')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --prepare_account --account arc1500 --pod baamuat --region us-east-1 --account_env uat")
        sys.exit(1)

    instances = {}
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    if args.pod:
        query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(args.pod)
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
    if args.env:
        query = "select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and IsActive=1"
        if args.env != 'all':
            query = "select lower(FriendlyName),lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and lower(Env)='{}' and IsActive=1".format(str(args.env).lower())
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
        if cmd == 'create_user':
            logger.info("Creating user: {} on instance {}".format(username, account))
            if user_type == 'temporary':
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type, user_mail=user_mail, dbname=dbname, retention=retention)
            if user_type == 'app':
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type,
                                          user_mail=user_mail, dbname=dbname, appname=appname)
            if user_type in ['third_party_app','customer','trm','app_team']:
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type,user_mail=user_mail, dbname=dbname)
        if cmd == 'delete_database':
            logger.info("Deleting database: {} in account {}".format(dbname, account))
            snowflakeutil.drop_database(account,dbname,pod)
        if cmd == 'drop_user':
            logger.info("Deleting user: {} in account {}".format(username, account))
            snowflakeutil.drop_user(account,username,pod)
    if cmd == 'prepare_account':
        logger.info("Preparing new snowflake account {}".format(account))
        snowflakeutil.prepare_account(account,region,account_env,pod)


if __name__ == "__main__":
    main()