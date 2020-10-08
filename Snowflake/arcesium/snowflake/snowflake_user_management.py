"""
Owner       : oguri
Description : This script helps in creating the users, reset the passwords and rotate the credentials for pods
"""
import textwrap
import argparse
import sys
sys.path.append('/g/dba/oguri/dba/snowflake')
import snowflakeutil
from datetime import datetime

logfile = '/g/dba/logs/snowflake/snowflake_user_management_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
logger = ''


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_user_management.py --create_user --pod baamuat --username cocoa_app --dbname arcesium_data_warehouse --user_type app --appname cocoa --user_mail cocoa-dev@arcesium.com 
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --create_user --pod baamuat --username soguri --dbname arcesium_data_warehouse --user_type temporary --retention 90 --user_mail oguri@arcesium.com
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --delete_user --pod baamuat --username cocoa_app
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --reset_user_password --pod baamuat --username cocoa_app
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --extend_retention_period --pod baamuat --username temp_oguri --retention 90
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --delete_expired_users --pod baamuat
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --unlock_user --pod baamuat --username cocoa_app
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --rotate_passwords --pod baamuat
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --grant_additional_permissions --permission_type database_owner --dbname arcesium_data_warehouse --username temp_oguri --pod terra
                                  OR
    sudo -u sqlexec python snowflake_user_management.py --grant_additional_permissions --permission_type monitoring_owner --username temp_oguri --pod terra   
    '''))
    # Parse the input task to be performed
    task = parser.add_mutually_exclusive_group(required=True)
    # user management options
    task.add_argument("--create_user", action='store_true', help="To create user")
    task.add_argument("--delete_user",action='store_true',help="To delete a user")
    task.add_argument("--reset_user_password", action='store_true', help="To reset user password")
    task.add_argument('--extend_retention_period', action='store_true', help="Extend retention period for temp users")
    task.add_argument('--unlock_user', action='store_true', help="unlock user account")
    task.add_argument('--delete_expired_users', action='store_true', help="delete expired users in account")
    task.add_argument('--rotate_passwords', action='store_true', help="reset user passwords in account")
    task.add_argument('--grant_additional_permissions',action='store_true', help="grant additional permissions to user")
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to create/delete , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--dbname', dest='dbname', help='Provide the db name, example: arcesium_data_warehouse')
    parser.add_argument('--username', dest='username', help='Provide the user name, example: cocoa_app')
    parser.add_argument('--user_mail', dest='user_mail', help='Provide the user mail, example: cocoa-dev@arcesium.com')
    parser.add_argument('--user_type', dest='user_type',choices=['app','third_party_app','customer','trm','temporary','app_team','dba'],help='Provide the user type')
    parser.add_argument('--appname', dest='appname',help='Give the appname, example: cocoa')
    parser.add_argument('--retention', dest='retention', help='Retention period for the user, example: 90')
    parser.add_argument('--permission_type', dest='permission_type', choices=['warehouse_owner', 'monitoring_owner', 'database_owner', 'share_owner'],help="type of permissions")
    return parser.parse_args()


def main():
    args             = parse_arguments()
    username         = args.username
    dbname           = args.dbname
    pod              = args.pod
    user_type        = args.user_type
    appname          = args.appname
    user_mail        = args.user_mail
    retention        = args.retention
    permission_type  = args.permission_type

    # implement logging
    global logger
    logger = snowflakeutil.setup_logging(logfile=logfile)

    if args.create_user:
        cmd = 'create_user'
    if args.delete_user:
        cmd = 'drop_user'
    if args.reset_user_password:
        cmd = 'reset_user_password'
    if args.extend_retention_period:
        cmd = 'extend_retention_period'
    if args.unlock_user:
        cmd = 'unlock_user'
    if args.delete_expired_users:
        cmd = 'delete_expired_users'
    if args.rotate_passwords:
        cmd = 'rotate_passwords'
    if args.grant_additional_permissions:
        cmd = 'grant_additional_permissions'

    # user management commands
    if cmd == 'create_user' and args.user_type is None:
        print("Missing user type , please give user type")
        sys.exit(1)
    if cmd == 'create_user' and args.user_type is not None:
        if args.user_type == 'app':
            if args.username is None or args.dbname is None or args.appname is None or args.user_mail is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_user_management.py --create_user --pod baamuat"
                      " --username cocoa_app --dbname arcesium_data_warehouse --user_type app --appname cocoa"
                      " --user_mail cocoa-dev@arcesium.com")
                sys.exit(1)
        if args.user_type in ['third_party_app','customer','trm','app_team','dba']:
            if args.username is None or args.dbname is None or args.user_mail is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_user_management.py --create_user --pod baamuat"
                      " --username looker_user --dbname arcesium_data_warehouse --user_type third_party_app"
                      " --user_mail dba-ops-team@arcesium.com")
                sys.exit(1)
        if args.user_type == 'temporary':
            if args.username is None or args.dbname is None or args.user_mail is None or args.retention is None:
                print("Missing required field for create user")
                print("sudo -u sqlexec python snowflake_user_management.py --create_user --pod terra"
                      " --username soguri --dbname arcesium_data_warehouse --user_type temporary"
                      " --retention 90 --user_mail oguri@arcesium.com")
                sys.exit(1)
    if cmd == 'drop_user' and args.username is None:
        print('Missing required field for drop user')
        print("example : sudo -u sqlexec python snowflake_user_management.py --delete_user"
              " --pod baamuat --username cocoa_app")
        sys.exit(1)
    if cmd == 'reset_user_password' and args.username is None:
        print('Missing required field for reset user password')
        print(
            "example : sudo -u sqlexec python snowflake_user_management.py --reset_user_password"
            " --pod baamuat --username cocoa_app")
        sys.exit(1)
    if cmd == 'extend_retention_period' and (args.username is None or args.retention is None):
        print('Missing required fields to extend the retention for user')
        print('sudo -u sqlexec python snowflake_user_management.py --extend_retention_period --pod baamuat'
              ' --username temp_oguri --retention 90')
        sys.exit(1)
    if cmd == 'unlock_user' and args.username is None:
        print('Missing required fields to unlock user')
        print(
            'sudo -u sqlexec python snowflake_user_management.py --unlock_user --pod terra --username cocoa_app')
        sys.exit(1)
    if cmd == 'grant_additional_permissions' and (args.permission_type is None or args.username is None):
        print('Missing required fields to grant permissions to user')
        print('sudo -u sqlexec python snowflake_user_management.py --grant_additional_permissions'
              ' --permission_type warehouse_owner --pod terra --username cocoa_app')
        sys.exit(1)
    if cmd == 'grant_additional_permissions' and args.permission_type in ['database_owner', 'database_reader'] and args.dbname is None and args.user_type is None:
        print('Missing required fields to grant permissions to user')
        print('sudo -u sqlexec python snowflake_user_management.py --grant_additional_permissions'
              ' --permission_type database_owner --pod terra --username cocoa_app'
              ' --dbname arcesium_data_warehouse --user_type app')
        sys.exit(1)

    # Get list of accounts on which the operation need to be performed
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
        # user management operations
        if cmd == 'create_user':
            logger.info("Creating user: {} on instance {}".format(username, account))
            if user_type == 'temporary':
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type,
                                            user_mail=user_mail, dbname=dbname, retention=retention, logfile=logfile)
            if user_type == 'app':
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type,
                                          user_mail=user_mail, dbname=dbname, appname=appname, logfile=logfile)
            if user_type in ['third_party_app','customer','trm','app_team','dba']:
                snowflakeutil.create_user(account=account, username=username, pod=pod, user_type=user_type,
                                                     user_mail=user_mail, dbname=dbname, logfile=logfile)

        if cmd == 'drop_user':
            logger.info("Deleting user: {} in account {}".format(username, account))
            snowflakeutil.drop_user(account,username,pod)
        if cmd == 'reset_user_password':
            logger.info("Resetting password for user: {} in account {}".format(username, account))
            snowflakeutil.reset_user_password(account=account, pod=pod, username=username)
        if cmd == 'extend_retention_period':
            logger.info("Extend retention period for user: {} in account {}".format(username, account))
            snowflakeutil.extend_user_retention(account=account, pod=pod,  username=username, retention=retention)
        if cmd == 'delete_expired_users':
            logger.info("Delete expired users from account {} or pod {}".format(account, pod))
            snowflakeutil.delete_expired_users(account= account, pod=pod)
        if cmd == 'rotate_passwords':
            logger.info("Rotating user passwords in account {} or pod {}".format(account, pod))
            snowflakeutil.rotate_passwords(account=account, pod=pod)
        if cmd == 'grant_additional_permissions':
            logger.info("Granting additional permission {} to user {} or pod {}".format(permission_type, username, pod))
            if permission_type in ['database_owner','database_reader']:
                snowflakeutil.grant_additional_permissions(account=account, pod=pod, username=username,
                                                           permission_type=permission_type, dbname=dbname, user_type=user_type)
            else:
                snowflakeutil.grant_additional_permissions(account=account, pod=pod, username=username,
                                                           permission_type=permission_type)


if __name__ == "__main__":
    main()
