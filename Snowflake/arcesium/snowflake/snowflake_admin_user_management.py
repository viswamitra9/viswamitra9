# Owner       : Srinivas Oguri
# Description : This script is used to crate/delete admin(dba) users and reset the user passwords

import textwrap
import argparse
import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import logging
import json
import sys
import pyodbc
from datetime import datetime
sys.path.append('/g/dba/oguri/dba/snowflake/')
import vaultutil

logger  = logging.getLogger()
logfile = '/g/dba/logs/snowflake/snowflake_admin_user_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))


def set_logging():
    # default log level for root handler
    logger.setLevel(logging.INFO)
    # creating file handler
    ch = logging.FileHandler(filename=logfile)
    ch.setLevel(logging.INFO)
    # creating stream handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.ERROR)
    # set formatter for handlers with secretdetector
    ch.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    sh.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)


def sql_connect():
    """
    PURPOSE:
        Create connection to DBMONITOR
    RETURNS:
        Returns connection and cursor
    """
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;'
            'PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=Snowflake_admin_management;')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logger.error("Error while creating database connection to DBMONITOR server {}".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def get_snowflake_connection(account, username, password):
    """
    PURPOSE:
        Create Snowflake connection for account
    INPUTS:
        account(<account>.<region>.privatelink) , username , password
    RETURNS:
        returns connection, cursor
    """
    try:
        connection = snowflake.connector.connect(
            account=account,
            user=username,
            password=password,
            insecure_mode=True
        )
    except Exception as e:
        logger.error("Failed to create connection to account : {} with error {}".format(account, e))
        raise Exception("Failed to create connection to account : {} with error {}".format(account, e))
    cursor = connection.cursor()
    return connection, cursor


def get_admin_connection(account, pod):
    """
    PURPOSE:
        Create connection to account with sa user.
        Create database audit_archive , small warehouse
    INPUTS:
        account(<account>.<region>.privatelink) , username , password
    RETURNS:
        returns connection, cursor
    """
    password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
    password = json.loads(password)['password']
    connection, cursor = get_snowflake_connection(account=account, password=password, username='sa')
    try:
        cursor.execute("create database if not exists audit_archive")
        cursor.execute("use database audit_archive")
        cursor.execute("use schema public")
        logger.info("Checking for dba warehouse and create it if not exists")
        cursor.execute("create warehouse if not exists DBA_WH with WAREHOUSE_SIZE=small")
        cursor.execute("use role accountadmin")
        cursor.execute("use warehouse DBA_WH")
        return connection, cursor
    except Exception as e:
        logger.error("error while creating super user connection to account : {}".format(account))
        exit(1)


def get_unique_password():
    """
    PURPOSE:
        As snowflake accounts are accessable from any pod we Need to maintain the unique password for users
        across all snowflake accounts. So we are using sequences and md5 to get the unique passwords.
        Login to terra account, get md5 of sequence number and convert random part of string to upper case.
    RETURNS:
        returns password
    """
    account = 'arc1000.us-east-1.privatelink'  # pod: terra account
    connection, cursor = get_admin_connection(account, pod='terra')
    cursor.execute("create sequence if not exists audit_archive.public.password_generator")
    cursor.execute("select md5(select audit_archive.public.password_generator.nextval)")
    result = cursor.fetchone()
    basevalue = result[0]
    rand_num = random.randint(1, 15)
    str1 = basevalue[:rand_num]
    str2 = basevalue[rand_num:]
    password = str1.upper() + str2
    return password


def reset_admin_user_password(account, username, pod):
    """
    PURPOSE:
        reset user password and write to vault.
    INPUTS:
        account (account.<region>.privatelink, username, pod)
    """
    logger.info("Creating admin user connection to account {}".format(account))
    try:
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Resetting password for user {}".format(username))
        cursor.execute("alter user {} set password = '{}' must_change_password=False".format(username, password))
        logger.info("Password reset for user {}".format(username))
        vaultpath = "/secret/v2/snowflake/{}/db/{}".format(pod, username)
        logger.info("writing user {} password to vault path {}".format(username, vaultpath))
        cname = '{}.snowflakecomputing.com'.format(account)
        # write password to vault
        # As this is for dba users we setting the audit_archive as default database
        temp_secret = {'cname': cname, 'account': account, 'password': password, 'database': 'audit_archive'}
        secret = json.dumps(temp_secret)
        vaultutil.write_secret_to_vault(vaultpath, secret)
    except Exception as e:
        logger.error("error while user password reset, error : {}".format(str(e)))
        sys.exit(1)


def create_admin_user(account, username, pod):
    """
    PURPOSE:
        create admin user for dba team members and write secret to dba vault
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    try:
        logger.info("Creating admin user connection to account {}".format(account))
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Creating admin user {}".format(username))
        cursor.execute("create user {} password = '{}' default_role=accountadmin must_change_password=False"
                       .format(username, password))
        cursor.execute("grant role accountadmin to user {}".format(username))
        logger.info("Created admin user {}".format(username))
        # write password to vault
        # As this is for dba users we setting the audit_archive as default database
        vaultpath = "/secret/v2/snowflake/{}/db/{}".format(pod, username)
        logger.info("writing user {} password to vault path {}".format(username, vaultpath))
        cname = "{}.snowflakecomputing.com".format(account)
        temp_secret = {'cname': cname, 'account': account, 'password': password, 'database': 'audit_archive'}
        secret = json.dumps(temp_secret)
        vaultutil.write_secret_to_vault(vaultpath, secret)
        logger.info("wrote password to vault")
    except Exception as e:
        logger.error("error occurred while creating user , error : {}".format(str(e)))
        sys.exit(1)


def drop_admin_user(account, username, pod):
    """
    PURPOSE:
        drop admin users from account
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    try:
        logger.info("Creating admin user connection to account {}".format(account))
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        logger.info("Dropping user {} from account {}".format(username,account))
        cursor.execute("drop user if exists {}".format(username))
        cursor.execute("drop role if exists {}_role".format(username))
        logger.info("user dropped")
    except Exception as e:
        logger.error("error occurred while dropping user {} from account {} , error : {}".
                     format(username, account, str(e)))
        sys.exit(1)


def parse_arguments():
    """
    PURPOSE:
        parse input arguments and store the values in variables
    """
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_admin_user_management.py --create_admin_user --pod terra --username oguri_sa
                                  OR
    sudo -u sqlexec python snowflake_admin_user_management.py --create_admin_user --env all --username oguri_sa
                                  OR
    sudo -u sqlexec python snowflake_admin_user_management.py --drop_admin_user --env all --username oguri_sa
                                  OR
    sudo -u sqlexec python snowflake_admin_user_management.py --reset_admin_password --env dev --username oguri_sa
    '''))
    # Parse the input task to be performed
    task = parser.add_mutually_exclusive_group(required=True)
    task.add_argument("--create_admin_user", action='store_true', help="To create admin user")
    task.add_argument("--drop_admin_user", action='store_true', help="To drop admin user")
    task.add_argument("--reset_admin_password", action='store_true', help="To reset password for user")
    # Instances on which task need to be performed
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to create/delete , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--username', dest='username',required=True, help='Provide the user name, example: oguri_sa')
    return parser.parse_args()


def main():
    args     = parse_arguments()
    username = args.username
    set_logging()
    print("Please check logfile {} for any errors".format(logfile))

    if args.create_admin_user:
        cmd = 'create_admin_user'
    elif args.drop_admin_user:
        cmd = 'drop_admin_user'
    else:
        cmd = 'reset_admin_password'

    instances = {}  # dictionary which holds the account (format : <account>.<region>.privatelink) and pod details
    """
    Create SQL connection to DBMONITOR to extract information about the accounts
    """
    cur_sql_dest, conn_sql_dest = sql_connect()
    if args.pod:
        query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                "where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(args.pod)
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]

    if args.env:
        query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                "where lower(ServerType)='snowflake' and IsActive=1"
        if args.env != 'all':
            query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and lower(Env)='{}' " \
                    "and IsActive=1".format(str(args.env).lower())
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
    conn_sql_dest.close()

    for account, pod in instances.items():
        if cmd == 'create_admin_user':
            create_admin_user(account, username, pod)
        elif cmd == 'drop_admin_user':
            drop_admin_user(account, username, pod)
        elif cmd == 'reset_admin_password':
            reset_admin_user_password(account, username, pod)


if __name__ == "__main__":
    main()
