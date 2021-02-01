#!/usr/bin/env python
import random, time
import string
import sys
import psycopg2
import pyodbc
import argparse
import os
import textwrap
from datetime import datetime
from retrying import retry
import requests
from requests_kerberos import HTTPKerberosAuth
import json
import logging

DB_RETRY_COUNT = 10
DB_WAIT_TIME   = 10

logger = logging.getLogger('create_pg_admin_user_credentials')


def setup_logging(logfile):
    """
    Args:
        logfile: logfile where to write the information or errors
    Returns:
        configure the error logging file to write the errors or information
    """
    print("Please check the logfile {} for any errors".format(logfile))
    # default log level for root handler
    logger.setLevel(logging.INFO)
    # creating file handler
    ch = logging.FileHandler(filename=logfile)
    ch.setLevel(logging.INFO)
    # creating stream handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.ERROR)
    # set formatter for handlers with secretdetector
    ch.setFormatter(logging.Formatter('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    sh.setFormatter(logging.Formatter('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)
    return logger


def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python create_pg_admin_user_credentials.py --user username_sa --create --environment dev
                                  OR
    sudo -u sqlexec python create_pg_admin_user_credentials.py --user username_sa --create --server marsdbpg1a
                                  OR
    sudo -u sqlexec python create_pg_admin_user_credentials.py --user username_sa --create_or_reset --environment dev
    '''))
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create user")
    createordelete.add_argument("--delete", action='store_true', help="To delete user")
    createordelete.add_argument("--reset", action='store_true', help="To reset user credentials")
    createordelete.add_argument("--create_or_reset", action='store_true', help="To create or reset credentials")
    parser.add_argument('--user', dest='user', help='Provide your user name, example: username_sa', required=True)
    serverorenv = parser.add_mutually_exclusive_group(required=True)
    serverorenv.add_argument('--environment', dest='env',
                             choices=['prod', 'qa', 'uat', 'dev', 'all', 'PROD', 'QA', 'UAT', 'DEV', 'ALL'],
                             help='Enter the environment name, example : prod/qa/uat/dev/all')
    serverorenv.add_argument('--server', dest='server', help='Provide the server alias name, example: marsdbpg1a')
    return parser.parse_args()


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def sql_connect():
    """
    Connect to DBMONITOR SQL Server
    """
    try:
        conn_sql_dest = pyodbc.connect('DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor5b.win.ia55.net;APP=PGSQL;')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        print("Error while creating database connection to DBMONITOR server {}, trying again".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def connect(hostname,username,passw):
    # create a connection to postgresql database and return the connection and cursor object
    try:
        conn_dest = psycopg2.connect(host=hostname, user=username, password=passw, dbname='postgres',sslmode="require")
        cur_dest = conn_dest.cursor()
        conn_dest.autocommit = True
        return cur_dest, conn_dest
    except Exception as e:
        print("Error while creating database connection to "+hostname+" using user: "+username)
        raise Exception("Error while creating database connection to " + hostname + " using user: " + username)


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_user_password(vaultpath,user):
    vault_path = "http://vault.ia55.net/v1{}/{}".format(vaultpath,user)
    try:
        response = requests.get(vault_path,auth=HTTPKerberosAuth())
        if response:
            user_pass = response.json()['data'][user]
            return user_pass
        else:
            logger.error("Failed to retrieve credentials from {} with error {}, trying again".format(vault_path, response.content))
            raise Exception("Failed to retrieve credentials from {} with error {}, trying again".format(vault_path, response.content))
    except Exception as e:
        logger.error("Failed to retrieve credentials from vault path {} with error {}, trying again".format(vault_path, str(e)))
        raise Exception("Failed to retrieve credentials from vault path {} with error {}".format(vault_path, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_user_password(pod,destination_instance,username,password):
    vault_path = "/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(pod, destination_instance,username)
    try:
        vaultpath_req = "http://vault.ia55.net/v1"+vault_path
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), data=json.dumps({username: password}))
        if response:
            logger.info("Credentials written successfully to {}".format(vault_path))
        else:
            logger.error("Failed to write credentials to {} with error {}, trying again".format(vault_path,response.content))
            raise Exception("Failed to write credentials to {} with error {}, trying again".format(vault_path,response.content))
    except Exception as e:
        logger.error("Failed to write credentials to {} with error {}, trying again".format(vault_path, str(e)))
        raise Exception("Failed to write credentials to {} with error {}, trying again".format(vault_path, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def delete_user_password(pod,destination_instance,username):
    vault_path = "/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(pod, destination_instance,username)
    try:
        vaultpath_req = "http://vault.ia55.net/v1"+vault_path
        response = requests.delete(vaultpath_req, auth=HTTPKerberosAuth())
        if response:
            logger.info("Credentials deleted successfully from {}".format(vault_path))
        else:
            logger.error("Failed to delete credentials from {} with error {}, trying again".format(vault_path,response.content))
            raise Exception("Failed to delete credentials from {} with error {}, trying again".format(vault_path,response.content))
    except Exception as e:
        logger.error("Failed to delete credentials from {} with error {}, trying again".format(vault_path, str(e)))
        raise Exception("Failed to delete credentials from {} with error {}, trying again".format(vault_path, str(e)))


def main():
    args = parse_arguments()
    user = args.user
    env = str(args.env).upper()
    srv = args.server
    if args.create:
        cmd = 'CREATE'
    if args.reset:
        cmd = 'RESET'
    if args.delete:
        cmd = 'DELETE'
    if args.create_or_reset:
        cmd = 'CREATE'

    logfile = '/g/dba/rds/logfiles/error_{}.log'.format(str(args.user))
    global logger
    logger = setup_logging(logfile=logfile)
    # Get list of instances , create users in that instance and grant sa to the user
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users', 'sa')
    pass_length = 32
    date_t = format(datetime.now().strftime("%d-%m-%Y-%H-%M-%S"))
    logged_in_user = os.getlogin()+"_sa"

    if env == 'ALL':
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and pod!='TEST' and Alias is not null and IsActive=1"
    elif srv:
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and IsActive=1 and pod!='TEST' and Alias =('" + str(srv).lower() + "')"
    else:
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and IsActive=1 and pod!='TEST' and Alias is not null and upper(Env) in ('{}')".format(env)

    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    if cur_sql_dest.rowcount == 0:
        print("Wrong server name")
        sys.exit(1)
    result = cur_sql_dest.fetchall()
    if cmd == 'CREATE' and str(user).lower() == logged_in_user:
        print('Creating the user ' + user + '.........')
        content = "Please copy the below content to .pgpass file in your home directory"
        content = content + "\n"
        print(" ")
    elif cmd == 'RESET' and str(user).lower() == logged_in_user:
        print('Resetting the password for user ' + user + '.........')
        content = "Please copy the below content to .pgpass file in your home directory"
        content = content + "\n"
        print(" ")
    elif cmd == 'DELETE':
        content = 'Deleting the user {} .........'.format(user)
    else:
        logger.error(
            "{} : Please enter the user name as {}. You are allowed to create reset "
            "your own admin user account only".format(date_t, logged_in_user))
        print("{} : Please enter the user name as {}. You are allowed to create reset "
              "your own admin user account only".format(date_t, logged_in_user))
        sys.exit(1)
    for row in result:
        cur, conn = connect(row.host,'sa',sa_pass)
        x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(pass_length))
        podname = row.pod
        instance = row.instancename
        cur.execute("select 1 from pg_roles where rolname = '{}'".format(user))
        if cur.rowcount != 0:
            user_exists = cur.fetchone()[0]
        else:
            user_exists = 0
        if cmd == 'CREATE':
            if user_exists == 0:
                cur.execute("create user  {}  password '{}' CREATEDB CREATEROLE".format(user, x))
                cur.execute("select count(*) from pg_roles where rolname='db_owner'")
                if cur.fetchone()[0] == 0:
                    cur.execute("create role db_owner")
                cur.execute("grant db_owner to {}".format(user))
                cur.execute("grant sa,rds_superuser to {} WITH ADMIN OPTION".format(user))
                print("creating user {} in instnace {}".format(user,row.host))
                content = content + '\n'
                content = content + row.host + ':*:*:' + user + ':' + x
                write_user_password(podname, instance, user, x)
            if user_exists == 1:
                cur.execute("alter user {} password '{}' createdb createrole".format(user, x))
                cur.execute("grant sa to {}".format(user))
                print("user already exists, resetting user {} in instance {}".format(user, row.host))
                content = content + '\n'
                content = content + row.host + ':*:*:' + user + ':' + x
                write_user_password(podname, instance, user, x)
        if cmd == 'RESET':
            if user_exists == 1:
                cur.execute("alter user {} password '{}' createdb createrole".format(user, x))
                cur.execute('grant sa to ' + user)
                print("user already exists, resetting user {} in instance {}".format(user, row.host))
                content = content + row.host + ':*:*:' + user + ':' + x
                content = content + '\n'
                write_user_password(podname, instance, user, x)
            else:
                print("user not exists, creating user {} in instance {}".format(user, row.host))
                cur.execute('create user ' + user + ' password \'' + x + '\' CREATEDB CREATEROLE')
                cur.execute('grant sa,rds_superuser to ' + user + ' WITH ADMIN OPTION')
                cur.execute("select count(*) from pg_roles where rolname='db_owner'")
                if cur.fetchone()[0] == 0:
                    cur.execute("create role db_owner")
                cur.execute("grant db_owner to {}".format(user))
                content = content + row.host + ':*:*:' + user + ':' + x
                content = content + '\n'
                open(os.devnull, 'w')
                write_user_password(podname, instance, user, x)
        if cmd == 'DELETE':
            if user_exists == 1:
                print("dropping user {} in instance {}".format(user, row.host))
                cur.execute('drop user IF EXISTS ' + user)
                open(os.devnull, 'w')
                delete_user_password(podname, instance, user)
                print("dropped user {} from instance {}".format(user, row.host))
            else:
                print('The user ' + user + ' does not exists in {}'.format(row.host))
        conn.commit()
        conn.close()
    print("************************************************************************************************** \n")
    content = "\n\n"+content
    print(content)
    print(" ")


if __name__ == "__main__":
    main()
