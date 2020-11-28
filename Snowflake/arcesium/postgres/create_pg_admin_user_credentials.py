#!/usr/bin/env python
import random, time
import string
import sys
import psycopg2
import pyodbc
import argparse
import subprocess
import os
import textwrap
from subprocess import PIPE
from datetime import datetime

DB_RETRY_COUNT = 10
DB_WAIT_TIME   = 10


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


def sql_connect():
    """
    PURPOSE:
        Create connection to DBMONITOR
    RETURNS:
        Returns connection and cursor
    """
    retry_count = 0
    while retry_count < DB_RETRY_COUNT:
        try:
            conn_sql_dest = pyodbc.connect(
                'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;'
                'ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=Snowflake;')
            cur_sql_dest = conn_sql_dest.cursor()
            conn_sql_dest.autocommit = True
            return cur_sql_dest, conn_sql_dest
        except Exception as e:
            print("Error while creating database connection to DBMONITOR server {}".format(str(e)))
            retry_count += 1
            time.sleep(DB_WAIT_TIME)
            print("trying again to connect to DBMONITOR, re-try count : {}".format(retry_count))
            raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def get_pg_sa_connect(server,sa_pass):
    """
    This method is to connect to PostgreSSQL
    """
    retry_count = 0
    DB_RETRY_COUNT = 2
    while retry_count < DB_RETRY_COUNT:
        try:
            conn = psycopg2.connect(host=server, user='sa', password=sa_pass, dbname='postgres', sslmode='require')
            cursor = conn.cursor()
            conn.autocommit = True
            return cursor, conn
        except Exception as e:
            print("Error {} while creating database connection to server {}".format(str(e),server))
            retry_count += 1
            time.sleep(DB_WAIT_TIME)
            print("trying again to connect to server {}, re-try count : {}".format(server, retry_count))
    return 1, 1


def get_sa_user_password():
    """
    PURPOSE:
        Read secret from vault. It is expected that vault read may fail,
        so retry for 10 times with delay of 10 sec in each run.
    """
    vaultpath = '/secret/default/v1/db-postgres-credentials/dba_users/sa'
    retry_count = 0
    try:
        while retry_count <= 10:
            command = "vault read -field=sa {}".format(vaultpath)
            pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            # initial password string i_pass
            i_pass, error = pipes.communicate()
            if pipes.returncode == 0 or pipes.returncode == 2:
                password = i_pass.decode('utf-8')
                command = "echo '{}' | grep -v 'Could not get working directory' | tr -d '\\n'".format(str(password))
                pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                password, err = pipes.communicate()
                return str(password.decode('utf-8'))
            else:
                print(
                    "Error while reading vault path {},reading again : {} attempt".format(vaultpath, retry_count))
                time.sleep(10)
                retry_count = retry_count + 1
                continue
        return 1
    except Exception as e:
        print("Exception while reading from vault {}".format(str(e)))
        print("Failed to read secret from vault : {} with error : {}".format(vaultpath, e))
        raise Exception("Failed to read secret from vault : {} with error : {}".format(vaultpath, e))


def write_secret_to_vault(vaultpath,secret,user):
    """
    PURPOSE:
        Write secret to vault, It is expected that vault write may fail,
        so retry for 10 times with delay of 10 sec in each run.
    INPUTS:
        vaultpath, secret
    """
    try:
        # Retry count variable
        retry_count = 0
        # error variable to store error message
        error = ''
        while retry_count <= 10:
            command = "vault write {} {}=\'{}\'".format(vaultpath, user, secret)
            writetovault = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            (output, error) = writetovault.communicate()
            if writetovault.returncode == 0:
                return
            else:
                retry_count = retry_count + 1
                time.sleep(10)
        print("Error occurred while writing to vault {}, error : {}".format(vaultpath, str(error)))
        exit(1)
    except Exception as e:
        print("Failed to write secret to vault : {} with error : {}".format(vaultpath, e))
        print("Exception while writing to vault {}".format(str(e)))
        raise Exception("Failed to write secret to vault : {} with error : {}".format(vaultpath, e))


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

    # Get list of instances , create users in that instance and grant sa to the user
    sa_pass = get_sa_user_password()
    pass_length = 32
    date_t = format(datetime.now().strftime("%d-%m-%Y-%H-%M-%S"))

    command = "pstree -lu -s $$ | grep --max-count=1 -o '([^)]*)' | head -n 1 | tr -d '()'"
    process = subprocess.Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    logged_in_user = str(stdout).rstrip("\n\r") + "_sa"

    if env == 'ALL':
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and pod!='TEST' and Alias is not null"
    elif srv:
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and pod!='TEST' and Alias =('" + str(srv).lower() + "')"
    else:
        query = "select pod,Alias as instancename,lower(host) as host from  dbainfra.dbo.database_server_inventory " \
                "where ServerType='PGDB' and pod!='TEST' and Alias is not null and upper(Env) in ('{}')".format(env)

    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    if cur_sql_dest.rowcount == 0:
        print("Wrong server name")
        sys.exit(1)
    result = cur_sql_dest.fetchall()
    file_obj = open('/g/dba/rds/logfiles/error_' + str(args.user) + '.log', 'a')
    if cmd == 'CREATE' and str(user) == logged_in_user:
        print('Creating the user ' + user + '.........')
        content = "Please copy the below content to .pgpass file in your home directory"
        content = content + "\n"
        print(" ")
    elif cmd == 'RESET' and str(user) == logged_in_user:
        print('Resetting the password for user ' + user + '.........')
        content = "Please copy the below content to .pgpass file in your home directory"
        content = content + "\n"
        print(" ")
    elif cmd == 'DELETE':
        content = 'Deleting the user {} .........'.format(user)
    else:
        file_obj.write(
            "{} : Please enter the user name as {}. You are allowed to create reset "
            "your own admin user account only".format(date_t, logged_in_user))
        print("{} : Please enter the user name as {}. You are allowed to create reset "
              "your own admin user account only".format(date_t, logged_in_user))
        sys.exit(1)
    for row in result:
        cur, conn = get_pg_sa_connect(row.host, sa_pass)
        if cur == 1:
            continue
        x = ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(pass_length))
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
                FNULL = open(os.devnull, 'w')
                write_secret_to_vault("/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(podname,instance,user),x,user)
            if user_exists == 1:
                cur.execute("alter user {} password '{}' createdb createrole".format(user, x))
                cur.execute("grant sa to {}".format(user))
                print("user already exists, resetting user {} in instance {}".format(user, row.host))
                content = content + '\n'
                content = content + row.host + ':*:*:' + user + ':' + x
                FNULL = open(os.devnull, 'w')
                write_secret_to_vault("/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(podname, instance, user),x,user)
        if cmd == 'RESET':
            if user_exists == 1:
                cur.execute("alter user {} password '{}' createdb createrole".format(user, x))
                cur.execute('grant sa to ' + user)
                print("user already exists, resetting user {} in instance {}".format(user, row.host))
                content = content + row.host + ':*:*:' + user + ':' + x
                content = content + '\n'
                FNULL = open(os.devnull, 'w')
                write_secret_to_vault("/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(podname, instance, user),x,user)
            else:
                # print('The user ' + user + ' does not exists. creating the user')
                print("user not exists, creating user {} in instance {}".format(user, row.host))
                cur.execute('create user ' + user + ' password \'' + x + '\' CREATEDB CREATEROLE')
                cur.execute('grant sa,rds_superuser to ' + user + ' WITH ADMIN OPTION')
                cur.execute("select count(*) from pg_roles where rolname='db_owner'")
                if cur.fetchone()[0] == 0:
                    cur.execute("create role db_owner")
                cur.execute("grant db_owner to {}".format(user))
                content = content + row.host + ':*:*:' + user + ':' + x
                content = content + '\n'
                FNULL = open(os.devnull, 'w')
                write_secret_to_vault("/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(podname, instance, user),x,user)
        if cmd == 'DELETE':
            if user_exists == 1:
                print("dropping user {} in instance {}".format(user, row.host))
                cur.execute('drop user IF EXISTS ' + user)
                FNULL = open(os.devnull, 'w')
                subprocess.Popen(['vault delete /secret/default/v1/db-postgres-credentials/password/%s/%s/%s' % (
                    podname, instance, user)], shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                content = content + 'dropping user {} from {}'.format(user,row.host)
                content = content + '\n'
            else:
                print('The user ' + user + ' does not exists in {}'.format(row.host))
        conn.commit()
        conn.close()
    file_obj.close()
    print("************************************************************************************************** \n")
    content = "\n\n"+content
    print(content)
    print(" ")
    print("Please check /g/dba/rds/logfiles/error_" + str(args.user) + ".log for any errors")


if __name__ == "__main__":
    main()
