#!/usr/bin/env python2

import argparse
import logging
import random
import string
import sys
import time
import requests
from requests_kerberos import HTTPKerberosAuth
import json

import arcesium.infra.boto as arcboto
import boto3
import psycopg2
import pyodbc
from botocore.exceptions import ClientError
from botocore.config import Config
from retrying import retry

config = Config(
    retries=dict(
        max_attempts=20
    )
)

logger = logging.getLogger('pgsql-passwords')


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
    parser.add_argument('--account-name', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)

    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the instance creation")
    parser.add_argument('--destination-instance', dest='destination_instance', default='none',
                        help='Give the name for the destination instance you want to create', required=False)
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    return parser.parse_args()


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_sa_user_password():
    try:
        response = requests.get('http://vault.ia55.net/v1/secret/default/v1/db-postgres-credentials/dba_users/sa',auth=HTTPKerberosAuth())
        if response:
            sa_pass = response.json()['data']['sa']
            return sa_pass
        else:
            logger.error("Failed to retrive credentials from /secret/default/v1/db-postgres-credentials/dba_users/sa with error {}, trying again".format(response.content))
            raise Exception("Failed to retrive credentials from /secret/default/v1/db-postgres-credentials/dba_users/sa with error {}".format(response.content))
    except Exception as e:
        logger.error("Failed to retrieve credentials from vault path /secret/default/v1/db-postgres-credentials/dba_users/sa with error {}, trying again".format(str(e)))
        raise Exception("Failed to retrieve credentials from vault path /secret/default/v1/db-postgres-credentials/dba_users/sa with error {}".format(str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_dba_user_password(pod,destination_instance,username,password):
    try:
        vaultpath_req = "http://vault.ia55.net/v1/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(pod,destination_instance,username)
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), data=json.dumps({username: password}))
        if response:
            logger.info("Credentials written successfully to /secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(pod,destination_instance,username))
        else:
            logger.error("Failed to write credentials to /secret/default/v1/db-postgres-credentials/password/{}/{}/{} with error {}, trying again".format(pod,destination_instance,username,response.content))
            raise Exception("Failed to write credentials to /secret/default/v1/db-postgres-credentials/password/{}/{}/{} with error {}".format(pod,destination_instance,username,response.content))
    except Exception as e:
        logger.error("Failed to write credentials to /secret/default/v1/db-postgres-credentials/password/{}/{}/{} with error {}, trying again".format(pod, destination_instance, username, str(e)))
        raise Exception("Failed to write credentials to /secret/default/v1/db-postgres-credentials/password/{}/{}/{} with error {}".format(pod, destination_instance, username, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_app_user_password(vaultpath,password):
    try:
        vaultpath_req = "http://vault.ia55.net/v1{}".format(vaultpath)
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), data=json.dumps({'secret': password}))
        if response:
            logger.info("Credentials written successfully to {}".format(vaultpath))
        else:
            logger.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
    except Exception as e:
        logger.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath,str(e)))
        raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath,str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_app_user_password(vaultpath):
    try:
        vaultpath_req = "http://vault.ia55.net/v1{}".format(vaultpath)
        response = requests.get(vaultpath_req,auth=HTTPKerberosAuth())
        if response:
            passwd = response.json()['data']['secret']
            return passwd
        else:
            logger.error("Failed to retrieve credentials from {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to retrieve credentials from {} with error {}".format(vaultpath,response.content))
    except Exception as e:
        logger.error("Failed to retrive credentials from {} with error {}, trying again".format(vaultpath,str(e)))
        raise Exception("Failed to retrive credentials from {} with error {}".format(vaultpath, str(e)))


def get_rds_ec2_kms_clients(account, region):
    try:
        arcboto.install()
        session = boto3.session.Session(profile_name='{}/dba'.format(account))
        rds = session.client('rds', region_name='{}'.format(region), config=config)
        ec2 = session.client('ec2', region_name='{}'.format(region), config=config)
        kms = session.client('kms', region_name='{}'.format(region), config=config)
        return rds, ec2, kms
    except ClientError as e:
        logger.error('exception while fetching boto3 connection', e.response['Error']['Code'])
        sys.exit(1)


def change_store_passwords(rds, pod, destination_instance, dry_run):
    # function to change the passwords of all db users in RDS instance and store in vault
    logger.info("Creating inventory connection for vault locations")
    cur_sql_dest, conn_sql_dest = sql_connect()
    logger.info("Successfully created inventory connection")
    destination_endpoint = \
    rds.describe_db_instances(DBInstanceIdentifier=destination_instance)['DBInstances'][0]['Endpoint']['Address']
    sa_pass = get_sa_user_password()
    conn_pgsql = psycopg2.connect(host=destination_endpoint, user='sa', password=sa_pass, dbname='postgres')
    conn_pgsql.autocommit = True
    pass_length = 32
    cur_pgsql = conn_pgsql.cursor()
    cur_pgsql.execute("select usename from pg_user where usename not in ('rdsadmin','sa','rdsrepladmin') order by usename")
    result = cur_pgsql.fetchall()
    for row in result:
        x = ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(pass_length))
        query = "alter user \"" + row[0] + "\" password \'" + x + "\'"
        cur_pgsql.execute(query)
        logger.info("setting password for user {}".format(row[0]))
        conn_pgsql.commit()
        query_sql = "select vaultpath from dbainfra.dbo.pg_vault_path where username = '" + row[0] + "'"
        cur_sql_dest.execute(query_sql)
        result = cur_sql_dest.fetchall()
        if result:
            for vpath in result:
                path = str(vpath[0]).replace("$MACHINE_POD", pod)
                try:
                    # writing to application vault
                    write_app_user_password(path,x)
                    logger.info("Verifying the user {} password by reading from vault path {}".format(row[0],path))
                    logger.info("Retriving the password from vault path {}".format(path))
                    user_password = get_app_user_password(path)
                    # Checking database connection
                    app_user_conn  = psycopg2.connect(host=destination_endpoint, user=row[0], password=user_password, dbname='postgres')
                    app_user_cur   = app_user_conn.cursor()
                    app_user_cur.execute("select 1")
                    app_user_res   = app_user_cur.fetchall()
                    if app_user_res[0][0] == 1:
                        logger.info("Password verification successful for user {} vault path {}".format(row[0],path))
                        app_user_conn.close()
                    else:
                        logger.info("Password verification failed for user {} vault path {}".format(row[0],path))
                        app_user_conn.close()
                        sys.exit(1)
                    time.sleep(5)
                except Exception as e:
                    logger.error("error occured while writing to vault, error : {}".format(str(e)))
                    sys.exit(1)
        # writing to dba vault
        write_dba_user_password(pod,destination_instance,row[0],x)
        time.sleep(5)
    conn_sql_dest.close()
    conn_pgsql.close()


def clean_vault(pod):
    # function to clean vault credentials of all users
    cur_sql_dest, conn_sql_dest = sql_connect()
    query_sql = "select vaultpath from dbainfra.dbo.pg_vault_path where vaultpath is not null or vaultpath != ''"
    cur_sql_dest.execute(query_sql)
    result = cur_sql_dest.fetchall()
    if result:
        for vpath in result:
            path = str(vpath[0]).replace("$MACHINE_POD", pod)
            write_app_user_password(path, '')
    conn_sql_dest.close()


def main():
    # Get the user inputs
    args = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    pod = args.pod
    dryrun = args.dry_run
    instance_action = ''
    destination_region = args.region
    destination_account = args.account_name

    if args.create:
        instance_action = 'create'
    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '
    else:
        dry_run = ''

    # defining the destination instance
    if args.destination_instance != 'none':
        destination_instance = args.destination_instance
    else:
        destination_instance = pod + 'dbpg1'

    if instance_action == 'create':
        rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
        logger.info("Started setting passwords for all database users")
        change_store_passwords(rds, pod, destination_instance, dry_run)
    if instance_action == 'delete':
        clean_vault(pod)


if __name__ == "__main__":
    main()
