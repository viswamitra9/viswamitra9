# Owner       : Srinivasarao Oguri
# Description : This is an utility program used to manage snowflake
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from smtpd import COMMASPACE
from email.mime.base import MIMEBase
import os
import email.encoders as Encoders
import smtplib

import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import logging
import json
import sys
sys.path.append('/g/dba/snowflake')
import pyodbc
import time
import datetime
from dateutil.relativedelta import relativedelta

from tabulate import tabulate

import vaultutil

# packages for radar alert
from arcesium.radar.client import SendAlertRequest
from arcesium.radar.client import RadarService


logger = logging.getLogger()

# type of users allowed to create
USER_TYPE   = ['app', 'third_party_app', 'customer', 'trm', 'temporary', 'app_team', 'dba']
# vault paths for app and other users
APP_VAULT   = "/secret/v2/$APPNAME/$POD/db/snowflake/$DBNAME/$USERNAME"
OTHER_VAULT = "/secret/v2/snowflake/$POD/db/$USERNAME"
# parameters for client users
C_LOCK_TIMEOUT      = 43200
C_STATEMENT_TIMEOUT = 172800
# parameters for application
APP_LOCK_TIMEOUT      = 900
APP_STATEMENT_TIMEOUT = 900
# SQL database connection retry in case of failures
DB_WAIT_TIME     = 60
DB_RETRY_COUNT   = 5
# hosts for network policy
ALLOWED_HOSTS    = "'125.18.12.160/28', '115.112.81.240/28','10.12.0.0/17','149.77.95.64/29','100.64.0.0/17','100.80.0.0/19','10.12.152.0/21','149.77.95.16/26'"
RESTRICTED_HOSTS = "'54.172.224.181','54.174.16.130'"
# warehouse usage alerting
DEFAULT_WAREHOUSE_CREDIT_LIMIT = 100
"""
cost for business critical edition , refer to https://www.snowflake.com/pricing/ for more details. We are using business
critical edition so for warehouses $4/credit, for storage $40/TB on demand storage.
"""
WAREHOUSE_COST = 4
STORAGE_COST   = 40


def setup_logging(logfile):
    """
    Args:
        logfile: logfile where to write the information or errors
    Returns:
        configure the error logging file to write the errors or information
    """
    print("Please check the logfile {} for details".format(logfile))
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
    return logger


def raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description):
    """
    PURPOSE:
        raise a radar alert when a database backup is failed
    Returns:
    """
    from arcesium.radar.client import SendAlertRequest
    from arcesium.radar.client import RadarService
    request = SendAlertRequest()
    request.alert_source = alert_source
    request.alert_class = alert_class
    request.alert_severity = alert_severity
    request.alert_key = alert_key
    request.alert_summary = alert_summary
    request.alert_description = alert_description
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


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
            logger.error("Error while creating database connection to DBMONITOR server {}".format(str(e)))
            retry_count += 1
            time.sleep(DB_WAIT_TIME)
            logger.info("trying again to connect to DBMONITOR, re-try count : {}".format(retry_count))
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
    retry_count = 0
    while retry_count < DB_RETRY_COUNT:
        try:
            connection = snowflake.connector.connect(
                account=account,
                user=username,
                password=password,
                insecure_mode=True
            )
            cursor = connection.cursor()
            connection.autocommit(True)
            return connection, cursor
        except Exception as e:
            logger.error("Failed to create connection to account : {} with error {}".format(account, e))
            retry_count += 1
            time.sleep(DB_WAIT_TIME)
            logger.info("trying again to connect to the account {}, re-try count : {}".format(account, retry_count))
    raise Exception("Failed to create connection to account : {} with error {}".format(account, e))


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
    try:
        password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        password = json.loads(password)['password']
        connection, cursor = get_snowflake_connection(account=account, password=password, username='sa')
        cursor.execute("create database if not exists audit_archive")
        cursor.execute("use database audit_archive")
        cursor.execute("use schema public")
        logger.info("Checking for dba warehouse and create it if not exists")
        cursor.execute("create warehouse if not exists DBA_WH with WAREHOUSE_SIZE=small")
        cursor.execute("use role accountadmin")
        cursor.execute("use warehouse DBA_WH")
        return connection, cursor
    except Exception as e:
        logger.error("error: {} encountered while creating admin connection to account : {}".format(str(e), account))
        raise Exception("Failed to create super user connection to account : {} with error {}".format(account, str(e)))


def create_database(account, dbname, pod):
    """
    PURPOSE:
        this function create the database in given account with two default roles for the database
        database_reader : Has read permissions on the database
        database_owner  : Has all permissions on the database
    Args:
        account: ex: ama69523.us-east-1.privatelink
        dbname:  ex: arcesium_data_warehouse
        pod:  ex: shared-dev
    Returns:
       null
    """
    try:
        logger.info("Creating super user connection")
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection")
        cursor.execute("use role accountadmin")
        cursor.execute("create database if not exists {}".format(dbname))
        cursor.execute("create role if not exists {}_reader".format(dbname))
        cursor.execute("create role if not exists {}_owner".format(dbname))
        # this role is only for trm team
        cursor.execute("use database {}".format(dbname))
        logger.info("DB roles are created")
        # Every Snowflake account has storage integration created, granting usage permissions on it to db roles
        logger.info("Giving permissions on storage integration to default database roles")
        cursor.execute("grant usage on integration s3_{}_integration to role {}_owner".format(pod,dbname))
        cursor.execute("grant usage on integration s3_{}_integration to role {}_reader".format(pod,dbname))
        cursor.execute("grant usage on integration s3_{}_integration to role trm_role".format(pod))
        logger.info("permissions on storage integration is granted to newly created db roles")
        # database related roles are created, granting permissions to owner role
        cursor.execute("grant all on database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all schemas in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future schemas in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all tables in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future tables in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all stages in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future stages in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all file formats in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future file formats in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all views in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future views in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all MATERIALIZED VIEWS in database {} to role {}_owner;".format(dbname, dbname))
        cursor.execute("grant all on future MATERIALIZED VIEWS in database {} to role {}_owner;".format(dbname, dbname))
        cursor.execute("grant all on all functions in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future functions in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all procedures in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future procedures in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all sequences in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future sequences in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on all EXTERNAL TABLES in database {} to role {}_owner".format(dbname, dbname))
        cursor.execute("grant all on future EXTERNAL TABLES in database {} to role {}_owner".format(dbname, dbname))
        # granting permissions to reader role
        cursor.execute("grant usage on database {} to {}_reader".format(dbname,dbname))
        cursor.execute("grant usage on all schemas in database {} to role {}_reader".format(dbname,dbname))
        cursor.execute("grant usage on future schemas in database {} to role {}_reader".format(dbname,dbname))
        cursor.execute("grant select on all tables in database {} to role {}_reader".format(dbname,dbname))
        cursor.execute("grant select on future tables in database {} to role {}_reader".format(dbname,dbname))
        cursor.execute("grant read on all stages in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant read on future stages in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant usage on all file formats in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant usage on future file formats in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant select on all views in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant select on future views in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant select on all MATERIALIZED VIEWS in database {} "
                       "to role {}_reader;".format(dbname, dbname))
        cursor.execute("grant select on future MATERIALIZED VIEWS in database {} "
                       "to role {}_reader;".format(dbname, dbname))
        cursor.execute("grant usage on all functions in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant usage on future functions in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant usage on all procedures in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant usage on future procedures in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant select on all EXTERNAL TABLES in database {} to role {}_reader".format(dbname, dbname))
        cursor.execute("grant select on future EXTERNAL TABLES in database {} to role {}_reader".format(dbname, dbname))
        # grant access on database along with grant permission and create share permission to trm user
        cursor.execute("grant all on database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all schemas in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future schemas in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all tables in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future tables in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all views in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future views in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all MATERIALIZED VIEWS in database {} "
                       "to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future MATERIALIZED VIEWS in database {} "
                       "to role trm_role with grant option".format(dbname, dbname))
        cursor.execute("grant all on all EXTERNAL TABLES in database {} "
                       "to role trm_role with grant option".format(dbname, dbname))
        cursor.execute("grant all on future EXTERNAL TABLES in database {} "
                       "to role trm_role with grant option".format(dbname, dbname))
        cursor.execute("grant all on all stages in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future stages in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all file formats in database {} to role "
                       "trm_role with grant option".format(dbname))
        cursor.execute("grant all on future file formats in database {} to role "
                       "trm_role with grant option".format(dbname))
        cursor.execute("grant all on all functions in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future functions in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on all procedures in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future procedures in database {} to role trm_role "
                       "with grant option".format(dbname))
        cursor.execute("grant all on all sequences in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant all on future sequences in database {} to role trm_role with grant option".format(dbname))
        cursor.execute("grant create share on account to role trm_role")
        # granting default database roles to account admin
        cursor.execute("grant role {}_reader to role accountadmin".format(dbname))
        cursor.execute("grant role {}_owner to role accountadmin".format(dbname))
        cursor.execute("grant role trm_role to role accountadmin".format(dbname))
    except Exception as e:
        logger.error("Failed to create database {} in account {} with error {}".format(dbname, account, str(e)))
        raise Exception("Failed to create database {} in account {} with error {}".format(dbname, account, str(e)))
    # release the connection
    connection.close()


def get_unique_password():
    """
    PURPOSE:
        Need to maintain the unique password for users across all snowflake accounts.
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


def create_user(account, username, pod, user_type, user_mail, logfile, dbname='arcesium_data_warehouse', **kwargs):
    """
    PURPOSE:
        create snowflake user, users are different type in Snowflake, refer to
        http://wiki.ia55.net/pages/viewpage.action?spaceKey=TECHDOCS&title=Snowflake+user+management
        This function will create a role for every user with "username_role", grant the permissions to the role
        and assign the role as default role and write password to vault. Make an entry into the DBMONITOR server.
        If the user is aready exists , it simply return with an error
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    Returns:
        returns user password
    """
    # create SQL and Snowflake connections
    sql_cur, sql_conn = sql_connect()
    connection, cursor = get_admin_connection(account, pod)
    # check the user_type is in given list
    assert user_type in USER_TYPE, "usertype should be anyone of {}".format(USER_TYPE)
    # role for every user with unique password
    user_role = "{}_role".format(username)
    db_reader = "{}_reader".format(dbname)
    db_owner  = "{}_owner".format(dbname)
    user_type = str(user_type).lower()
    # check the existence of user
    cursor.execute("SHOW USERS")
    cursor.execute("SELECT \"login_name\"  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) where lower(\"login_name\")='{}'".format(str(username).lower()))
    result = cursor.fetchall()
    print(result)
    if len(result) > 0:
        logger.error("user {} already exists in pod {}".format(username, pod))
        return
    # create user if not exists
    password = get_unique_password()
    cursor.execute("create role if not exists {}".format(user_role))
    cursor.execute("create user if not exists {} password='{}' DEFAULT_ROLE={} "
                   "EMAIL='{}'".format(username, password, user_role, user_mail))
    cursor.execute("grant role {} to user {}".format(user_role, username))
    # write password to vault and make entry into SQL server
    if user_type == 'app':
        vaultpath = APP_VAULT.replace("$POD", pod).replace("$APPNAME", kwargs['appname']) \
            .replace("$DBNAME", dbname).replace("$USERNAME", username)
        cname = "{}.snowflakecomputing.com".format(account)
        secret = {'cname': cname, 'account': account, 'password': password, 'database': dbname}
        #pdb.set_trace()
        #print(secret)
        vaultutil.write_secret_to_vault(vaultpath,json.dumps(secret))
        sql_cur.execute("insert into dbainfra.dbo.snowflake_users "
                    "(username, usertype, appname, user_mail, vaultpath, pod) values ('{}', '{}', '{}', "
                    "'{}', '{}', '{}')".format(username, user_type, kwargs['appname'], user_mail, vaultpath,pod))
    else:
        vaultpath = OTHER_VAULT.replace("$POD", pod).replace("$USERNAME", username)
        cname = "{}.snowflakecomputing.com".format(account)
        secret = {'cname': cname, 'account': account, 'password': password, 'database': dbname}
        vaultutil.write_secret_to_vault(vaultpath,json.dumps(secret))
        if user_type == 'temporary':
            sql_cur.execute(
                "insert into dbainfra.dbo.snowflake_users (username, usertype, user_retention, user_mail, "
                "vaultpath, pod) values "
                "('{}','{}',{},'{}','{}','{}')".format(username, user_type, kwargs['retention'], user_mail,
                                                       vaultpath, pod))
        else:
            sql_cur.execute(
                "insert into dbainfra.dbo.snowflake_users (username, usertype, user_mail, vaultpath, pod) "
                "values ('{}','{}','{}','{}','{}')".format(username, user_type, user_mail, vaultpath, pod))
    sql_cur.commit()
    # grant required roles to the user role
    # based on the user type grant the required permissions to the users
    if user_type == 'app':
        if 'appname' not in kwargs:
            raise Exception("appname argument is required for creation of application user")
        cursor.execute("grant role {} to role {}".format(db_owner, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # create third party application user
    if user_type == 'third_party_app':
        if username == 'looker_user':
            cursor.execute("create schema if not exists looker_scratch")
            cursor.execute("grant all on schema looker_scratch to role {}".format(user_role))
        cursor.execute("grant role {} to role {}".format(db_reader, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # create customer user
    if user_type == 'customer':
        cursor.execute("grant role {} to role {}".format(db_reader, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
        # set default values for parameters for customer user
        cursor.execute("alter user {} set lock_timeout = {}".format(username, C_LOCK_TIMEOUT))
        cursor.execute("alter user {} set statement_timeout_in_seconds = {}".format(username, C_STATEMENT_TIMEOUT))
    # create trm user
    if user_type == 'trm':
        cursor.execute("grant role trm_role to role {}".format(user_role))
    if user_type == 'dba':
        cursor.execute("grant role accountadmin to role {}".format(user_role))
    # create temporary user
    if user_type == 'temporary':
        if 'retention' not in kwargs:
            raise Exception("retention argument is required for temporary users")
        cursor.execute("grant role {} to role {}".format(db_reader, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
        cursor.execute("alter user {} set DAYS_TO_EXPIRY  = {}".format(username, kwargs['retention']))
    # create user for app_team
    if user_type == 'app_team':
        sql_cur.execute("select lower(env) from dbainfra.dbo.database_server_inventory "
                        "where lower(pod)='{}' and lower(servertype)='snowflake'".format(str(pod).lower()))
        result = sql_cur.fetchall()
        for i in result:
            env = i[0]
        if env not in ['dev', 'qa']:
            cursor.execute("drop role {}".format(user_role))
            cursor.execute("drop user {}".format(username))
            raise Exception("application team(human) users are not created in prod or uat environment, "
                            "create temporary users")
        cursor.execute("grant role {} to role {}".format(db_owner, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # release the resources
    connection.close()
    verify_user_permissions(account, username, pod)
    send_user_creation_email_to_user(account, pod, user_mail, password, user_type, username, logfile)
    logger.info("Successfully sent email to the user about user creation")


def reset_user_password(account, username, pod):
    """
    PURPOSE:
        reset user password and write to vault and return new password
    INPUTS:
        account (account.<region>.privatelink, username, pod)
    Returns:
        new password
    """
    logger.info("Creating super user connection to account {}".format(account))
    try:
        # Check the entry for the user in database inventory
        sql_cur, sql_conn = sql_connect()
        sql_cur.execute("select vaultpath,usertype,user_mail from dbainfra.dbo.snowflake_users "
                        "where username = '{}' and pod = '{}'".format(username, pod))
        result = sql_cur.fetchall()
        if not result:
            raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
        # if entry is there then proceed and reset the password
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Resetting password for user {} in pod {}".format(username, pod))
        cursor.execute("alter user {} set password = '{}' must_change_password=False".format(username, password))
        logger.info("Password reset completed for user {} in pod {}".format(username, pod))
        # write the password to vault
        for i in result:
            vaultpath  = i[0]
            user_type  = i[1]
            user_mail  = i[2]
            logger.info("writing user {} password to vault path {}".format(username, vaultpath))
            cname     = "{}.snowflakecomputing.com".format(account)
            dbname    = json.loads(vaultutil.get_user_password(vaultpath))['database']
            secret    = {'cname': cname, 'account': account, 'password': password, 'database': dbname}
            vaultutil.write_secret_to_vault(vaultpath, json.dumps(secret))
            logger.info("Successfully wrote user {} password to vault path {}".format(username, vaultpath))
            # Send mail notification to the user
            logger.info("Sending email to the user about password reset")
            send_passwrod_reset_email_to_user(account, pod, user_mail, password, user_type, username)
            logger.info("Successfully sent email to the user about password reset")
    except Exception as e:
        logger.error("error while user password reset, error : {}".format(str(e)))
        raise Exception("Failed to reset the user {} password in account {}".format(username, account))
    finally:
        # release the database connections
        sql_conn.commit()
        connection.close()
        sql_conn.close()


def drop_user(account, username, pod):
    """
    PURPOSE:
        drop user from snowflake account and delete his vault entry
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    try:
        logger.info("Creating super user connection to account {}".format(account))
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        logger.info("Dropping user {} from account {}".format(username,account))
        cursor.execute("drop user if exists {}".format(username))
        cursor.execute("drop role if exists {}_role".format(username))
        logger.info("user {} dropped from pod {}".format(username, pod))
        # delete the vault entry
        sql_cur, sql_conn = sql_connect()
        sql_cur.execute("select vaultpath from dbainfra.dbo.snowflake_users "
                        "where username = '{}' and pod = '{}'".format(username, pod))
        result = sql_cur.fetchall()
        if not result:
            raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
        for i in result:
            vaultpath  = i[0]
            logger.info("deleting user {} password from vault path {}".format(username, vaultpath))
            # delete the vault entry
            vaultutil.delete_secret_from_vault(vaultpath)
            logger.info("Successfully deleted user {} vault path {}".format(username, vaultpath))
            sql_cur.execute("delete from dbainfra.dbo.snowflake_users "
                            "where username = '{}' and pod = '{}'".format(username, pod))
            logger.info("Successfully deleted user {} entry "
                        "from table dbainfra.dbo.snowflake_users".format(username, vaultpath))
    except Exception as e:
        logger.error("error while deleting user, error : {}".format(str(e)))
        connection.close()
        sql_conn.close()
        raise Exception("Failed to delete user {} from account {}".format(username, account))
    sql_conn.commit()
    connection.close()
    sql_conn.close()


def prepare_account(account, region, env, pod):
    """
    Whenever a new account is procured it need to be prepared for production ready by doing.
    - delete the default users and databases created by Snowflake team
    - create default databases (ex: audit_archive) and roles (warehouse_owner, share_owner, monitoring_owner, trm_role)
    - Create default network policy and apply to the account
    - Create default admin user (sa) for the account
    Args:
        account: ex: arc1000.us-east-1.privatelink
        region: ex: us-east-1
        env: ex: dev
        pod: ex: terra
    Returns:
    """
    try:
        admin_pass = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/admin'.format(pod))
        password   = json.loads(admin_pass)['password']
        logger.info("Creating super user connection")
        connection, cursor = get_snowflake_connection(account='{}.{}.privatelink'.format(account, region),
                                                      username='admin', password=password)
        logger.info("Created super user connection")
        logger.info("Dropping unwanted users and default warehouse")
        cursor.execute("use role accountadmin")
        cursor.execute("drop user if exists MNDINI_SFC")
        cursor.execute("drop user if exists APATEL_SFC")
        cursor.execute("drop warehouse if exists COMPUTE_WH")
        cursor.execute("drop warehouse if exists LOAD_WH")
        cursor.execute("drop warehouse if exists DEMO_WH")
        cursor.execute("create warehouse if not exists DBA_WH")
        logger.info("Dropped users : MNDINI_SFC and APATEL_SFC")
        logger.info("Dropped warehouses : COMPUTE_WH,LOAD_WH and DEMO_WH")
        # create role for trm , this role will be given to users until pod is onboarded
        cursor.execute("create role if not exists trm_role")
        # create default account roles
        cursor.execute("create role if not exists warehouse_owner")
        cursor.execute("grant create warehouse on account to warehouse_owner")
        cursor.execute("create role if not exists monitoring_owner")
        cursor.execute("grant imported privileges on database snowflake to role monitoring_owner")
        cursor.execute("create role if not exists share_owner")
        cursor.execute("grant CREATE SHARE on account to role share_owner")
        # grant the roles to accountadmin
        cursor.execute("grant role warehouse_owner, monitoring_owner, share_owner, trm_role to role accountadmin")
        # grant the roles to trm_role
        cursor.execute("grant role warehouse_owner, monitoring_owner, share_owner to role trm_role")
        # creating required databases
        logger.info("Creating required databases")
        cursor.execute("create database if not exists audit_archive")
        # create default admin user for the account
        password = get_unique_password()
        logger.info("Creating sa user")
        cursor.execute("create or replace user sa password = '{}' "
                       "default_role = accountadmin MUST_CHANGE_PASSWORD=FALSE".format(password))
        cursor.execute("grant role accountadmin to user sa")
        # write password to vault
        vaultpath = "/secret/v2/snowflake/{}/db/sa".format(pod)
        cname     = "{}.{}.privatelink.snowflakecomputing.com".format(account, region)
        secret    = {'cname': cname, 'account': "{}.{}.privatelink".format(account, region),
                                'password': password, 'database': 'audit_archive'}
        vaultutil.write_secret_to_vault(vaultpath, json.dumps(secret))
        # Set default parameters for account
        cursor.execute("alter account set PERIODIC_DATA_REKEYING = TRUE")
        cursor.execute("alter account set lock_timeout = {}".format(APP_LOCK_TIMEOUT))
        cursor.execute("alter account set abort_detached_query = TRUE")
        cursor.execute("alter account set statement_timeout_in_seconds = {}".format(APP_STATEMENT_TIMEOUT))
        # if the environment is prod set the time travel period to 35 days for other environments it is default to 1
        if str(env).lower() == 'prod':
            cursor.execute("alter account set DATA_RETENTION_TIME_IN_DAYS = 35")
        # make entry into database inventory if the entry not exists
        logger.info("Making entry into database inventory")
        cur_sql_dest, conn_sql_dest = sql_connect()
        query = "select * from dbainfra.dbo.database_server_inventory" \
                " where FriendlyName='{}'".format("{}.{}.privatelink".format(account, region))
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        if len(result) == 0:
            query = "insert into dbainfra.dbo.database_server_inventory " \
                "(Tier,Dataserver,Env,Host,IsActive,Monitor,ServerType,FriendlyName,Pod,ClientDbState) " \
                "values('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".\
                format('Tier 1:<<BR>>Arcesium',cname,env,cname,1,'yes','snowflake',
                "{}.{}.privatelink".format(account, region),pod,'onboarding')
            cur_sql_dest.execute(query)
        query = "select * from dbainfra.dbo.snowflake_users where username='sa' and pod = '{}'".format(pod)
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        if result is None:
            query = "insert into dbainfra.dbo.snowflake_users values('sa','{}','admin',null,null," \
                "'dba-ops-team@arcesium.com','/secret/v2/snowflake/{}/db/sa')".format(pod, pod)
            cur_sql_dest.execute(query)
        # apply the network policy
        logger.info("Creating network policy block_public and applying to account")
        cursor.execute("CREATE OR REPLACE NETWORK POLICY block_public ALLOWED_IP_LIST=({}) "
                       "BLOCKED_IP_LIST=({})".format(ALLOWED_HOSTS, RESTRICTED_HOSTS))
        cursor.execute("alter account set network_policy = block_public")
    except Exception as e:
        logger.exception("Failed to prepare the account {} with error {}".format(str(account), str(e)))
        raise Exception("Failed to prepare the account {} with error {}".format(str(account), str(e)))
    else:
        # release the resources
        conn_sql_dest.close()
        connection.close()


def verify_user_permissions(account, username, pod):
    """
    PURPOSE:
        After creating the user check the user permissions by creating test data and confirm the permissions.
    Args:
        pod: ex terra
        appname: ex cocoa
        dbname: ex audit_archive_database
        username: ex cocoa_app
        permission: ex owner
        create_warehouse: ex y
        vaultpath: APP_VAULT_PATH
    Returns:
    """
    operations = [['Operation', 'Status']]
    cur_sql, conn_sql = sql_connect()
    cur_sql.execute("select usertype,vaultpath from dbainfra.dbo.snowflake_users "
                    "where username='{}' and pod = '{}'".format(username, pod))
    result = cur_sql.fetchall()
    if not result:
        raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
    for i in result:
        user_type      = i[0]
        vaultpath      = i[1]
    secret = vaultutil.get_user_password(vaultpath)
    password = json.loads(secret)['password']
    database = json.loads(secret)['database']
    logger.info("testing user connection and access permissions")
    # create admin connection, create a warehouse and give access to user
    logger.info("creating admin user connection")
    admin_connection, admin_cursor = get_admin_connection(account, pod)
    logger.info("created admin user connection")
    admin_cursor.execute("use database {}".format(database))
    admin_cursor.execute("create warehouse if not exists DBA_WH")
    admin_cursor.execute("grant usage on warehouse DBA_WH to role {}_role".format(username))
    # create normal user connection
    connection, cursor = get_snowflake_connection(account, username, password)
    cursor.execute("use database {}".format(database))
    cursor.execute("use warehouse DBA_WH")
    if user_type in ['app','trm','app_team']:
        try:
            cursor.execute("create schema user_permission_test")
            operations.append(["create_schema", "success"])
        except Exception as e:
            operations.append(["create_schema", "failed"])
            logger.exception(str(e))
        try:
            cursor.execute("create table user_permission_test.test_permission as select current_timestamp as time")
            operations.append(["create_table", "success"])
        except Exception as e:
            operations.append(["create_table", "failed"])
            logger.exception(str(e))
        if user_type == 'trm':
            try:
                cursor.execute("create share user_permission_share")
                cursor.execute("grant usage on database {} to share user_permission_share".format(database))
                cursor.execute("grant usage on schema {}.user_permission_test to share user_permission_share".format(database))
                cursor.execute("drop share user_permission_share")
                operations.append(["create_share", "success"])
            except Exception as e:
                logger.exception(str(e))
                operations.append(["create_share", "failed"])
        try:
            cursor.execute("drop schema user_permission_test cascade")
            operations.append(["drop_schema", "success"])
        except Exception as e:
            operations.append(["drop_schema", "failed"])
            logger.exception(str(e))
        try:
            cursor.execute("create warehouse user_permission_test_wh")
            cursor.execute("drop warehouse user_permission_test_wh")
            operations.append(["create_warehouse", "success"])
        except Exception as e:
            operations.append(["create_warehouse", "failed"])
            logger.exception(str(e))
    if user_type in ['third_party_app', 'temporary', 'customer']:
        admin_cursor.execute("create schema user_permission_test")
        admin_cursor.execute("create table user_permission_test.test_permission as select current_timestamp as time")
        try:
            cursor.execute("select * from {}.user_permission_test.test_permission".format(database))
            operations.append(["read_data", "success"])
        except Exception as e:
            operations.append(["read_data", "failed"])
            logger.exception(str(e))
        admin_cursor.execute("drop schema user_permission_test")
        try:
            cursor.execute("create warehouse user_permission_test_wh")
            cursor.execute("drop warehouse user_permission_test_wh")
            operations.append(["create_warehouse", "success"])
        except Exception as e:
            operations.append(["create_warehouse", "failed"])
            logger.exception(str(e))
    logger.info("revoking access on DBA warehouse")
    admin_cursor.execute("revoke usage on warehouse DBA_WH from role {}_role".format(username))
    # release the resources
    admin_connection.close()
    connection.close()
    logger.info("Summary: user: {}, account: {}, pod: {} \n\n".format(username,account,pod))
    logger.info(tabulate(operations))
    # raise exception if any failure
    for i in operations:
        if i[1] == 'failed':
            raise Exception("user got created without required permissions")


def drop_database(account, database, pod):
    """
    PURPOSE:
        drop database from given account
    Args:
        account: ex: arc1000.us-east-1.privatelink
        database: ex: arcesium_data_warehouse
        pod: ex: terra
    Returns:
    """
    try:
        logger.info("Creating super user connection")
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection")
        cursor.execute("use role accountadmin")
        cursor.execute("drop database if exists {} cascade".format(database))
        cursor.execute("drop role if exists {}_reader".format(database))
        cursor.execute("drop role if exists {}_owner".format(database))
        logger.info("Successfully dropped database {} and roles from account {}".format(database, account))
    except Exception as e:
        logger.exception("Failed to drop database {} and roles from account {} "
                         "with error".format(database, account, str(e)))
        raise Exception("Failed to drop database {} in account {}".format(database, account))


def send_mail(send_from, send_to, subject, text, files=None, server="relay.ia55.net"):
    """
    Function to send email with given details. We use SMTP library for sending email

    Arguments:
            send_from (string): from mailing address
            send_to (list): list of mailing addresses to whom this mail should be sent
            subject (string): subject of mail
            text (string): contents of body of mail
            files (list): lsit of file names which should be attached to the mail
            server (string): the server which should be used for sending mail
                             Defaults to 'realay.ia55.net'

    Examples:
            self.send_email(send_from='kokkanti@arcesium.com', send_to=['kokkanti@arcesium.com'],
            subject='Test mail', text='this is test mail', files=['abc.txt','123.sql'])
    Raises:
            Any exception while sending email
    """
    if files is None:
        files = []
    assert type(send_to) == list
    assert type(files) == list

    message            = MIMEMultipart()
    message['From']    = send_from
    message['To']      = COMMASPACE.join(send_to)
    message['Date']    = formatdate(localtime=True)
    message['Subject'] = subject

    message.attach(MIMEText(text,'html'))

    for f in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(f, "rb").read())
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        message.attach(part)

    try:
        smtpObj = smtplib.SMTP('relay.ia55.net', 25)
        smtpObj.sendmail(message['From'], message['To'], message.as_string())
        smtpObj.close()

    except Exception as e:
        logger.error("Unable to send email with error : str(e)")
        raise Exception("Unable to send email")


def send_passwrod_reset_email_to_user(account, pod, user_mail, password, user_type, username):
    """
    PURPOSE:
        We need to send email to human users in below scenarios
        1. When we create a new user
        2. When we reset user password on user request
        3. When we rotate the password as per standard 180 days
    Args:
        account: arc1000.us-east-1.privatelink
        pod: terra
        usermail: oguri@arcesium.com
        password: oguri_sa
    Returns:
    """
    assert user_type in USER_TYPE, "user type should be anyone of {}".format(USER_TYPE)
    sub = "Snowflake password rest for user {} in pod {}".format(username, pod)
    if user_type in ['app']:
        mail_body = """Hi team, <br> <br>
        We have reset the password for Snowflake user {} in pod {} and wrote to application vault.
        Please check and let us know if there any issues.        
        <br> <br> <br>
        Thanks
        <br>
        DBA Team 
        """.format(username, pod)
    if user_type not in ['app']:
        mail_body = """Hi team, <br> <br>
        We have reset the password for Snowflake user {} in pod {}. Please check and let us know if there any issues.
        <br><br><br>
        <html>
        <head>
        <style>
        table, th, td {{ border: 1px solid black; border-collapse: collapse; }}
        th, td {{ padding: 5px; }}
        </style>
        </head>        
        <table>
        <tr>
            <td>ACCOUNT</td>
            <td>{}</td>
        </tr>
        <tr>
            <td>USER NAME</td>
            <td>{}</td>
        </tr>
        <tr>
            <td>PASSWORD</td>
            <td>{}</td>
        </tr>
        </table>
        </html>
        <br> <br> <br>
        Thanks
        <br>
        DBA Team 
        """.format(username, pod, account, username, password)
    send_mail(send_from="dba-ops@arcesium.com", send_to=["dba-ops-team@arcesium.com",user_mail], subject=sub, text=mail_body)


def send_user_creation_email_to_user(account, pod, user_mail, password, user_type, username, logfile):
    """
    PURPOSE:
        We need to send email to human users in below scenarios
        1. When we create a new user
        2. When we reset user password on user request
        3. When we rotate the password as per standard 180 days
    Args:
        account: arc1000.us-east-1.privatelink
        pod: terra
        usermail: oguri@arcesium.com
        password: oguri_sa
    Returns:
    """
    assert user_type in USER_TYPE, "user type should be anyone of {}".format(USER_TYPE)
    sub = "Snowflake user {} created in pod {}".format(username, pod)
    if user_type in ['app']:
        mail_body = """Hi team, <br> <br>
        We have created new Snowflake user {} in pod {} and wrote credentials to application vault.
        Please check and let us know if there any issues.        
        <br> <br> <br>
        Thanks
        <br>
        DBA Team 
        """.format(username, pod)
    if user_type not in ['app']:
        mail_body = """Hi team, <br> <br>
        We have created new Snowflake user {} in pod {}, below are credentials.
        Please check and let us know if there any issues.
        <br><br><br>
        <html>
        <head>
        <style>
        table, th, td {{ border: 1px solid black; border-collapse: collapse; }}
        th, td {{ padding: 5px; }}
        </style>
        </head>        
        <table>
        <tr>
            <td>ACCOUNT</td>
            <td>{}</td>
        </tr>
        <tr>
            <td>USER NAME</td>
            <td>{}</td>
        </tr>
        <tr>
            <td>PASSWORD</td>
            <td>{}</td>
        </tr>
        </table>
        </html>
        <br> <br> <br>
        Thanks
        <br>
        DBA Team 
        """.format(username, pod, account, username, password)
    send_mail(send_from="dba-ops@arcesium.com", send_to=["dba-ops-team@arcesium.com",user_mail], subject=sub,
              text=mail_body, files=[logfile])


def rotate_passwords(account, pod):
    """
    PURPOSE:
        As a part of standard process we need to rotate the password for all users in an account for every 180 days.
        This will reset the password for all users in given pod and account and send email for all human users.
    Args:
        account: ex: arc1000.us-east-1.privatelink
        pod : ex: terra
    Returns:
    """
    """
    Get list of users from snowflake account and reset the user password and write to vault.
    Based on the type of user send email with new password to the user.
    """
    try:
        connection, cursor = get_admin_connection(account=account, pod=pod)
        cursor.execute("select lower(NAME) from snowflake.account_usage.users "
                       "where MUST_CHANGE_PASSWORD=false and HAS_PASSWORD=true and DELETED_ON is null "
                       "and DISABLED=false and snowflake_lock=false and lower(NAME)!='snowflake'")
        snowflake_result = cursor.fetchall()
        for i in snowflake_result:
            username   = i[0]
            reset_user_password(account=account, username= username, pod= pod)
            # wait for 1 min as vault will be get loaded with multiple calls
            time.sleep(DB_WAIT_TIME)
    except Exception as e:
        logger.error("Error while resetting password for user {} in pod {}".format(username, pod))
        raise Exception("Error while resetting password for user {} in pod {}".format(username, pod))
    connection.close()


def extend_user_retention(account, pod,  username, retention):
    """
    PURPOSE:
        extend the retention of the user and update the request and send email
    Args:
        account: arc1000.us-east-1.privatelink
        username: oguri_temp
        pod : terra
        retention:  90
    Returns:
    """
    connection, cursor = get_admin_connection(account=account, pod=pod)
    logger.info("extending user {} retention period to {} in pod {}".format(username, retention, pod))
    cursor.execute("alter user {} set DAYS_TO_EXPIRY  = {}".format(username, retention))
    logger.info("extended user {} retention period to {} in pod {}".format(username, retention, pod))
    logger.info("updating database inventory")
    sql_cur, sql_conn = sql_connect()
    sql_cur.execute("update dbainfra.dbo.snowflake_users "
                    "set user_retention={} where username='{}' and pod='{}'".format(retention, username, pod))
    sql_cur.commit()
    sql_conn.close()
    connection.close()


def grant_additional_permissions(account, pod, username, permission_type, user_type, **kwargs):
    """
    PURPOSE:
        To grant additional permissions to the existing user.
        1. warehouse_owner  : create warehouse permisions
        2. monitoring_owner : monitor account usage, login etc
        3. database_owner   : owner permissions to database (all users by default has at least read permissions)
        4. share_owner      : data sharing permission with clients
        5. user type        : type of the user
    Args:
        account: arc1000.us-east-1.privatelink
        pod              : terra
        username         : cocoa_app
        permission_type  : database_owner
        database         : ubor_data_warehouse
    Returns:
    """
    permissions = ['warehouse_owner', 'monitoring_owner', 'database_owner', 'database_reader','share_owner']
    assert permission_type in permissions , "permissions should be in  {}".format(permissions)
    assert user_type in USER_TYPE, "usertype should be anyone of {}".format(USER_TYPE)
    # create database connection
    logger.info("Granting additional permissions {} to user {}".format(permission_type, username))
    connection, cursor = get_admin_connection(account=account, pod=pod)
    user_role = "{}_role".format(username)
    if permission_type in ['database_owner', 'database_reader']:
        if 'dbname' not in kwargs:
            raise Exception("Missing database name to grant permissions")
        dbname = kwargs['dbname']
        db_owner  = "{}_owner".format(dbname)
        db_reader = "{}_reader".format(dbname)
        if permission_type == 'database_owner':
            cursor.execute("grant role {} to role {}".format(db_owner, user_role))
            if user_type == 'app':
                cur_sql_dest, conn_sql_dest = sql_connect()
                cur_sql_dest.execute("select TOP 1 vaultpath,appname from dbainfra.dbo.snowflake_users "
                                     "where username='{}' and pod = '{}' and usertype='app'".format(username,pod))
                result = cur_sql_dest.fetchall()
                if not result:
                    raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
                for i in result:
                    vaultpath = i[0]
                    appname   = i[1]
                password  = vaultutil.get_user_password(vaultpath=vaultpath)
                password  = json.loads(password)['password']
                dbname    = dbname
                vaultpath = APP_VAULT.replace("$POD", pod).replace("$APPNAME", appname).replace("$DBNAME",
                                                                            dbname).replace("$USERNAME", username)
                cname = "{}.snowflakecomputing.com".format(account)
                secret = {'cname': cname, 'account': account, 'password': password, 'database': dbname}
                vaultutil.write_secret_to_vault(vaultpath, json.dumps(secret))
                logger.info("Permission {} granted to user {} successfully".format(db_owner,username))
                logger.info("Wrote credentials of user {} to vault path {} successfully".format(username, vaultpath))
                conn_sql_dest.close()
        if permission_type == 'database_reader':
            cursor.execute("grant role {} to role {}".format(db_reader, user_role))
    else:
        cursor.execute("grant role {} to role {}".format(permission_type, user_role))
    connection.close()


def unlock_user(account, pod, username):
    """
    PURPOSE:
        unlock the user in given pod
    Args:
        account: arc1000.us-east-1.privatelink
        pod: terra
        username: oguri_sa
    Returns:
    """
    connection, cursor = get_admin_connection(account=account, pod=pod)
    cursor.execute("alter user {} set mins_to_unlock= 0".format(username))
    connection.close()


def delete_expired_users(account, pod):
    """
    PURPOSE:
        delete all the users which are expired, Get all the users which are in expired state and remove one by one user
    Args:
        account: arc1000.us-east-1.privatelink
        pod: terra
    Returns:
    """
    connection, cursor = get_admin_connection(account=account, pod=pod)
    cursor.execute("show users")
    cursor.execute("SELECT \"login_name\"  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) where \"expires_at_time\" < current_timestamp")
    result = cursor.fetchall()
    for i in result:
        username = i[0]
        drop_user(account=account, username=username, pod=pod)
    connection.close()


def monitor_warehouse_utilization(account, pod):
    """
    PURPOSE:
        This function is to get list of warehouses in an account, get cost of each warehouse and send the report to the
        owner of the warehouses.
    Args:
        account: ex: arc1000
        pod : ex: terra
    Returns:
    """
    # create database connections
    cur_sql_dest, conn_sql_dest = sql_connect()
    connection, cursor = get_admin_connection(account=account, pod=pod)
    mail_body = """
    Hi Team,
    <br><br><br>
    Your warehouse utilization in pod {} has crossed the default alert limit {}. Below are the warehouses with 
    cost details.
    <br><br><br>
    <html>
    <head>  
    {}
    </head>
    <table>
    <tr>
        <th>OWNER</th>
        <th>WAREHOUSE NAME</th>
        <th>CREDITS USED</th>
    </tr>
    """.format(pod, (DEFAULT_WAREHOUSE_CREDIT_LIMIT*0.5),
               '<style> table { border-collapse: collapse; width: 100%; } th,'
               ' td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; } </style>')
    # gather the usernames and their mail details
    users_mails = {}
    cur_sql_dest.execute("select distinct lower(username), user_mail "
                         "from dbainfra.dbo.snowflake_users where pod='{}'".format(pod))
    sql_result = cur_sql_dest.fetchall()
    for i in sql_result:
        username  = i[0]
        user_mail = i[1]
        users_mails[username] = user_mail
    conn_sql_dest.close()
    """
    Get the total credit utilization by the user, if the credit limit is more than default limit then get the 
    credit utilization for each warehouse he created. Build a html table our of the result and send an email
    to the user. If the email entry is not there then send the report to the DBA team.
    """
    cursor.execute("show warehouses")
    cursor.execute("create or replace transient table warehouses as "
                   "select \"name\" as NAME,\"size\" as SIZE,\"min_cluster_count\" as MIN_CLUSTER_COUNT,"
                   "\"max_cluster_count\" as MAX_CLUSTER_COUNT,\"owner\" as OWNER "
                   "from table(result_scan(last_query_id()))")
    cursor.execute("select lower(owner),ROUND(sum(credits_used),2) total_credits_used "
                   "from snowflake.account_usage.WAREHOUSE_METERING_HISTORY usage join warehouses "
                   "on (usage.warehouse_name=warehouses.name) where MONTH(current_timestamp)=MONTH(start_time) "
                   "and YEAR(current_timestamp)=YEAR(start_time) group by 1")
    usage_owner = cursor.fetchall()
    for i in usage_owner:
        owner        = i[0]
        credits_used = i[1]
        if credits_used > (DEFAULT_WAREHOUSE_CREDIT_LIMIT*0.5):
            sub = "credit utilization in pod {} by user {}".format(pod, owner)
            user_mail = ''
            if owner in users_mails.keys():
                user_mail = users_mails[owner]
            cursor.execute("select owner,warehouse_name,ROUND(sum(credits_used),2) total_credits_used "
                      "from snowflake.account_usage.WAREHOUSE_METERING_HISTORY usage join warehouses on "
                      "(usage.warehouse_name=warehouses.name) where MONTH(current_timestamp)=MONTH(start_time)"
                      " and YEAR(current_timestamp)=YEAR(start_time) and lower(owner) = '{}' group by 1,2".format(owner))
            for warehouse in cursor.fetchall():
                warehouse_owner   = warehouse[0]
                warehouse_name    = warehouse[1]
                warehouse_credits = warehouse[2]
                mail_body += """
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>
                """.format(warehouse_owner,warehouse_name,warehouse_credits)
            mail_body += """
            </table>
            </html>
            <br> <br> <br>
            Thanks
            <br>
            DBA Team             
            """
            send_mail(send_from="dba-ops@arcesium.com", send_to=["dba-ops-team@arcesium.com",user_mail], subject=sub,
                      text=mail_body)
    # release the resources
    connection.close()


def snowflake_account_monitoring(account, pod):
    """
    PURPOSE:
        this function is to monitor the Snowflake account. Below are the items will be monitored
        1. Connectivity
        2. virtual warehouse
        3. Snowflake(login history etc) database access
        4. Storage failure
    Args:
        account: arc1000.us-east-1.privatelink
        pod: terra
    Returns:
    """
    account_monitor = {}
    # check connection to account
    try:
        logger.info("Creating super user connection to account {} pod {}".format(account, pod))
        connection, cursor = get_admin_connection(account=account, pod=pod)
        cursor.execute("select current_timestamp")
        if cursor.rowcount > 0:
            account_monitor['CONNECTION STATUS'] = 'SUCCESS'
            logger.info("Connection created successfully")
    except Exception as e:
        account_monitor['CONNECTION STATUS'] = 'FAILED'
        logger.info("Connection creation failed with error {}".format(e))
        alert_description = "Creating connection to pod {} or account {} failed with error {}".format(pod, account, str(e))
        raise_radar_alert(alert_description)
        raise Exception("Error occurred while creating connection to Snowflake account {} or pod {}".format(account, pod))
    # check virtual warehouse creation
    alert_description = ''
    try:
        cursor.execute("create or replace warehouse snowflake_account_monitoring")
        account_monitor['VIRTUAL WAREHOUSE'] = 'SUCCESS'
        logger.info("Accessing virtual warehouse is successful")
    except Exception as e:
        account_monitor['VIRTUAL WAREHOUSE'] = 'FAILED'
        logger.info("Virtual warehouse creation failed with error {}".format(e))
        alert_description += "Error encountered while accessing Snowflake virtual warehouse in account {} \n".format(account)
        # check the storage
    try:
        cursor.execute("use warehouse snowflake_account_monitoring")
        cursor.execute("create or replace table audit_archive.public.sf_monitoring_test(id int)")
        cursor.execute("insert into audit_archive.public.sf_monitoring_test select seq4() "
                       "from table(generator(rowcount => 100))")
        account_monitor['Storage Access'] = 'SUCCESS'
        logger.info("Accessing storage is successful")
    except Exception as e:
        account_monitor['Storage Access'] = 'FAILED'
        logger.info("Accessing storage failed with error {}".format(e))
        alert_description += "Error encountered while accessing Snowflake storage in account {} \n".format(account)
    # access login history
    try:
        cursor.execute("use warehouse snowflake_account_monitoring")
        cursor.execute("select count(*) from snowflake.account_usage.query_history "
                       "where START_TIME > dateadd(hour, -6,current_timestamp)")
        account_monitor['Metadata Access'] = 'SUCCESS'
        logger.info("Accessing login history is successful")
    except Exception as e:
        account_monitor['Metadata Access'] = 'FAILED'
        logger.info("Accessing login history failed with error {}".format(e))
        alert_description += "Error encountered while accessing Snowflake metadata in account {} \n".format(account)
    for i in account_monitor.values():
        if i == 'FAILED':
            logger.info("Some of the resources are not working in account {} or pod {}".format(account,pod))
            alert_description += "Some of the resources are not working in account {} or pod {} \n".format(account,pod)
            raise_radar_alert(alert_description)
            raise Exception("Some of the resources are not working in account {} or pod".format(account, pod))
    logger.info("Account : {} is accessible and all resources are working fine".format(account))
    print("Account : {} is accessible and all resources are working fine".format(account))


def snowflake_cost_utilization_report():
    """
    PURPOSE:
       This function get the last 6 months of resource utilization and send a report of that.
    Returns:
    """
    TAX_PCT = 8.87
    report = '/g/dba/logs/snowflake/cost_report.html'
    fh = open(report, 'w')
    # get the last 6 months as header row
    now = datetime.datetime.now()
    th = ''
    for i in range(6, 0, -1):
        temp_time = now+relativedelta(months=-i)
        th += "<th> {}_{} </th>".format(temp_time.strftime("%b"), temp_time.year)
    mail_body = """
    Hi Team,
    <br><br><br>
    Attached the Snowflake cost for utilization in all accounts for last 6 months.
    <br><br><br>
    Thanks
    <br>
    DBA Team
    """
    file_content = """"<html>
    <head>
    {}
    </head>
    <body>
    <table>
    <tr>
        <th>ACCOUNT</th>
        <th>POD</th>
        {}
    </tr>
    """.format('<style> table { font-family: arial, sans-serif; border-collapse: collapse; width: 70%; } td, '
               'th { border: 1px solid #dddddd; text-align: left; padding: 8px; } '
               'tr:nth-child(even) { background-color: #dddddd;} </style>', th)
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute("select lower(FriendlyName), lower(pod) from dbainfra.dbo.database_server_inventory "
                         "where lower(ServerType)='snowflake' and IsActive=1")
    # variable to hold all costs based on month for all accounts
    cost = {}
    # populate the cost variable with required information
    connection, cursor = get_admin_connection(account='arc1000.us-east-1.privatelink', pod='terra')
    cursor.execute("select MONTH(ADD_MONTHS(current_timestamp, -(seq4(1)+1)))||'_'||YEAR(ADD_MONTHS(current_timestamp, -(seq4(1)+1))) as month from table(generator(rowcount => 6)) v")
    for i in cursor.fetchall():
        cost[i[0]] = []
    connection.close()
    # retrive the cost of each account
    for sql_result in cur_sql_dest.fetchall():
        connection, cursor = get_admin_connection(account=sql_result[0], pod=sql_result[1])
        cursor.execute("create or replace temporary table months as select MONTH(ADD_MONTHS(current_timestamp, -(seq4(1)+1))) month"
                       " ,YEAR(ADD_MONTHS(current_timestamp, -(seq4(1)+1))) year from table(generator(rowcount => 6)) v")
        cursor.execute("WITH WAREHOUSE AS (select date_trunc('MONTH',CONVERT_TIMEZONE('UTC',USAGE_DATE)) month,"
                       "ROUND(sum(CREDITS_BILLED),3)*4 cost from snowflake.account_usage.METERING_DAILY_HISTORY "
                       "where USAGE_DATE between to_timestamp(date_trunc('MONTH', dateadd(month,-6,current_timestamp))) "
                       "and to_timestamp(date_trunc('MONTH', current_timestamp)) group by 1), "
                       "STORAGE AS (select date_trunc('MONTH',CONVERT_TIMEZONE('UTC',USAGE_DATE)) month, "
                       "ROUND((avg(storage_bytes + stage_bytes + failsafe_bytes)/power(1024, 4))*40,3) as cost "
                       "from snowflake.account_usage.storage_usage "
                       "where USAGE_DATE between to_timestamp(date_trunc('MONTH', dateadd(month,-6,current_timestamp))) "
                       "and to_timestamp(date_trunc('MONTH', current_timestamp))  group by 1) "
                       "select months.month||'_'||months.year as month, '$' as unit,"
                       "(coalesce(ROUND((WAREHOUSE.cost + STORAGE.cost),0),0) + coalesce(ROUND((WAREHOUSE.cost + STORAGE.cost) * ({}/100),0),0)) as cost "
                       "from WAREHOUSE join STORAGE on (WAREHOUSE.month=STORAGE.month) right join months on "
                       "(months.month=MONTH(WAREHOUSE.month) and months.year=YEAR(WAREHOUSE.month)) "
                       "order by months.year,months.month".format(TAX_PCT))
        result = cursor.fetchall()
        file_content += "<tr> <td> {} </td> ".format(sql_result[0])
        file_content += " <td> {} </td> ".format(sql_result[1])
        for i in result:
            file_content += " <td> {} </td> ".format(str(i[1])+str(i[2]))
            cost[i[0]].append(i[2])
        file_content += "</tr>"
        connection.close()
    file_content += "<tr><td></td><td>TOTAL</td>"
    for i in reversed(list(cost.keys())):
        file_content += "<td>{}</td>".format(sum(cost[i]))
    file_content += "</tr>"
    file_content += """
     </table>
     <p style="color:blue">COST is including {}% of tax.</p>
     </body>
     </html>""".format(TAX_PCT)
    fh.write(file_content)
    fh.close()
    sub = "COST Report of Snowflake accounts for last 6 months"
    send_mail(send_from="dba-ops@arcesium.com", send_to=["dba-ops-team@arcesium.com"], subject=sub,
              text=mail_body,files=[report])
    conn_sql_dest.close()


"""
Below are the functions which will be used in the Snowflake refresh
"""


def check_refresh_possibility(dest_pod):
    """
    before proceeding for fresh check the table refresh_server_inventory for entry if there is no entry exit
    """
    logger.info("checking the possibility of refresh")
    query = "select count(1) from dbainfra.dbo.refresh_server_inventory " \
            "where lower(dest_pod) = '{}' and performrefresh=1".format(str(dest_pod).lower())
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    if result[0] == 0:
        logger.error("Backup is not scheduled for this instance or no entry for pod {} in refresh inventory table "
                     "dbainfra.dbo.refresh_server_inventory".format(dest_pod))
        return 1
    logger.info("Refresh is scheduled for snowflake pod {}, proceeding further".format(dest_pod))


def check_replication(source_account, source_pod, destination_account, destination_pod):
    """
    1. login to source account (production), check if replication is enabled to destination accounts(uat)
    2. if replication is not enabled from snowflake side, return 1 or failure message
    """
    try:
        # ex : Get arc1000 from arc1000.us-east-1.privatelink
        logger.info("checking replication enabled from source pod {} to destination pod {}".format(source_pod, destination_pod))
        destination_account = str(destination_account).split('.')[0]
        connection, cursor = get_admin_connection(source_account, source_pod)
        cursor.execute("show replication accounts")
        count = cursor.execute("select count(*) from table(result_scan(last_query_id())) where \"name\"='{}'".format(str(destination_account).upper())).fetchone()[0]
        if count == 0:
            logger.error("replication is not enabled from source pod : {} to destination pod : {}".format(source_pod, destination_pod))
            # raise Exception("replication is not enabled from source pod : {} to destination pod : {}".format(source_pod, destination_pod))
            return 1
    except Exception as e:
        logger.error("Error: {} occurred while verifying replication between source pod : {} and destination pod : {}".format(str(e),source_pod, destination_pod))
        # raise Exception("Error: {} occurred while verifying replication between source pod : {} and destination pod : {}".format(str(e),source_pod, destination_pod))
        return 1


def enable_replication_for_database(source_account, source_pod, destination_account, destination_pod, dbname):
    """
    1. Snowflake replication works on database wise.
    2. Login to source account, enable replication for database
    3. return 1 in case of failure
    """
    try:
        destination_account = str(destination_account).split('.')[0]
        connection, cursor  = get_admin_connection(source_account, source_pod)
        cursor.execute("show replication accounts")
        accountname = cursor.execute("select \"snowflake_region\"||'.'||\"name\" from table(result_scan(last_query_id())) "
                                     "where \"name\"=upper('{}')".format(destination_account)).fetchone()[0]
        logger.info("enabling replication for database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
        logger.info("alter database {} enable replication to accounts {}".format(dbname, accountname))
        cursor.execute("alter database {} enable replication to accounts {}".format(dbname, accountname))
        logger.info("enabled replication for database {} from source pod {} to destination pod".format(dbname,source_pod,destination_pod))
    except Exception as e:
        logger.error("Error {} occurred while enabling replication for database {} between "
                     "source pod : {} and destination pod : {}".format(str(e),dbname,source_pod, destination_pod))
        #raise Exception("Error {} occurred while enabling replication for database {} between "
        #                "source pod : {} and destination pod : {}".format(str(e),dbname,source_pod, destination_pod))
        return 1


def replicate_database_from_source(source_account, destination_account, destination_pod, dbname, source_pod,arc_techops_number):
    """
    taking example of arcesium_data_warehouse database

    After replication is enabled from source account to destination account, login to destination account (uat)
    1. create a database <source_pod>_replica_arcesium_data_warehouse which is replica of arcesium_data_warehouse database from source account
    2. Refresh the <source_pod>_replica_arcesium_data_warehouse database which will copy the database arcesium_data_warehouse from production to uat
    3. create a clone of the <source_pod>_replica_arcesium_data_warehouse with name <source_pod>_clone_arcesium_data_warehouse
    this completes enabling replication and copying the database
    4. Rename the database from arcesium_data_warehouse to arcesium_data_warehouse_request-number
    5. Rename the clone from production replica (source-pod_arcesium_clone_data_warehouse) to arcesium_data_warehouse
    6. Make an entry for the database into old database table to delete after two days
    """
    try:
        logger.info("Configuring replication for database {} source : {} and destination : {}".format(dbname,source_account, destination_account))
        source_account = str(source_account).split('.')[0]
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        count = cursor.execute("select count(*) from audit_archive.information_schema.databases where database_name='{}_{}'".format(str(dbname).upper(), arc_techops_number)).fetchone()[0]
        if count == 1:
            logger.info("Database replication was completed for this database {} "
                        "from source pod {} to "
                        "destination pod {}, "
                        "continuing with next steps".format(dbname,source_pod,destination_pod))
            return 0
        cursor.execute("show replication accounts")
        accountname = cursor.execute("select \"snowflake_region\"||'.'||\"name\" from table(result_scan(last_query_id())) where \"name\"=upper('{}')".format(source_account)).fetchone()[0]
        acc_dbname = str(accountname)+'.'+str(dbname)
        logger.info("creating replica of database {} from source {}".format(dbname, acc_dbname))
        cursor.execute("create database if not exists {}_replica_{} as replica of {}".format(source_pod,dbname, acc_dbname))
        # refresh process will take more time based on database size.
        logger.info("starting database refresh from source {}".format(dbname, acc_dbname))
        logger.info("Refresh process take longer time based on database size...so please be patient...")
        query = """
        use role accountadmin;
        use warehouse dba_wh;
        select * from table(information_schema.database_refresh_progress({}));
        """.format(str(source_pod)+'_replica_'+str(dbname))
        logger.info("To see the status of the replication, login to the target account {} and run below command {}".format(destination_account, query))
        cursor.execute("alter database {}_replica_{} refresh".format(source_pod,dbname))
        cursor.execute("create if not exists database {}_clone_{} clone {}_replica_{}".format(source_pod,dbname,source_pod, dbname))
        # Rename the existing database to old and clone to actual database
        cursor.execute("alter database IF EXISTS {} rename to {}_{}".format(dbname, dbname, arc_techops_number))
        cursor.execute("alter database IF EXISTS {}_clone_{} rename to {}".format(source_pod, dbname, dbname))
        # Make an entry into the table to remove them after two days
        cur_sql_dest, conn_sql_dest = sql_connect()
        cur_sql_dest.execute("select count(*) from dbainfra.dbo.snowflake_old_databases where pod='{}' and dbname='{}_{}'".format(destination_pod,dbname,arc_techops_number))
        if cur_sql_dest.fetchone()[0] == 0:
            cur_sql_dest.execute("insert into dbainfra.dbo.snowflake_old_databases(accountname,pod,dbname,deleted) "
                                 "values('{}','{}','{}_{}',0)".format(destination_account, destination_pod, dbname,arc_techops_number))
        conn_sql_dest.close()
    except Exception as e:
        logger.error("Error {} occurred while replicating database {} from source {} to destination {}".format(str(e),dbname,source_account,destination_account))
        # raise Exception("Error {} occurred while replicating database from source {} to destination {}".format(str(e),source_account,destination_account))
        return 1


def backup_internal_stages(destination_account, destination_pod, dbname, request_number):
    """
    Take backup of internal stages
    """
    try:
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        logger.info("Creating inventory tables - stage_properties, stage_backup")
        cursor.execute("create or replace table audit_archive.public.stage_properties "
                                   "(dbname varchar,schemaname varchar, stagename varchar, parent_property varchar, "
                                   "property varchar, property_type varchar,property_value varchar, property_default varchar)")
        cursor.execute("create or replace table audit_archive.public.stage_backup"
                                   "(dbname varchar,schemaname varchar,ordr int,def varchar)")
        logger.info("Started taking backup of internal stages in pod {} from database {}_{}".format(destination_pod, dbname, request_number))
        cursor.execute("use database {}_{}".format(dbname,request_number))
        cursor.execute("show stages in database {}_{}".format(dbname,request_number))
        cursor.execute("select \"schema_name\",\"name\" from table(result_scan(last_query_id())) where \"type\"='INTERNAL'")
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                stage_schema = var[0]
                stage_name   = var[1]
                stg_name     = stage_schema+'.'+stage_name
                cursor.execute("desc stage {}".format(stg_name))
                cursor.execute("insert into audit_archive.public.stage_properties select '{}','{}','{}',* "
                               "from table(result_scan(last_query_id()))".format(dbname,stage_schema,stage_name))
                stage_def = """
                insert into audit_archive.public.stage_backup
                WITH T AS (
                select
                '{}.'||SCHEMANAME||'.'||STAGENAME as stagename,
                CASE
                WHEN parent_property = 'STAGE_LOCATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'["','\\''),'"]','\\''),' ')
                WHEN parent_property = 'STAGE_INTEGRATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[','\\''),']','\\''),' ')
                WHEN parent_property = 'STAGE_COPY_OPTIONS' THEN 'COPY_OPTIONS = ('||LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[',' '),']',' '),', ')||')'
                WHEN parent_property = 'STAGE_FILE_FORMAT'  THEN 'FILE_FORMAT = ('|| LISTAGG(property||'='||REPLACE(REPLACE((CASE
                                                                                                                            WHEN PROPERTY_VALUE = 'true' THEN PROPERTY_VALUE
                                                                                                                            WHEN PROPERTY_VALUE = 'false' THEN PROPERTY_VALUE
                                                                                                                            WHEN PROPERTY_VALUE = '0' THEN PROPERTY_VALUE
                                                                                                                            WHEN PROPERTY_VALUE = '1' THEN PROPERTY_VALUE
                                                                                                                            ELSE concat('\\'',PROPERTY_VALUE,'\\'') END)
                                                                                                                            ,'[',' '),']',' '),', ')||')'
                ELSE ' '
                END as options
                from audit_archive.public.stage_properties
                where PROPERTY_VALUE is not null and PROPERTY_VALUE != ''
                group by SCHEMANAME,STAGENAME,stagename,parent_property
                order by schemaname,stagename)
                select '{}','{}',2,'CREATE OR REPLACE STAGE '||STAGENAME||' '||LISTAGG(OPTIONS,' ')||';' from T
                group by STAGENAME
                """.format(str(dbname).upper(),str(dbname),stage_schema)
                cursor.execute(stage_def)
        logger.info("Completed taking backup of internal stages in database {} from pod {}".format(dbname, destination_pod))
    except Exception as e:
        logger.error("Error {} occurred while taking backup of internal stages from pod {} in database {}".format(str(e),destination_pod, dbname))
        # raise Exception("Error {} occurred while taking backup of internal stages from pod {} in database {}".format(str(e),destination_pod, dbname))
        return 1


def restore_stages_fileformats(destination_account, destination_pod, dbname, arc_techops_number):
    """
    Restore file formats, stages
    """
    try:
        logger.info("started restoring file formats")
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database {}".format(dbname))
        cursor.execute("show file formats in database {}_{}".format(dbname,arc_techops_number))
        # after performing the refresh from prod to uat, there might be some schemas missing. So adding where condition
        cursor.execute("select 'create or replace file format '||\"schema_name\"||'.'||\"name\"||' CLONE '||\"database_name\"||'.'||\"schema_name\"||'.'||\"name\"||';' "
                       "from table(result_scan(last_query_id())) where \"schema_name\" in (select SCHEMA_NAME from information_schema.SCHEMATA)")
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                sql = var[0]
                cursor.execute(sql)
            logger.info("Restoration of file formats is completed")
        logger.info("started restoration of external stages")
        cursor.execute("show stages in database {}_{}".format(dbname, arc_techops_number))
        # after performing the refresh from prod to uat, there might be some schemas missing. So adding where condition
        cursor.execute("select 'create or replace stage '||\"schema_name\"||'.'||\"name\"||' CLONE '||\"database_name\"||'.'||\"schema_name\"||'.'||\"name\"||';' "
                       "from table(result_scan(last_query_id())) where \"type\"='EXTERNAL' and \"schema_name\" in (select SCHEMA_NAME from information_schema.SCHEMATA)")
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                sql = var[0]
                cursor.execute(sql)
            logger.info("Restoration of external stages is completed")
        logger.info("Started restoration of internal stages")
        cursor.execute("WITH T as (select * from audit_archive.public.stage_backup where DBNAME='{}') "
                       "select schemaname,def from T where upper(schemaname) in (select SCHEMA_NAME from information_schema.SCHEMATA)"
                       " order by ordr".format(str(dbname).lower(),arc_techops_number))
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                schemaname    = var[0]
                sql_statement = var[1]
                try:
                    cursor.execute("use schema {}".format(schemaname))
                    cursor.execute(sql_statement)
                except Exception as e:
                    logger.error("Failed to execute statement {} with exception {}, continuing with next statement".format(sql_statement,str(e)))
                    continue
            logger.info("Restoration of internal stages is completed")
    except Exception as e:
        logger.error("Error : {} occurred to restore the file format / stages".format(str(e)))
        # raise Exception("Error : {} occurred to restore the file format / stages".format(str(e)))
        return 1


def backup_shares_permissions(destination_account, destination_pod, dbname, arc_techops_number):
    """
    by default snowflake refresh do not take care of permissions, taking backup of permissions given to outbound shares
    """
    try:
        logger.info("Started taking backup of privileges assigned to shares in pod {}".format(destination_pod))
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database audit_archive")
        cursor.execute("CREATE TABLE IF NOT EXISTS audit_archive.public.share_grants(request_number varchar,created_on timestamp_ltz,privilege varchar,granted_on varchar,"
                       "name varchar,granted_to varchar,grantee_name varchar,grant_option varchar,granted_by varchar)")
        logger.info("Taking backup of permissions to shares in database {} from pod {}".format(dbname, destination_pod))
        cursor.execute("show shares")
        cursor.execute("select \"name\" from table(result_scan(last_query_id()))"
                       " where \"kind\"='OUTBOUND' and \"database_name\"='{}_{}'".format(str(dbname).upper(),arc_techops_number))
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                share_name = var[0]
                count = cursor.execute("select count(*) from audit_archive.public.share_grants "
                                       "where grantee_name='{}' and request_number='{}'".format(share_name,arc_techops_number)).fetchone()[0]
                if count == 0:
                    cursor.execute("show grants to share {}".format(share_name))
                    cursor.execute("insert into audit_archive.public.share_grants select '{}',* from table(result_scan(last_query_id()))".format(arc_techops_number))
            logger.info("Completed taking backup of privileges assigned to shares in pod {}".format(destination_pod, dbname))
    except Exception as e:
        logger.error("Error {} occurred while taking backup of privileges assigned to shares in pod {}".format(str(e),destination_pod))
        # raise Exception("Error {} occurred while taking backup of roles and privileges in pod {}".format(str(e),destination_pod))
        return 1


def change_ownership_to_db_owner(destination_account, destination_pod, dbname):
    """
    This is to make the database_owner as the owner of all objects in the database
    """
    try:
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database {}".format(dbname))
        cursor.execute("GRANT OWNERSHIP ON DATABASE {} to {}_owner COPY CURRENT GRANTS".format(dbname,dbname))
        cursor.execute("select SCHEMA_NAME from information_schema.SCHEMATA where SCHEMA_NAME not in ('INFORMATION_SCHEMA')")
        result = cursor.fetchall()
        for var in result:
            schema_name = var[0]
            cursor.execute("GRANT OWNERSHIP ON SCHEMA {} to role {}_owner COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL TABLES IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL VIEWS IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL STAGES IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL FILE FORMATS IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL FUNCTIONS IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL PROCEDURES IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL SEQUENCES IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL STREAMS IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            cursor.execute("GRANT OWNERSHIP ON ALL TASKS IN SCHEMA {} to role {}_owner  COPY CURRENT GRANTS".format(schema_name,dbname))
            logger.info("Granted ownership on all objects in schema {} to role {}_owner".format(schema_name,dbname))
        logger.info("Successfully granted ownership on all objects in the database {} to role {}_owner".format(dbname,dbname))
    except Exception as e:
        logger.error("Error :{} occurred while changing the object owner ship in database : {}".format(str(e),dbname))
        raise Exception("Error occurred while changing the object owner ship in database : {}".format(str(e),dbname))


def restore_shares_permissions(destination_account, destination_pod, dbname, arc_techops_number):
    """
    Restore the permissions on objects to shares
    """
    try:
        error = 0
        connection, cursor = get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database {}".format(dbname))
        """
        once the database is renamed share will have permissions for renamed database or old database. So we will remove
        the access to the old database (db_<techops number>) and grant the permissions back to the share on the new database
        copied from the production.
        """
        logger.info("Revoking and Granting permissions to shares on database objects")
        query = """
        select 'REVOKE '||PRIVILEGE||' ON '||GRANTED_ON||' '||NAME||' FROM '||GRANTED_TO||' '||GRANTEE_NAME||';'
        from audit_archive.public.share_grants where granted_to='SHARE' and split_part(NAME,'.',0)='{}_{}' and request_number='{}'
        union
        select 'GRANT '||PRIVILEGE||' ON '||GRANTED_ON||' '||REPLACE(NAME,split_part(NAME,'.',0),'{}')||' TO '||GRANTED_TO||' '||GRANTEE_NAME||';'
        from audit_archive.public.share_grants where granted_to='SHARE' and split_part(NAME,'.',0)='{}_{}' and request_number='{}'
        """.format(str(dbname).upper(),arc_techops_number,arc_techops_number,str(dbname).upper(),str(dbname).upper(),arc_techops_number,arc_techops_number)
        cursor.execute(query)
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                sql_statement = var[0]
                logger.info(sql_statement)
                try:
                    cursor.execute(sql_statement)
                except snowflake.connector.errors.ProgrammingError as e:
                    if e.errno == 2003:
                        logger.warning("Failed execute statement as the object not exists")
                        continue
                    else:
                        logger.error("Failed to execute statement {} with exception {}, continuing with next statement".format(sql_statement,str(e)))
                        error = 1
                        continue
        """
        change the permissions on the database objects to <dbname>_owner
        """
        change_ownership_to_db_owner(destination_account, destination_pod, dbname)
        """
        Assigning the default permissions to the roles on the database
        """
        logger.info("applying default permissions for the database {}".format(dbname))
        create_database(destination_account, dbname, destination_pod)
        logger.info("Granted default permissions to roles")

        if error == 1:
            logger.error("Failed to restore the permissions")
            return 1
        return 0
    except Exception as e:
        logger.error("Error occurred while restoring stages/permissions in pod with error {}".format(destination_pod,str(e)))
        # raise Exception("Error occurred while restoring stages/permissions in pod".format(destination_pod))
        return 1
