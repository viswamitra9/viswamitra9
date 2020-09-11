# Owner       : Srinivasarao Oguri
# Description : This is an utility program used to manage snowflake

import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import logging
import json
import sys
import pyodbc
import time

from tabulate import tabulate

import arcesium.snowflake.vaultutil as vaultutil

logger = logging.getLogger()

# type of users allowed to create
USER_TYPE   = ['app', 'third_party_app', 'customer', 'trm', 'temporary', 'app_team']
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
ALLOWED_HOSTS    = "'125.18.12.160/28', '115.112.81.240/28','10.12.0.0/17','149.77.95.64/29'"
RESTRICTED_HOSTS = "'54.172.224.181','54.174.16.130'"


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
        logger.info("permissions granted to newly created db roles")
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


def create_user(account, username, pod, user_type, user_mail, dbname='arcesium_data_warehouse', **kwargs):
    """
    PURPOSE:
        create snowflake user, users are different type in Snowflake, refer to
        http://wiki.ia55.net/pages/viewpage.action?spaceKey=TECHDOCS&title=Snowflake+user+management
        This function will create a role for every user with "username_role", grant the permissions to the role
        and assign the role as default role and write password to vault. Make an entry into the DBMONITOR server.
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    # create SQL connection
    sql_cur, sql_conn = sql_connect()
    assert user_type in USER_TYPE, "usertype should be anyone of {}".format(USER_TYPE)
    # role for every user with unique password
    user_role = "{}_role".format(username)
    db_reader = "{}_reader".format(dbname)
    db_owner  = "{}_owner".format(dbname)
    password  = get_unique_password()
    connection, cursor = get_admin_connection(account, pod)
    cursor.execute("create role if not exists {}".format(user_role))
    cursor.execute("create user if not exists {} password='{}' DEFAULT_ROLE={} "
                   "EMAIL='{}'".format(username, password, user_role, user_mail))
    cursor.execute("grant role {} to user {}".format(user_role, username))
    # grant required roles to the user role
    user_type = str(user_type).lower()
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
            raise Exception("application team(human) users are not created in prod or uat environment")
        cursor.execute("grant role {} to role {}".format(db_owner, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # write password to vault and make entry into SQL server
    if user_type == 'app':
        vaultpath   = APP_VAULT.replace("$POD", pod).replace("$APPNAME", kwargs['appname'])\
            .replace("$DBNAME", dbname).replace("$USERNAME", username)
        cname       = "{}.snowflakecomputing.com".format(account)
        secret      = json.dumps({'cname': cname, 'account': account, 'password': password, 'database': dbname})
        vaultutil.write_secret_to_vault(vaultpath, secret)
        # write to sql server inventory table
        vaultpath = APP_VAULT.replace("$APPNAME", kwargs['appname']).replace("$DBNAME", dbname).\
            replace("$USERNAME", username)
        sql_cur.execute("insert into dbainfra.dbo.snowflake_users "
                        "(username, usertype, appname, user_mail, vaultpath, pod) values ('{}', '{}', '{}', "
                        "'{}', '{}', '{}')".format(username, user_type, kwargs['appname'], user_mail, vaultpath, pod))
    else:
        vaultpath = OTHER_VAULT.replace("$POD", pod).replace("$USERNAME", username)
        cname     = "{}.snowflakecomputing.com".format(account)
        secret    = json.dumps({'cname': cname, 'account': account, 'password': password, 'database': dbname})
        vaultutil.write_secret_to_vault(vaultpath, secret)
        # write to sql server inventory table
        vaultpath = OTHER_VAULT.replace("$USERNAME", username)
        if user_type == 'temporary':
            sql_cur.execute("insert into dbainfra.dbo.snowflake_users (username, usertype, user_retention, user_mail, "
            "vaultpath, pod) values "
            "('{}','{}',{},'{}','{}','{}')".format(username, user_type, kwargs['retention'], user_mail, vaultpath, pod))
        else:
            sql_cur.execute("insert into dbainfra.dbo.snowflake_users (username, usertype, user_mail, vaultpath, pod) "
            "values ('{}','{}','{}','{}','{}')".format(username, user_type, user_mail, vaultpath, pod))
    # release the resources
    sql_cur.commit()
    cursor.commit()
    sql_conn.close()
    connection.close()


def reset_user_password(account, username, pod):
    """
    PURPOSE:
        reset user password and write to vault.
    INPUTS:
        account (account.<region>.privatelink, username, pod)
    """
    logger.info("Creating super user connection to account {}".format(account))
    try:
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Resetting password for user {} in pod {}".format(username, pod))
        cursor.execute("alter user {} set password = '{}' must_change_password=False".format(username, password))
        logger.info("Password reset completed for user {} in pod {}".format(username, pod))
        sql_cur, sql_conn = sql_connect()
        sql_cur.execute("select vaultpath from dbainfra.dbo.snowflake_users "
                        "where username = '{}' and pod = '{}'".format(username, pod))
        result = sql_cur.fetchall()
        if not result:
            raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
        for i in result:
            vaultpath  = i[0]
            logger.info("writing user {} password to vault path {}".format(username, vaultpath))
            # write password to vault
            cname     = "{}.snowflakecomputing.com".format(account)
            dbname    = json.loads(vaultutil.get_user_password(vaultpath))['database']
            secret    = json.dumps({'cname': cname, 'account': account, 'password': password, 'database': dbname})
            vaultutil.write_secret_to_vault(vaultpath, secret)
            logger.info("Successfully wrote user {} password to vault path {}".format(username, vaultpath))
    except Exception as e:
        logger.error("error while user password reset, error : {}".format(str(e)))
        connection.close()
        raise Exception("Failed to reset the user {} password in account {}".format(username, account))
    # release the database connections
    connection.commit()
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
    connection.commit()
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
        account: ex: arc1000
        region: ex: us-east-1
        env: ex: dev
        pod: ex: terra
    Returns:
    """
    try:
        admin_pass = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/admin'.format(pod))
        password   = json.loads(admin_pass)['password']
        logger.info("Creating super user connection")
        connection, cursor = get_snowflake_connection(account=account, username='admin', password=password)
        logger.info("Created super user connection")
        logger.info("Dropping unwanted users and default warehouse")
        cursor.execute("use role accountadmin")
        cursor.execute("drop user if exists MNDINI_SFC")
        cursor.execute("drop user if exists APATEL_SFC")
        cursor.execute("drop warehouse if exists COMPUTE_WH")
        logger.info("Dropped users : MNDINI_SFC and APATEL_SFC")
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
        cursor.execute("grant role warehouse_owner, monitoring_owner, share_owner to role accountadmin")
        # grant the roles to trm_role
        cursor.execute("grant role warehouse_owner, monitoring_owner, share_owner to role trm_role")
        # creating required databases
        logger.info("Creating required databases")
        cursor.execute("create database if not exists audit_archive")
        # create default admin user for the account
        password = get_unique_password()
        logger.info("Creating sa user")
        cursor.execute("create user if not exists sa password = '{}' "
                       "default_role = accountadmin MUST_CHANGE_PASSWORD=FALSE".format(password))
        cursor.execute("grant role accountadmin to user sa")
        # write password to vault
        vaultpath = "/secret/v2/snowflake/{}/db/sa".format(pod)
        cname     = "{}.{}.privatelink.snowflakecomputing.com".format(account, region)
        secret    = json.dumps({'cname': cname, 'account': "{}.{}.privatelink".format(account, region),
                                'password': password, 'database': 'audit_archive'})
        vaultutil.write_secret_to_vault(vaultpath, secret)
        # Set default parameters for account
        cursor.execute("alter account set PERIODIC_DATA_REKEYING = TRUE")
        cursor.execute("alter account set lock_timeout = {}".format(APP_LOCK_TIMEOUT))
        cursor.execute("alter account set abort_detached_query = TRUE")
        cursor.execute("alter account set statement_timeout_in_seconds = {}".format(APP_STATEMENT_TIMEOUT))
        # if the environment is prod set the time travel period to 35 days for other environments it is default to 1
        if str(env).lower() == 'prod':
            cursor.execute("alter account set DATA_RETENTION_TIME_IN_DAYS = 35")
        # make entry into database inventory
        logger.info("Making entry into database inventory")
        cur_sql_dest, conn_sql_dest = sql_connect()
        query = "insert into database_server_inventory " \
                "(Dataserver,Env,Host,IsActive,Monitor,ServerType,FriendlyName,Pod,ClientDbState) " \
                "values('{}','{}','{}','{}','{}','{}','{}','{}','{}')".\
                format(cname,env,cname,'yes','yes','snowflake',
                "{}.{}.privatelink".format(account, region),pod,'onboarding')
        cur_sql_dest.execute(query)
        conn_sql_dest.close()
        # apply the network policy
        logger.info("Creating network policy block_public and applying to account")
        cursor.execute("CREATE OR REPLACE NETWORK POLICY block_public ALLOWED_IP_LIST=({}) "
                       "BLOCKED_IP_LIST=({})".format(ALLOWED_HOSTS, RESTRICTED_HOSTS))
        cursor.execute("alter account set network_policy = block_public")
        # release the resources
        connection.commit()
        conn_sql_dest.commit()
        conn_sql_dest.close()
        connection.close()
    except Exception as e:
        logger.exception("Failed to prepare the account {} with error {}".format(str(account), str(e)))
        raise Exception("Failed to prepare the account {} with error {}".format(str(account), str(e)))


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
    operations = []
    cur_sql, conn_sql = sql_connect()
    cur_sql.execute("select usertype,vaultpath "
             "from dbainfra.dbo.snowflake_users where username='{}' and pod = '{}'".format(username, pod))
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
            temp_list = ["create_schema", "success"]
        except Exception as e:
            temp_list = ["create_schema", "failed"]
            logger.exception(str(e))
        try:
            cursor.execute("create table user_permission_test.test_permission as select current_timestamp as time")
            temp_list.append(["create_table", "success"])
        except Exception as e:
            temp_list.append(["create_table", "failed"])
            logger.exception(str(e))
        if user_type == 'trm':
            try:
                cursor.execute("create share user_permission_share")
                cursor.execute("grant usage on database {} to share".format(database))
                cursor.execute("grant usage on schema {}.user_permission_test to share".format(database))
                cursor.execute("drop share user_permission_share")
                temp_list.append(["create_share", "success"])
            except Exception as e:
                temp_list.append(["create_share", "failed"])
        try:
            cursor.execute("drop schema user_permission_test cascade")
            temp_list.append(["drop_schema", "success"])
        except Exception as e:
            temp_list.append(["drop_schema", "failed"])
            logger.exception(str(e))
        try:
            cursor.execute("create warehouse user_permission_test_wh")
            cursor.execute("drop warehouse user_permission_test_wh")
            temp_list.append(["create_warehouse", "success"])
        except Exception as e:
            temp_list.append(["create_warehouse", "failed"])
            logger.exception(str(e))
        operations.append(temp_list)
    if user_type in ['third_party_app', 'temporary', 'customer']:
        admin_cursor.execute("create schema user_permission_test")
        admin_cursor.execute("create table user_permission_test.test_permission as select current_timestamp as time")
        try:
            cursor.execute("select * from {}.user_permission_test.test_permission".format(database))
            temp_list = ["read_data", "success"]
        except Exception as e:
            temp_list = ["read_data", "failed"]
            logger.exception(str(e))
        admin_cursor.execute("drop schema user_permission_test")
        try:
            cursor.execute("create warehouse user_permission_test_wh")
            cursor.execute("drop warehouse user_permission_test_wh")
            temp_list.append(["create_warehouse", "success"])
        except Exception as e:
            temp_list.append(["create_warehouse", "failed"])
            logger.exception(str(e))
        operations.append(temp_list)
    logger.info("revoking access on DBA warehouse")
    admin_cursor.execute("revoke usage on warehouse DBA_WH from role {}_role".format(database))
    # release the resources
    admin_connection.close()
    connection.close()
    logger.info("Summary: user: {}, account: {}, pod: {} \n\n".format(username,account,pod))
    logger.info(tabulate(operations, headers=['Operation', 'Status']))


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