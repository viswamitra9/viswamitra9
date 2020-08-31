# Owner       : Srinivasarao Oguri
# Description : This is an utility program used to manage snowflake

import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import logging
import json
import sys
import pyodbc
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


def setup_logging(logfile):
    print("Please check the logfile {} for details".format(logfile))
    # default log level for root handler
    logger.setLevel(logging.INFO)
    # creating file handler
    ch = logging.FileHandler()
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
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
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
        cursor = connection.cursor()
        connection.autocommit(True)
        return connection, cursor
    except Exception as e:
        logger.error("Failed to create connection to account : {} with error {}".format(account, e))
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


def create_default_roles(account, pod):
    """
    PURPOSE:
        Create default roles which are used to manage the user privileges. Below are the roles we create
        warehouse_owner  : role with full permissions to create and manage warehouses
        share_owner      : role with permissions to create share
        monitoring_owner : role with permissions to monitor the login history , cost usage etc
    Returns:
        null
    """
    try:
        logger.info("Creating super user connection to create default roles")
        connection, cursor = get_admin_connection(account, pod)
        # create default roles
        cursor.execute("create role if not exists warehouse_owner")
        cursor.execute("grant create warehouse on account to warehouse_owner")
        cursor.execute("create role if not exists monitoring_owner")
        cursor.execute("grant imported privileges on database snowflake to role monitoring_owner")
        cursor.execute("create role if not exists share_owner")
        cursor.execute("grant CREATE SHARE on account to role share_owner")
        # grant the roles to accountadmin
        cursor.execute("grant share_owner to role accountadmin")
        cursor.execute("grant warehouse_owner to role accountadmin")
        cursor.execute("grant monitoring_owner to role accountadmin")
    except Exception as e:
        logger.error("error {} encountered while creating roles in pod {}".format(str(e), pod))
        raise Exception("error {} encountered while creating roles in pod {}".format(str(e), pod))
    connection.close()


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
        cursor.execute("create role if not exists trm_role")
        cursor.execute("use database {}".format(dbname))
        logger.info("DB roles are created")
        # Every Snowflake account has storage integration created, granting usage permissions on it to db roles
        logger.info("Giving permissions on storage integration to default database roles")
        cursor.execute("grant usage on integration s3_{}_integration to role {}_owner".format(pod,dbname))
        cursor.execute("grant usage on integration s3_{}_integration to role {}_reader".format(pod,dbname))
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
        cursor.execute("grant create share on account to role trm_role")
        # granting default database roles to account admin
        cursor.execute("grant role {}_reader to role accountadmin".format(dbname))
        cursor.execute("grant role {}_owner to role accountadmin".format(dbname))
        cursor.execute("grant role trm_role to role accountadmin".format(dbname))
    except Exception as e:
        logger.error("Failed to create database {} in account {} with error {}".format(dbname, account, str(e)))
        raise Exception("Failed to create database {} in account {} with error {}".format(dbname, account, str(e)))
    connection.close()


def create_user(account, username, pod, user_type, dbname='arcesium_data_warehouse', **kwargs):
    """
    PURPOSE:
        create snowflake user, users are different type in Snowflake, refer to
        http://wiki.ia55.net/pages/viewpage.action?spaceKey=TECHDOCS&title=Snowflake+user+management
        This function will create a role for every user with "username_role", grant the permissions to the role
        and assign the role as default role and write password to vault. Make an entry into the DBMONITOR server.
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    assert user_type in USER_TYPE, "usertype should be anyone of {}".format(USER_TYPE)
    # role for every user with unique password
    user_role = "{}_role".format(username)
    db_reader = "{}_reader".format(dbname)
    db_owner  = "{}_owner".format(dbname)
    password  = get_unique_password()
    # before creating the users create the default roles
    create_default_roles(account, pod)
    connection, cursor = get_admin_connection(account, pod)
    cursor.execute("create role if not exists {}".format(user_role))
    cursor.execute("create user if not exists {} password='{}' DEFAULT_ROLE={}".format(username, password, user_role))
    cursor.execute("grant role {} to user {}".format(user_role, username))
    # grant required roles to the user role
    user_type = str(user_type).lower()
    # create application user
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
        cursor.execute("grant role {} to role {}".format(db_owner, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # create temporary user
    if user_type == 'temporary':
        if 'retention' not in kwargs:
            raise Exception("retention argument is required for temporary users")
        cursor.execute("grant role {} to role {}".format(db_reader, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
        cursor.execute("alter user {} set DAYS_TO_EXPIRY  = {}".format(username, kwargs['retention']))
    # create user for app_team
    if user_type == 'app_team':
        if 'env' not in kwargs:
            raise Exception("env (environment) argument is required for app team (human) user creation")
        if kwargs['env'] not in ['dev', 'qa']:
            cursor.execute("drop role {}".format(user_role))
            cursor.execute("drop user {}".format(username))
            raise Exception("application team(human) users are not created in prod or uat environment")
        cursor.execute("grant role {} to role {}".format(db_owner, user_role))
        cursor.execute("grant role warehouse_owner to role {}".format(user_role))
    # write password to vault and make entry into SQL server
    sql_cur, sql_conn = sql_connect()
    if user_type == 'app':
        vaultpath   = APP_VAULT.replace("$POD", pod).replace("$APPNAME", kwargs['appname'])\
            .replace("$DBNAME", dbname).replace("$USERNAME", username)
        cname       = "{}.snowflakecomputing.com".format(account)
        secret      = json.dumps({'cname': cname, 'account': account, 'password': password, 'database': dbname})
        vaultutil.write_secret_to_vault(vaultpath, secret)
        # write to sql server inventory table
        vaultpath = APP_VAULT.replace("$APPNAME", kwargs['appname']).replace("$DBNAME", dbname).\
            replace("$USERNAME", username)
        sql_cur.execute("insert into dbainfra.dbo.snowflake_users(username, usertype, vaultpath) "
                        "values ('{}', '{}', '{}')".format(username, user_type, vaultpath))
    else:
        vaultpath = OTHER_VAULT.replace("$POD", pod).replace("$USERNAME", username)
        cname     = "{}.snowflakecomputing.com".format(account)
        secret    = json.dumps({'cname': cname, 'account': account, 'password': password, 'database': dbname})
        vaultutil.write_secret_to_vault(vaultpath, secret)
        # write to sql server inventory table
        vaultpath = OTHER_VAULT.replace("$USERNAME", username)
        sql_cur.execute("insert into dbainfra.dbo.snowflake_users(username, usertype, vaultpath) "
                        "values ('{}', '{}', '{}')".format(username, user_type, vaultpath))
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
        sql_cur.execute("select vaultpath from dbainfra.dbo.snowflake_users where username = '{}'".format(username))
        result = sql_cur.fetchall()
        if not result:
            raise Exception("No entry for this user in dbainfra.dbo.snowflake_users table")
        for i in result:
            vaultpath  = i[0]
            logger.info("writing user {} password to vault path {}".format(username, vaultpath))
            # write password to vault
            vaultpath = vaultpath.replace("$POD", pod)
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
        drop user from snowflake account
    INPUTS:
        account (format is account.<region>.privatelink), username, pod
    """
    try:
        logger.info("Creating super user user connection to account {}".format(account))
        connection, cursor = get_admin_connection(account, pod)
        logger.info("Created super user connection to account {}".format(account))
        logger.info("Dropping user {} from account {}".format(username,account))
        cursor.execute("drop user if exists {}".format(username))
        cursor.execute("drop role if exists {}_role".format(username))
        logger.info("user {} dropped from pod {}".format(username, pod))
    except Exception as e:
        logger.error("error occurred while dropping user {} from account {} , error : {}".
                     format(username, account, str(e)))
        raise Exception("error encountered while dropping user {} from account {}".format(username, account))


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


def prepare_account(account, region, env, pod):
    try:
        admin_pass = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/admin'.format(pod))
        password   = json.loads(admin_pass)['password']
        logger.info("Creating super user connection")
        connection, cursor = get_snowflake_connection(account, 'admin', password)
        logger.info("Created super user connection")
        logger.info("Dropping unwanted users")
        cursor.execute("drop user if exists MNDINI_SFC")
        cursor.execute("drop user if exists APATEL_SFC")
        logger.info("Dropped users : MNDINI_SFC and APATEL_SFC")
        logger.info("Creating required databases")
        cursor.execute("create database if not exists audit_archive")
        password = get_unique_password()
        logger.info("Creating sa user")
        cursor.execute("create user if not exists sa password = '{}' "
                       "default_role = accountadmin MUST_CHANGE_PASSWORD=FALSE".format(password))
        cursor.execute("grant role accountadmin to user sa")
        # set key rotation every year
        cursor.execute("alter account set PERIODIC_DATA_REKEYING = TRUE")
        if str(env).lower() == 'prod':
            cursor.execute("alter account set DATA_RETENTION_TIME_IN_DAYS = 35")
        # write password to vault
        path = "/secret/v2/snowflake/{}/db/sa".format(pod)

        logger.info("Making entry into database inventory")
        cur_sql_dest, conn_sql_dest = sql_connect()
        instance = "{}.{}.privatelink.snowflakecomputing.com".format(account,region)
        query = "insert into database_server_inventory " \
                "(Dataserver,Env,Host,IsActive,Monitor,ServerType,FriendlyName,Pod,ClientDbState) " \
                "values('{}','{}','{}','{}','{}','{}','{}','{}','{}')".\
                        format(host,account_env,host,'yes','yes','snowflake',account,pod,'onboarding')
        cur_sql_dest.execute(query)
        conn_sql_dest.close()
        # apply the network policy
        logger.info("Creating network policy block_public and pplying to account")
        admin_cur.execute("CREATE OR REPLACE NETWORK POLICY block_public ALLOWED_IP_LIST=('125.18.12.160/28', '115.112.81.240/28','10.12.0.0/17','149.77.95.64/29') BLOCKED_IP_LIST=('54.172.224.181','54.174.16.130')")
        admin_cur.execute("alter account set network_policy = block_public")
    except:
        raise Exception("Failed to prepare the account")
