import textwrap
import argparse
import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import string
import logging
import subprocess
import json
from datetime import datetime
from tabulate import tabulate
import os, sys, stat
import pyodbc


for logger_name in ['snowflake.connector', 'botocore', 'boto3']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    ch = logging.FileHandler('/g/dba/logs/snowflake/snowflake_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S")))
    ch.setLevel(logging.INFO)
    ch.setFormatter(SecretDetector('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
    logger.addHandler(ch)


def sql_connect():
    # create a SQL connection to DBMONITOR1B database and return the connection and cursor object
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logger.error("Error while creating database connection to DBMONITOR server {}".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def get_user_password(vaultpath):
    retry_count = 0
    while retry_count <= 10:
        command = "vault read -field=secret {}".format(vaultpath)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        passw, err = pipes.communicate()
        if pipes.returncode == 0:
            password=passw.decode('utf-8')
            command = "echo '{}' | grep -v 'Could not get working directory' | tr -d '\\n'".format(str(password))
            pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
            passw, err = pipes.communicate()
            return str(passw.decode('utf-8'))
        elif pipes.returncode == 2:
            password=passw.decode('utf-8')
            command = "echo '{}' | grep -v 'Could not get working directory' | tr -d '\\n'".format(str(password))
            pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
            passw, err = pipes.communicate()
            return str(passw.decode('utf-8'))
        else:
            logger.warning("Error while reading password for user: sa in vault path {}, reading again : {} attempt".format(vaultpath,retry_count))
            time.sleep(sleep_time)
            retry_count = retry_count + 1
            continue
    return 1


def get_dba_connection(account,username,password):
    "to create snowflake connection"
    try:
        conn = snowflake.connector.connect(
        account=account,
        user=username,
        password=password,
        database='DEMO_DB',
        schema='public',
        insecure_mode=True
        )
    except Exception as e:
        raise Exception("Failed to obtain dba connection : {}".format(e))
    cur = conn.cursor()
    logger.info("Checking for dba warehouse and create it if not exists")
    cur.execute("create warehouse if not exists DBA_WH with WAREHOUSE_SIZE=small")
    cur.execute("use role accountadmin")
    cur.execute("use warehouse DBA_WH")
    return conn,cur


def get_unique_password():
    "Generate a unique password for user"
    account  = 'arc1000.us-east-1.privatelink'
    username = 'sa'
    password = get_user_password('/secret/v2/snowflake/{}/db/sa'.format('terra'))
    conn, cur = get_dba_connection(account,username,password)
    cur.execute("create database if not exists audit_archive")
    cur.execute("create sequence if not exists audit_archive.public.password_generator")
    cur.execute("select md5(select audit_archive.public.password_generator.nextval)")
    result = cur.fetchone()
    basevalue = result[0]
    rand_num = random.randint(1, 31)
    str1 = basevalue[:rand_num]
    str2 = basevalue[rand_num:]
    password = str1.upper() + str2
    return password


def get_user_connection(account,host,dbname,username,password):
    "to create snowflake connection"
    try:
        conn = snowflake.connector.connect(
        account=account,
        host=host,
        user=username,
        password=password,
        database=dbname,
        schema='PUBLIC',
        protocol='https',
        warehouse='DBA_WH',
        insecure_mode=True
        )
    except Exception as e:
        raise Exception("Failed to obtain user connection")
    cur = conn.cursor()
    return conn,cur


# verify_user_permissions('terra','cocoa','arcesium_data_warehouse','cocoa_app','owner','y')
def verify_user_permissions(pod,appname,dbname,username,permission,create_warehouse,vaultpath):
    operations = []
    logger.info("Getting dba connection")
    sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
    passw = get_user_password('{}'.format(vaultpath))
    secret     = json.loads(passw)
    host       = secret['cname']
    password   = secret['password']
    account    = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
    dba_conn,dba_cur = get_dba_connection(account,'sa',sa_pass)
    logger.info("connecting to database using user password")
    logger.info("giving temporary access to DBA warehouse to test connection")
    sql = "grant usage on warehouse DBA_WH to role {}_{}".format(dbname,permission)
    dba_cur.execute(sql)
    logger.info("granted access on warehouse")
    logger.info("testing user connection and access permissions")
    conn, cur = get_user_connection(account,host,dbname,username,password)
    cur.execute("use warehouse DBA_WH")
    if permission == 'owner':
        cur.execute("create schema dba_permission_test")
        temp_list = ["create_schema","success"]
        operations.append(temp_list)
        cur.execute("create table dba_permission_test.test_permission as select current_timestamp as time")
        temp_list = ["create_table","success"]
        operations.append(temp_list)
        cur.execute("drop schema dba_permission_test cascade")
        temp_list = ["drop_schema","success"]
        operations.append(temp_list)
    if permission == 'reader':
        dba_cur.execute("create schema {}.dba_permission_test".format(dbname))
        dba_cur.execute("create table {}.dba_permission_test.test_permission as select current_timestamp as time".format(dbname))
        cur.execute("select * from {}.dba_permission_test.test_permission".format(dbname))
        temp_list = ["read_data","success"]
        operations.append(temp_list)
        dba_cur.execute("drop schema {}.dba_permission_test cascade".format(dbname))
    if create_warehouse == 'y':
        cur.execute("create warehouse {}_permission_test with warehouse_size=xsmall".format(username))
        temp_list = ["create_warehouse","success"]
        operations.append(temp_list)
        cur.execute("alter warehouse {}_permission_test set warehouse_size=small".format(username))
        temp_list = ["upsize_warehouse","success"]
        operations.append(temp_list)
        cur.execute("drop warehouse {}_permission_test".format(username))
        temp_list = ["drop_warehouse","success"]
        operations.append(temp_list)
    logger.info("revoking access on DBA warehouse")
    dba_cur.execute("revoke usage on warehouse DBA_WH from role {}_{}".format(dbname,permission))
    dba_conn.close()
    conn.close()
    logger.info("Summary: user: {}, account: {}, pod: {},cname: {}".format(username,account,pod,host))
    logger.info(tabulate(operations, headers=['Operation', 'Status']))


#create_database('arc1500','arc1500.us-east-1.privatelink.snowflakecomputing.com','arcesium_data_warehouse','baamuat')
# conn,cur = get_dba_connection('arc1000','arcterra.us-east-1.privatelink.snowflakecomputing.com','sa',sa_pass)
def create_database(account,host,dbname,pod):
    try:
        logger.info("Creating DBA connection")
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        dba_conn,dba_cur = get_dba_connection(account,'sa',sa_pass)
        logger.info("Created a database connection")
        dba_cur.execute("use role accountadmin")
        dba_cur.execute("create database if not exists {}".format(dbname))
        dba_cur.execute("create role if not exists {}_reader".format(dbname))
        dba_cur.execute("create role if not exists {}_owner".format(dbname))
        dba_cur.execute("use database {}".format(dbname))
        dba_cur.execute("create schema if not exists looker_scratch")
        logger.info("DB roles are created")
        dba_cur.execute("grant all on database {} to {}_owner".format(dbname,dbname))
        dba_cur.execute("grant all on all schemas in database {} to {}_owner".format(dbname,dbname))
        dba_cur.execute("grant all on future schemas in database {} to {}_owner".format(dbname,dbname))
        dba_cur.execute("grant all on all tables in database {} to {}_owner".format(dbname,dbname))
        dba_cur.execute("grant all on future tables in database {} to {}_owner".format(dbname,dbname))
        dba_cur.execute("grant usage on database {} to {}_reader".format(dbname,dbname))
        dba_cur.execute("grant usage on all schemas in database {} to {}_reader".format(dbname,dbname))
        dba_cur.execute("grant usage on future schemas in database {} to {}_reader".format(dbname,dbname))
        dba_cur.execute("grant select on all tables in database {} to {}_reader".format(dbname,dbname))
        dba_cur.execute("grant select on future tables in database {} to {}_reader".format(dbname,dbname))
        dba_cur.execute("grant all on schema looker_scratch to {}_reader".format(dbname))
        logger.info("Giving permissions on storage integration")
        dba_cur.execute("grant usage on integration s3_{}_integration to role {}_owner".format(pod,dbname))
        dba_cur.execute("grant usage on integration s3_{}_integration to role {}_reader".format(pod,dbname))
        logger.info("permissions granted to newly created db roles")
        dba_cur.execute("grant role {}_reader to role accountadmin".format(dbname))
        dba_cur.execute("grant role {}_owner to role accountadmin".format(dbname))
    except:
        raise Exception("Failed to create database")


# drop_database('arc1000','arc1000.us-east-1.privatelink.snowflakecomputing.com','arcesium_data_warehouse')
def drop_database(account,host,dbname,pod):
    try:
        logger.info("Creating DBA connection")
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        conn,cur = get_dba_connection(account,'sa',sa_pass)
        logger.info("Created a database connection")
        cur.execute("use role accountadmin")
        cur.execute("drop database if exists {} cascade".format(dbname))
        cur.execute("drop role if exists {}_reader".format(dbname))
        cur.execute("drop role if exists {}_owner".format(dbname))
        logger.info("DB roles and database are dropped")
    except:
        raise Exception("Failed to drop database")


# create_user('baamuat','arc1500','arc1500.us-east-1.privatelink.snowflakecomputing.com',' ','arcesium_data_warehouse','looker_user','READER','y','n')
def create_user(pod,account,host,appname,dbname,username,permission,create_warehouse,user_type):
    try:
        userrole = '{}_role'.format(username)
        dbrole = '{}_{}'.format(dbname,permission)
        logger.info("Creating DBA connection")
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        conn,cur = get_dba_connection(account,'sa',sa_pass)
        password = get_unique_password()
        logger.info("Created a database connection")
        logger.info("creating role for user")
        cur.execute("create role if not exists {}".format(userrole))
        logger.info("Creating user")
        sql = "create user if not exists {} password = '{}' default_role = {} MUST_CHANGE_PASSWORD=FALSE".format(username,password,userrole)
        cur.execute(sql)
        logger.info("user created")
        logger.info("Grating permission")
        sql = "grant role {} to role {}".format(dbrole,userrole)
        cur.execute(sql)
        cur.execute("grant role {} to user {}".format(userrole,username))
        if create_warehouse == 'y':
            cur.execute("create role if not exists warehouse_owner")
            cur.execute("grant create warehouse on account to warehouse_owner")
            cur.execute("grant role warehouse_owner to role {}".format(userrole))
            logger.info("Granted permissions to create warehouse in account")
        cur.execute(sql)
        if user_type == 'app':
            path = "/secret/v2/{}/{}/db/snowflake/{}/{}".format(appname,pod,dbname,username)
        else:
            path = "/secret/v2/snowflake/{}/db/{}".format(pod,username)
        logger.info("writing password to vault")
        try:
            # writing to application vault
            temp_var = {'cname':host,'password':password,'account':account,'database':dbname}
            pvalue = json.dumps(temp_var)
            appvault = subprocess.Popen(['vault write {} {}=\'{}\''.format(path,'secret',pvalue)],stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            (output, err) = appvault.communicate()
            if appvault.returncode != 0:
                logger.error("Error while writing to vault: {}".format(path))
                logger.error(err)
                sys.exit(1)
            logger.info(output)
        except:
            logger.error("error occured while writing to vault")
        logger.info("wrote password to vault")
        print("pod name : {} password of the user {} is {}".format(pod,username,password))
        logger.info("Checking user access privilages")
        verify_user_permissions(pod,appname,dbname,username,permission,create_warehouse,path)
    except:
        raise Exception("Failed to create user")


def reset_dba_password(account,username,pod):
    """This function is used to reset password for dba user"""
    logger.info("Creating admin user connection to account {}".format(account))
    try:
        conn,cur = get_dba_connection(account)
        logger.info("Created a admin connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Resetting password for user {}".format(username))
        cur.execute("alter user {} set password = '{}' must_change_password=False".format(username,password))
        logger.info("Password reset for user {}".format(username))
        vaultpath = "/secret/v2/snowflake/{}/db/{}".format(pod,username)
        logger.info("wriring user {} password to vault path {}".format(username,vaultpath))
    except Exception as e:
        logger.error("error while user password reset, error : {}".format(str(e)))
        sys.exit(1)
    try:
        writetovault = subprocess.Popen(['vault write {} {}=\'{}\''.format(vaultpath, 'secret', password)], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        (output, err) = writetovault.communicate()
        if writetovault.returncode != 0:
            logger.error("Error while writing to vault: {}".format(vaultpath))
            logger.error(err)
            sys.exit(1)
        logger.info(output)
    except Exception as e:
        logger.error("error while writing password to vault {} , error : {}".format(vaultpath,str(e)))
        sys.exit(1)
    logger.info("wrote password to vault")


def create_dba_user(host,username,pod):
    "This function is used to create a DBA user"
    try:
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        logger.info("Creating admin user connection to account {}".format(account))
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        conn,cur = get_dba_connection(account,'sa',sa_pass)
        logger.info("Created a admin connection to account {}".format(account))
        password = get_unique_password()
        logger.info("Creating admin user {}".format(username))
        cur.execute("create user {} password = '{}' default_role=accountadmin must_change_password=False".format(username,password))
        cur.execute("grant role accountadmin to user {}".format(username))
        logger.info("Created admin user {}".format(username))
        vaultpath = "/secret/v2/snowflake/{}/db/{}".format(pod,username)
        logger.info("wriring user {} password to vault path {}".format(username,vaultpath))
        writetovault = subprocess.Popen(['vault write {} {}=\'{}\''.format(vaultpath, 'secret', password)], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        (output, err) = writetovault.communicate()
        if writetovault.returncode != 0:
            logger.error("Error while writing to vault: {}".format(vaultpath))
            logger.error(err)
            sys.exit(1)
        logger.info(output)
    except:
        logger.error("error occurred while creating user {} in pod {}".format(username,pod))
    logger.info("wrote password to vault")



# drop_user('arc1000','arc1000.us-east-1.privatelink.snowflakecomputing.com','cocoa_app')
def drop_user(account,host,username,pod):
    try:
        logger.info("Creating DBA connection")
        sa_pass = get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        conn,cur = get_dba_connection(account,'sa',sa_pass)
        logger.info("Created a database connection")
        logger.info("Dropping user")
        sql = "drop user if exists {}".format(username)
        cur.execute(sql)
        sql = "drop role if exists {}_role".format(username)
        logger.info("user dropped")
    except:
        raise Exception("Failed to drop user")


# prepare account for usage like remove the snowflake dummy users, add network policy
def prepare_account(account,region,account_env,pod):
    try:
        host = "{}.{}.privatelink.snowflakecomputing.com".format(account,region)
        logger.info("Creating admin connection")
        admin_pass = get_user_password('/secret/v2/snowflake/{}/db/admin'.format(pod))
        account = "{}.{}.{}".format(host.split(sep='.')[0],host.split(sep='.')[1],host.split(sep='.')[2])
        admin_conn, admin_cur = get_dba_connection(account,'admin',admin_pass)
        logger.info("Created a database connection")
        logger.info("Dropping unwanted users")
        admin_cur.execute("drop user if exists MNDINI_SFC")
        admin_cur.execute("drop user if exists APATEL_SFC")
        logger.info("Dropped users : MNDINI_SFC and APATEL_SFC")
        logger.info("Creating required databases")
        admin_cur.execute("create database if not exists audit_archive")
        password = get_unique_password()
        logger.info("Creating sa user")
        sql = "create user if not exists sa password = '{}' default_role = accountadmin MUST_CHANGE_PASSWORD=FALSE".format(password)
        admin_cur.execute(sql)
        admin_cur.execute("grant role accountadmin to user sa")
        # set rekeying data every year
        admin_cur.execute("alter account set PERIODIC_DATA_REKEYING = TRUE")
        if str(account_env).lower() == 'prod':
            admin_cur.execute("alter account set DATA_RETENTION_TIME_IN_DAYS = 90")
        # write password to vault
        path = "/secret/v2/snowflake/{}/db/sa".format(pod)
        dbavault = subprocess.Popen(['vault write {} {}=\'{}\''.format(path,'secret',password)],stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
        (output, err) = dbavault.communicate()
        if dbavault.returncode != 0:
            logger.error("Error while writing to vault: {}".format(path))
            logger.error(err)
            sys.exit(1)
        logger.info("Making entry into database inventory")
        cur_sql_dest, conn_sql_dest = sql_connect()
        instance = "{}.{}.privatelink.snowflakecomputing.com".format(account,region)
        query = "insert into database_server_inventory (Dataserver,Env,Host,IsActive,Monitor,ServerType,FriendlyName,Pod,ClientDbState) values('{}','{}','{}','{}','{}','{}','{}','{}','{}');".format(host,account_env,host,'yes','yes','snowflake',account,pod,'onboarding')
        cur_sql_dest.execute(query)
        conn_sql_dest.close()
        # apply the network policy
        logger.info("Creating network policy block_public and pplying to account")
        admin_cur.execute("CREATE OR REPLACE NETWORK POLICY block_public ALLOWED_IP_LIST=('125.18.12.160/28', '115.112.81.240/28','10.12.0.0/17','149.77.95.64/29') BLOCKED_IP_LIST=('54.172.224.181','54.174.16.130')")
        admin_cur.execute("alter account set network_policy = block_public")
    except:
        raise Exception("Failed to prepare the account")


#parse the infput arguments
def parse_arguments():
    #take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
    example :
    sudo -u sqlexec python snowflake_create_delete_database.py --create_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --delete_database --pod baamuat --dbname arcesium_data_warehouse
                                  OR
    sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username cocoa_app --dbname arcesium_data_warehouse --permission owner --user_type app --appname cocoa --create_warehouse y
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
    task.add_argument("--create_dba_user", action='store_true', help="To create dba user")
    task.add_argument("--delete_user",action='store_true',help="To delete a user")
    task.add_argument('--prepare_account', action='store_true', help="To prepare a new snowflake account")
    # Instances on which we need to perform the task
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need to create/delete , example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    # Arguments required to perform the tasks
    parser.add_argument('--dbname', dest='dbname', help='Provide the db name, example: test')
    parser.add_argument('--username', dest='username', help='Provide the user name, example: test')
    parser.add_argument('--permission', dest='permission', choices=['owner','reader'], default='read',help='Provide the permission to be granted to the user, example: "reader" "owner"')
    parser.add_argument('--user_type', dest='user_type',choices=['app','user'],default='app',help='Provide the choice of writing to app vault, example: app/user')
    parser.add_argument('--create_warehouse', dest='create_warehouse',choices=['y','n'],default='y',help='give permission to create warehouse, example: y/n')
    parser.add_argument('--appname', dest='appname',help='Give the appname, example: iris')
    parser.add_argument('--account', dest='account', help='Provide the account , example: ama69523')
    parser.add_argument('--region', dest='region', help='Provide the region , example: us-east-1')
    parser.add_argument('--account_env',dest='account_env',help='Provide the environment of new account, example: uat')
    return parser.parse_args()


def main():
    args             = parse_arguments()
    username         = args.username
    dbname           = args.dbname
    permission       = args.permission
    pod              = args.pod
    user_type        = args.user_type
    appname          = args.appname
    env              = args.env
    create_warehouse = args.create_warehouse
    region           = args.region
    account          = args.account
    account_env      = args.account_env

    if args.create_database:
        cmd = 'create_database'
    elif args.delete_database:
        cmd = 'delete_database'
    elif args.create_user:
        cmd = 'create_user'
    elif args.prepare_account:
        cmd = 'prepare_account'
    elif args.create_dba_user:
        cmd = 'create_dba_user'
    else:
        cmd = 'drop_user'

    if cmd == 'create_database' and args.dbname is None:
        print('Missing required field for database creation')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --create_database --pod baamuat --dbname arcesium_data_warehouse")
        sys.exit(1)
    if cmd == 'delete_database' and args.dbname is None:
        print('Missing required field for database deletion')
        print("example : sudo -u sqlexec python snowflake_create_delete_database.py --delete_database --pod baamuat --dbname arcesium_data_warehouse")
        sys.exit(1)
    if cmd == 'create_dba_user' and args.username is None:
        print('Missing required field for user creation')
        print('example : sudo -u sqlexec python snowflake_create_delete_database.py --create_dba_user --pod baamuat --username oguri_sa')
        sys.exit(1)
    if args.user_type == 'user':
        if cmd == 'create_user' and (args.username is None or args.dbname is None or args.permission is None or args.user_type is None or args.create_warehouse is None):
            print('Missing required field for create user')
            print("example : sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username looker_user --dbname arcesium_data_warehouse --permission reader --user_type user --create_warehouse y")
            sys.exit(1)
    if args.user_type == 'app':
        if cmd == 'create_user' and (args.username is None or args.dbname is None or args.permission is None or args.user_type is None or args.appname is None or args.create_warehouse is None):
            print('Missing required field for create user')
            print("example : sudo -u sqlexec python snowflake_create_delete_database.py --create_user --pod baamuat --username cocoa_app --dbname arcesium_data_warehouse --permission owner --user_type app --appname cocoa --create_warehouse y")
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
    # create SQL connection to get information about instances
    cur_sql_dest, conn_sql_dest = sql_connect()
    if args.pod:
        query = "select lower(Host),lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(args.pod)
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
            # instances.append('{}'.format(instance[0]))
    if args.env:
        query = "select lower(Host),lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and IsActive=1"
        if args.env != 'all':
            query = "select lower(Host),lower(pod) from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake' and lower(Env)='{}' and IsActive=1".format(str(args.env).lower())
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        for instance in result:
            instances[instance[0]] = instance[1]
            # instances.append('{}'.format(instance[0]))
    conn_sql_dest.close()

    for host in instances:
        if cmd   == 'create_database':
            logger.info("Creating database: {} on instance {}".format(dbname, host))
            account = str(host).split('.')[0]
            pod     = instances[host]
            create_database(account,host,dbname,pod)
        elif cmd == 'create_user':
            logger.info("Creating user: {} on instance {}".format(username, host))
            account = str(host).split('.')[0]
            pod     = instances[host]
            create_user(pod,account,host,appname,dbname,username,permission,create_warehouse,user_type)
        elif cmd == 'delete_database':
            logger.info("Deleting database: {} on instance {}".format(dbname, host))
            account = str(host).split('.')[0]
            pod     = instances[host]
            drop_database(account,host,dbname,pod)
        elif cmd == 'drop_user':
            logger.info("Deleting user: {} on instance {}".format(username, host))
            account = str(host).split('.')[0]
            pod     = instances[host]
            drop_user(account,host,username,pod)
        elif cmd == 'create_dba_user':
            logger.info("Creating user {} on instance {}".format(username,host))
            account = str(host).split('.')[0]
            pod     = instances[host]
            create_dba_user(host,username,pod)
    if cmd == 'prepare_account':
        logger.info("Preparing new snowflake account {}".format(account))
        prepare_account(account,region,account_env,pod)


if __name__ == "__main__":
    main()