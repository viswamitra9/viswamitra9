#!/usr/local/bin/python
import logging
import shlex
import os
import subprocess
import sys
import time
import pyodbc
from retrying import retry
import requests
from requests_kerberos import HTTPKerberosAuth
sys.path.append('/g/dba/rds/')
sys.path.append('/g/dba/radarutil/')

import arcesium.infra.boto as arcboto
import json
import boto3
import psycopg2
from botocore.exceptions import ClientError
from datetime import datetime
import random
import string
from botocore.config import Config
config = Config(
    retries = dict(
        max_attempts = 15
    )
)

# This date_t variable used to generate unique names for the database backups
date_t = format(datetime.now().strftime("%d-%m-%Y-%H-%M-%S"))
sleep_time = 200


def get_rds_ec2_kms_clients(account, region):
    try:
        arcboto.install()
        session = boto3.session.Session(profile_name='{}/dba'.format(account))
        rds = session.client('rds', region_name='{}'.format(region), config=config)
        ec2 = session.client('ec2', region_name='{}'.format(region), config=config)
        kms = session.client('kms', region_name='{}'.format(region), config=config)
        iam = session.client('iam', region_name='{}'.format(region), config=config)
        return rds, ec2, kms, iam
    except ClientError as e:
        logging.error('exception while fetching boto3 connection', e.response['Error']['Code'])
        sys.exit(1)


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def connect(hostname,username,passw,db_name):
    # create a connection to postgresql database and return the connection and cursor object
    try:
        conn_dest = psycopg2.connect(host=hostname, user=username, password=passw, dbname=db_name,sslmode="require")
        cur_dest = conn_dest.cursor()
        conn_dest.autocommit = True
        return cur_dest, conn_dest
    except Exception as e:
        logging.error("Error while creating database connection to "+hostname+" using user: "+username)
        raise Exception("Error while creating database connection to " + hostname + " using user: " + username)


def check_db_exists(destination_endpoint, dbname):
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur_dest, conn_dest = connect(destination_endpoint,'sa',sa_pass,'postgres')
    query = "select 1 from pg_database where datname='"+dbname+"'"
    cur_dest.execute(query)
    rows = cur_dest.fetchall()
    if len(rows) == 0:
        return 1
    else:
        return 0


def make_entry_for_instance(instancename,account,region):
    cur_sql_dest, conn_sql_dest = sql_connect()
    query = "insert into [dbainfra].[dbo].[pg_old_instances](instancename,account,region,deleted) values('{}','{}','{}',0)".format(instancename,account,region)
    conn_sql_dest.autocommit = True
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def sql_connect():
    # create a SQL connection to DBMONITOR1B database and return the connection and cursor object
    try:
        conn_sql_dest = pyodbc.connect('DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor5b.win.ia55.net;APP=DBRefreshUtil;')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logging.error("Error while creating database connection to DBMONITOR server {}".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def get_techops_request():
    cur_sql_dest, conn_sql_dest = sql_connect()
    rows = cur_sql_dest.execute("SELECT * FROM [dbainfra].[dbo].[refresh_desflow_ticket_details]")
    row = rows.fetchone()
    conn_sql_dest.close()
    return str('ArcTechOps#'+str(row.archelpnumber))


def stop_cluster(client,clustername):
    client.stop_db_cluster(DBClusterIdentifier=clustername)
    retry_count = 0
    while retry_count <= 10:
        time.sleep(sleep_time)
        try:
            retry_count += 1
            status = client.describe_db_clusters(DBClusterIdentifier=clustername)['DBClusters'][0]['Status']
            logging.info("iteration : %s, status of the cluster: %s  is %s", retry_count,clustername, status)
            if status == 'stopped':
                logging.info("instance stopped successfully")
                return
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                logging.warning('cluster %s not found, trying again to check the status',clustername)
                raise Exception('cluster %s not found, trying again to check the status',clustername)
            else:
                logging.error('error occurred while stopping cluster%s',clustername, e.response['Error']['Code'])
                raise Exception('error occurred while stopping cluster%s',clustername, e.response['Error']['Code'])


def get_instance_details(client,instance_identifier):
    """
    function to validate the input and implement re-try
    """
    try:
        response = client.describe_db_instances(DBInstanceIdentifier=instance_identifier)
        if response['DBInstances'][0]['Engine'] != 'aurora-postgresql':
            logging.error('The instance : %s, you entered is not Aurora instance', instance_identifier)
            raise Exception('The instance : {}, you entered is not Aurora instance'.format(instance_identifier))
        if response['DBInstances'][0]['DBInstanceStatus'] != 'available':
            logging.error('The instance : %s is not in available state,run the script after the instance is available', instance_identifier)
            raise Exception('The instance : %s is not in available state,run the script after the instance is available', instance_identifier)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            logging.error("The instance : %s does not exists", instance_identifier)
            raise Exception("The instance : %s does not exists", instance_identifier)
        else:
            logging.error("There is an error in finding the instance : %s details :", instance_identifier,e.response['Error']['Code'])
            raise Exception("There is an error in finding the instance : %s details :", instance_identifier,e.response['Error']['Code'])
    return response


def get_cluster_details(client,cluster_identifier):
    # Get the details of cluster
    try:
        response = client.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
    except ClientError as e:
        logging.error('Error while getting details of cluster: %s, error: %s', cluster_identifier,e.response['Error']['Code'])
        raise Exception('Error while getting details of cluster: %s, error: %s', cluster_identifier,e.response['Error']['Code'])
    return response


def check_cluster_status_for_create(client,clusteridentifier):
    # check the status of given cluster
    retry_count = 0
    while retry_count <= 10:
        time.sleep(sleep_time)
        try:
            retry_count += 1
            status = client.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['Status']
            logging.info("iteration : %s, status of the cluster: %s  is %s", retry_count,clusteridentifier, status)
            if status == 'available':
               return 0
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                logging.warning('cluster %s not found, trying again to check the status',clusteridentifier)
                continue
            else:
                logging.error('error occurred while checking cluster %s status %s',clusteridentifier, e.response['Error']['Code'])
                return 1
    return 1


def check_instance_status_for_create(client,instanceidentifier):
    # returns 0 if instance is available within 15 minutes, otherwise return 1
    retry_count = 1
    while retry_count <= 15:
        time.sleep(sleep_time)
        try:
            retry_count += 1
            status = client.describe_db_instances(DBInstanceIdentifier=instanceidentifier)['DBInstances'][0]['DBInstanceStatus']
            logging.info("iteration : %s, status of the instance:%s is %s", retry_count, instanceidentifier, status)
            if status == 'available':
                return 0
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logging.warning('instance %s not found trying again to check the status',instanceidentifier)
                continue
            else:
                logging.error('error while checking instance %s status %s', instanceidentifier, e.response['Error']['Code'])
                return 1
    return 1


def delete_instance(client,instanceidentifier):
    """"
    Returns success if instanceidentifier doesn't exist
    Deletes instance and returns after waiting upto 15 mts for confirmation of deletion
    Fails if instance deletion takes more than 15 minutes
    """
    retry_count = 1
    try:
        query = "select TOP 1 lower(Env),lower(Pod) from dbainfra.dbo.database_server_inventory where lower(Alias) = '"+ str(instanceidentifier).lower()+"'"
        cur_sql_dest, conn_sql_dest = sql_connect()
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchone()
        if result:
            if result[0] == 'prod':
                raise Exception("Production instance {} can not be deleted".format(instanceidentifier))
        client.delete_db_instance(DBInstanceIdentifier=instanceidentifier)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            logging.error('returning success as db instance %s was notfound' , instanceidentifier)
            return 0
        else:
            logging.error('error while deleting %s : %s', instanceidentifier, e.response['Error']['Code'])
            raise Exception('error while deleting %s : %s', instanceidentifier, e.response['Error']['Code'])
    while retry_count <= 15:
        time.sleep(sleep_time)
        try:
            status = client.describe_db_instances(DBInstanceIdentifier=instanceidentifier)['DBInstances'][0]['DBInstanceStatus']
            logging.info("iteration : %s, status of instance %s is %s", retry_count, instanceidentifier, status)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logging.info("Instance deleted successfully")
                return 0
            else:
                logging.error("Instance deletion failed")
                logging.error('error deleting %s :  %s', instanceidentifier,e.response['Error']['Code'])
                raise Exception('error deleting %s :  %s', instanceidentifier,e.response['Error']['Code'])


def delete_cluster(client,clusteridentifier):
    """
     Returns success if clusteridentifier doesn't exist
     Deletes cluster and returns after waiting upto 15 mts for confirmation of deletion
     Fails if instance deletion takes more than 15 minutes
     """
    retry_count = 1
    try:
        cluster_snapshot = clusteridentifier + '-' + date_t + '-weekend-snapshot'
        client.modify_db_cluster(DBClusterIdentifier=clusteridentifier, DeletionProtection=False)
        client.delete_db_cluster(DBClusterIdentifier=clusteridentifier, FinalDBSnapshotIdentifier=cluster_snapshot)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
            logging.error('returning success as db cluster %s was not found',clusteridentifier)
            return 0
        else:
            logging.error('error deleting %s :  %s', clusteridentifier, e.response['Error']['Code'])
            sys.exit(1)
    while retry_count <= 60:
        time.sleep(sleep_time)
        try:
            status = client.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['Status']
            logging.info("iteration : %s, status of cluster %s is %s", retry_count, clusteridentifier, status)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                logging.info("Cluster deleted successfully")
                return 0
            else:
                logging.error("cluster deletion failed")
                logging.error('error deleting %s : %s', clusteridentifier, e.response['Error']['Code'])
                raise Exception('error deleting %s : %s', clusteridentifier, e.response['Error']['Code'])


def create_cluster(client,dbcluster_identifier_clone, input_cluster, subnet_group, vpc_sec_groups, kms_key_id, clusterpgroup):
    """
    Return success if cluster is available
    Creates cluster and returns success after waiting up to 15 mts for the cluster to become available
    In case of failure, retries one more time before bailing out
    """
    retry_count = 0
    while retry_count <= 1:
        try:
            logging.info("creating clone for cluster %s", input_cluster)
            client.restore_db_cluster_to_point_in_time(
                DBClusterIdentifier=dbcluster_identifier_clone,
                RestoreType='copy-on-write',
                SourceDBClusterIdentifier=input_cluster,
                UseLatestRestorableTime=True,
                DBSubnetGroupName=subnet_group,
                VpcSecurityGroupIds=vpc_sec_groups,
                KmsKeyId=kms_key_id,
                DBClusterParameterGroupName=clusterpgroup)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterAlreadyExistsFault':
                ret_code = check_cluster_status_for_create(client,dbcluster_identifier_clone)
                if ret_code == 0:
                    logging.warning("cluster %s already exists", dbcluster_identifier_clone)
                    return 0
            else:
                logging.error('cluster %s creation failed with exceptions %s', dbcluster_identifier_clone, e.response['Error']['Code'])
                raise Exception('cluster %s creation failed with exceptions %s', dbcluster_identifier_clone, e.response['Error']['Code'])
        ret_code = check_cluster_status_for_create(client,dbcluster_identifier_clone)
        if ret_code == 0:
            logging.info("cluster %s created successfully",dbcluster_identifier_clone)
            return 0
        else:
            logging.error("cluster %s creation failed, trying again",dbcluster_identifier_clone)
            retry_count += 1
            ret_delete = delete_cluster(client,dbcluster_identifier_clone)
            if ret_delete == 0:
                logging.info("deleting cluster %s, before retry the creation of cluster",dbcluster_identifier_clone)
            else:
                logging.error("not able to delete cluster %s, during retry",dbcluster_identifier_clone)
                raise Exception("not able to delete cluster %s, during retry",dbcluster_identifier_clone)
    logging.error('cluster %s creation failed with exceptions %s', dbcluster_identifier_clone, e.response['Error']['Code'])
    raise Exception('cluster %s creation failed with exceptions %s', dbcluster_identifier_clone,e.response['Error']['Code'])


def create_instance(client,input_instance_clone, dbinstance_class, preferred_mwindow, dbpgroup, dbcluster_identifier_clone,tags,region,MonitoringRoleArn):
    #function to create RDS instance
    retry = 0
    while retry <= 1:
        try:
            logging.info("trying : %s time creating instance", retry)
            client.create_db_instance(
                DBInstanceIdentifier=input_instance_clone,
                DBInstanceClass=dbinstance_class,
                Engine='aurora-postgresql',
                PreferredMaintenanceWindow=preferred_mwindow,
                DBParameterGroupName=dbpgroup,
                AutoMinorVersionUpgrade=False,
                PubliclyAccessible=False,
                EnablePerformanceInsights=True,
                PerformanceInsightsRetentionPeriod=7,
                Tags=tags,
                AvailabilityZone=region+'a',
                DBClusterIdentifier=dbcluster_identifier_clone,
                MonitoringInterval=30,
                MonitoringRoleArn=MonitoringRoleArn)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceAlreadyExists':
                ret_code = check_instance_status_for_create(client,input_instance_clone)
                if ret_code == 0:
                    logging.warning("instance %s already exists",input_instance_clone)
                    return 0
            else:
                logging.error('instance %s, creation failed with exceptions %s', input_instance_clone, e.response['Error']['Code'])
                raise Exception('instance %s, creation failed with exceptions %s', input_instance_clone, e.response['Error']['Code'])
        # Check the status of Instance creation, wait until Instance is available
        retcode = check_instance_status_for_create(client,input_instance_clone)
        if retcode == 0:
            logging.info("instance %s created successfully",input_instance_clone)
            response = client.modify_db_instance(DBInstanceIdentifier=input_instance_clone,CACertificateIdentifier='rds-ca-2019',ApplyImmediately=True)
            retcode = check_instance_status_for_create(client,input_instance_clone)
            if retcode == 0:
                logging.info("instance {} updated with rds-ca-2019 certificate".format(input_instance_clone))
            return 0
        else:
            logging.error("instance %s creation failed, trying again",input_instance_clone)
            retry += 1
            ret_delete = delete_instance(client,input_instance_clone)
            if ret_delete == 0:
                logging.info("deleting instance: %s, before retry the creation of instance",input_instance_clone)
            else:
                logging.error("not able to delete the instance: %s, during the retry",input_instance_clone)
                raise Exception("not able to delete the instance: %s, during the retry",input_instance_clone)
    raise Exception('Error while creating the instance {}'.format(input_instance_clone))


def rename_instance(client,source_instance, destination_instance):
    # function to rename instance
    try:
        response = client.modify_db_instance(DBInstanceIdentifier=source_instance,
                                             NewDBInstanceIdentifier=destination_instance, ApplyImmediately=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidDBInstanceState':
            logging.info("Instance %s is in invalid state", source_instance)
            return 1
        if e.response['Error']['Code'] == 'DBInstanceAlreadyExists':
            ret_code = check_instance_status_for_create(client,destination_instance)
            if ret_code == 0:
                logging.warning("instance %s already exists", destination_instance)
                return 0
    retcode = check_instance_status_for_create(client,destination_instance)
    if retcode == 0:
        logging.info("the renaming %s to %s completed successfully", source_instance, destination_instance)
        return 0
    else:
        logging.info("the renaming %s to %s failed", source_instance, destination_instance)
        raise Exception("the renaming %s to %s failed", source_instance, destination_instance)


def rename_cluster(client,source_cluster, destination_cluster):
    # Rename cluster
    try:
        response = client.modify_db_cluster(DBClusterIdentifier=source_cluster,
                                            NewDBClusterIdentifier=destination_cluster, ApplyImmediately=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
            logging.error("the cluster %s not found", source_cluster)
            raise Exception("the cluster %s not found", source_cluster)
        if e.response['Error']['Code'] == 'DBClusterAlreadyExistsFault':
            ret_code = check_cluster_status_for_create(client,destination_cluster)
            if ret_code == 0:
                logging.warning("cluster %s already exists", destination_cluster)
                return 0
        else:
            logging.error('error occurred while renaming cluster %s to %s', source_cluster, destination_cluster)
            raise Exception('error occurred while renaming cluster %s to %s', source_cluster, destination_cluster)
    retcode = check_cluster_status_for_create(client,destination_cluster)
    if retcode == 0:
        logging.info("cluster renaming completed successfully %s to %s", source_cluster, destination_cluster)
        return 0
    else:
        logging.error("cluster renaming failed %s to %s", source_cluster, destination_cluster)
        raise Exception("cluster renaming failed %s to %s", source_cluster, destination_cluster)


def make_super_user(endpoint, dbname):
    # Grant all permission to user to make superuser
    try:
        sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
        cur, conn = connect(endpoint, 'sa', sa_pass, dbname)
        query0 = """
        DO $$
        BEGIN
        CREATE ROLE db_owner WITH NOLOGIN;
        EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'not creating role db_owner -- it already exists';
        END
        $$;
        """
        query1 = """
        --- This is used to change the ownership of objects before taking pg_dump from golden instance
        DO
        $do$
        DECLARE
        cur_query record;
        BEGIN
        FOR cur_query in WITH T as (select 'alter schema '||nspname||' owner to db_owner;' as query from pg_namespace n join pg_roles r on (n.nspowner=r.oid and r.rolname not in ('db_owner')) where nspname not like 'pg_toast%' and nspname not like 'pg_temp%' and nspname not in ('pg_catalog','information_schema')
        union all
        select 'alter '||
        CASE c.relkind
        WHEN 'r' THEN 'table '
        WHEN 'v' THEN 'view '
        WHEN 'm' THEN 'materialized view '
        WHEN 'c' THEN 'TYPE '
        WHEN 'f' THEN 'foreign table '
        ELSE '' END ||n.nspname||'.'||c.relname||' owner to db_owner;' as query
        FROM pg_class c JOIN pg_namespace n ON (c.relnamespace = n.oid) JOIN pg_roles r on (c.relowner=r.oid and r.rolname not in ('db_owner'))  
        where n.nspname not like 'pg_toast%' and n.nspname not like 'pg_temp%' and n.nspname not in ('pg_catalog','information_schema') and c.relkind not in ('S','i')
        union all
        select 'alter sequence '||n.nspname||'.'||c.relname||' owner to db_owner;' as query FROM pg_class c JOIN pg_namespace n ON (c.relnamespace = n.oid) JOIN pg_roles r on (c.relowner=r.oid and r.rolname not in ('db_owner'))  where n.nspname not like 'pg_toast%' and n.nspname not like 'pg_temp%' and n.nspname not in ('pg_catalog','information_schema') and c.relkind='S'
        union all
        SELECT 'ALTER FUNCTION ' || quote_ident(s.nspname) || '.' ||quote_ident(s.function_name) || '('||s.parms||') owner TO db_owner' as query
        FROM 
        (
         SELECT 
          nspname
          ,proname AS function_name
          , pg_catalog.oidvectortypes(proargtypes) AS parms
         FROM pg_catalog.pg_proc AS c JOIN pg_namespace n ON (c.pronamespace = n.oid) JOIN pg_roles r on (r.oid=c.proowner and r.rolname not in ('db_owner'))
         WHERE nspname != 'information_schema'
          AND nspname NOT LIKE E'pg\\_%'
         ORDER BY proname
        )s
        union all
        select 'ALTER SERVER '||srvname||' owner to db_owner;' as query from pg_foreign_server
        union all
        select 'alter operator '||oprname||' owner to db_owner;' as query from pg_operator o join pg_roles r on (o.oprowner=r.oid and r.rolname not in ('db_owner','rdsadmin'))
        union all
        select 'alter domain '||typname||' owner to db_owner;' as query from pg_type t join pg_roles r on (r.oid=t.typowner and r.rolname not in ('db_owner','rdsadmin')) where typtype = 'd') select * from T
        union all
        --- Change ownership of table, view, sequences , materialized views, foreign tables to dbowner
        select 'ALTER SCHEMA '||nspname||' owner to db_owner;' from pg_namespace where nspname not like 'pg_toast%' and nspname not like 'pg_temp%' and nspname not in ('pg_catalog','information_schema')
        LOOP
        EXECUTE cur_query.query;
        END LOOP;
        EXECUTE 'grant db_owner to sa';
        END;
        $do$;
        """
        query2 = """
        DO
        $$
        declare
        rec record;
        BEGIN
        FOR rec in select 'GRANT "'||rolname||'" TO sa;' as query from pg_roles where rolname not in 
        ('rdsadmin','dumprestoreuser','rdsrepladmin','rds_superuser','sa')
        and rolname not in (SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON 
        (m.member = b.oid) WHERE m.roleid = (select oid from pg_roles where rolname='sa'))
        LOOP
        EXECUTE rec.query;
        END LOOP;
        return;
        END;
        $$;
        """
        cur.execute(query0)
        cur.execute(query1)
        cur.execute(query2)
        conn.commit()
        conn.close()
        return 0
    except Exception as e:
        logging.error("Exception while making the user as superuser : {}".format(str(e)))
        return 1


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_user_password(vaultpath,user):
    vault_path = "http://vault.ia55.net/v1{}/{}".format(vaultpath,user)
    try:
        response = requests.get(vault_path,auth=HTTPKerberosAuth())
        if response:
            user_pass = response.json()['data'][user]
            return user_pass
        if response.status_code == 404 or response.status_code == 403:
            logging.error("vaultpath does not exists or permission denied".format(vaultpath,response.content))
            return
        else:
            logging.error("Failed to retrieve credentials from {} with error {}, trying again".format(vault_path, response.content))
            raise Exception("Failed to retrieve credentials from {} with error {}, trying again".format(vault_path, response.content))
    except Exception as e:
        logging.error("Failed to retrieve credentials from vault path {} with error {}, trying again".format(vault_path, str(e)))
        raise Exception("Failed to retrieve credentials from vault path {} with error {}".format(vault_path, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_user_list(vaultpath):
    try:
        response = requests.get(vaultpath,auth=HTTPKerberosAuth())
        if response:
            user_names = response.json()['data']['keys']
            return user_names
        else:
            logging.error("Failed to retrieve users list from {} with error {}, trying again".format(vaultpath, response.content))
            raise Exception("Failed to retrieve users list from {} with error {}, trying again".format(vaultpath, response.content))
    except Exception as e:
        logging.error("Failed to retrieve users list from vault path {} with error {}, trying again".format(vaultpath, str(e)))
        raise Exception("Failed to retrieve users list from vault path {} with error {}".format(vaultpath, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_app_user_password(vaultpath,password):
    try:
        vaultpath_req = "http://vault.ia55.net/v1{}".format(vaultpath)
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), data=json.dumps({'secret': password}))
        if response:
            logging.info("Credentials written successfully to {}".format(vaultpath))
        else:
            logging.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
    except Exception as e:
        logging.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath,str(e)))
        raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath,str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_dba_user_password(pod,destination_instance,username,password):
    vault_path = "/secret/default/v1/db-postgres-credentials/password/{}/{}/{}".format(pod, destination_instance,username)
    try:
        vaultpath_req = "http://vault.ia55.net/v1"+vault_path
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), data=json.dumps({username: password}))
        if response:
            logging.info("Credentials written successfully to {}".format(vault_path))
        else:
            logging.error("Failed to write credentials to {} with error {}, trying again".format(vault_path,response.content))
            raise Exception("Failed to write credentials to {} with error {}, trying again".format(vault_path,response.content))
    except Exception as e:
        logging.error("Failed to write credentials to {} with error {}, trying again".format(vault_path, str(e)))
        raise Exception("Failed to write credentials to {} with error {}, trying again".format(vault_path, str(e)))


def backup_database(host, database_name, user, password, filename):
    # Backup given database
    try:
        process = subprocess.Popen(
            ['pg_dump',
             '--dbname=postgresql://{}:{}@{}:5432/{}'.format(user, password, host, database_name),
             '-Fc',
             '-f', filename,
             '-v'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        (stdout, stderr) = process.communicate()
        backup_file = '/g/dba/logs/dbrefresh/backup_{}_{}.log'.format(host.split('.')[0],database_name)
        temp_file = '/g/dba/logs/dbrefresh/backup_tempfile_{}_{}.log'.format(host.split('.')[0],database_name)
        backup_log = open(backup_file, 'w')
        logging.info(stderr)
        backup_log.write(stderr)
        backup_log.close()
        command = "grep -B2 -A3 'does not exist\|could not execute query: ERROR:  database\|ERROR:  permission denied for sequence hints\|could not execute query: ERROR:  must be owner of extension\|already exists\|ERROR:  permission denied for relation pg_' {} > {}".format(backup_file,temp_file)
        process = subprocess.Popen(command, shell=True)
        process.communicate()
        if process.returncode == 0:
            command = "grep -vFf {} {} | grep -vi WARNING | grep -i ERROR".format(temp_file,backup_file)
            process = subprocess.Popen(command, shell=True)
            process.communicate()
            if process.returncode == 1:
                logging.info("backup of database %s completed successfully",database_name)
                return 0
            else:
                logging.error("backup of database %s failed",database_name)
                return 1
        return 0
    except subprocess.CalledProcessError as e:
        logging.error("common::run_command() : [ERROR]: output = %s, error code = %s\n" % (e.output, e.returncode))
        return 1


def get_instance_type(client,instance_name):
    response = client.describe_db_instances(DBInstanceIdentifier=instance_name)
    rds_host = response.get('DBInstances')[0].get('DBInstanceClass')
    return rds_host


def restore_database(client,host, user, password, filename, dbname):
    instance = str(host).split('.')[0]
    instance_type = get_instance_type(client,instance)
    query ="select default_vcpus from dbainfra.dbo.aws_instance_configuration where db_instance_class = '" + instance_type + "'"
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    cpu_count = result[0] - 1
    conn_sql_dest.close()
    # Restore backup of given database
    try:
        os.environ["PGPASSWORD"] = password
        command = 'pg_restore -h {} -U {} --dbname=postgres -Fc --clean --create -j {} -v {}'.format(host,user,cpu_count,filename)
        args = shlex.split(command)
        process = subprocess.Popen(args,stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        #process = subprocess.Popen(['pg_restore', '-h', host, '-U', user, '--dbname=postgres', '-Fc', '--clean',
        #                            '--create', '-j 2', '-v', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        #                           stderr=subprocess.PIPE)
        (stdout, stderr) = process.communicate()
        # Check the restoration status
        restore_file = '/g/dba/logs/dbrefresh/restore_{}_{}.log'.format(host.split('.')[0],dbname)
        temp_file = '/g/dba/logs/dbrefresh/tempfile_{}_{}.log'.format(host.split('.')[0],dbname)
        restore_log = open(restore_file, 'w')
        logging.info(stderr)
        restore_log.write(stderr)
        restore_log.close()
        command = "grep 'pg_restore: [custom archiver] could not open input file' {}".format(restore_file)
        process = subprocess.Popen(command, shell=True)
        if process.returncode == 0:
            logging.error("restoration of database {} failed, missing backup file".format(dbname))
            return 1
        command = "grep -B2 -A1 'could not execute query: ERROR:  database\|ERROR:  permission denied for sequence hints\|could not execute query: ERROR:  must be owner of extension\|already exists\|ERROR:  permission denied for relation pg_\|Error from TOC entry\|could not execute query: ERROR:  ' {} > {}".format(restore_file,temp_file)
        process = subprocess.Popen(command, shell=True)
        process.communicate()
        if process.returncode == 0:
            command = "grep -vFf {} {} | grep -vi WARNING | grep -iw ERROR".format(temp_file,restore_file)
            process = subprocess.Popen(command, shell=True)
            process.communicate()
            if process.returncode == 1:
                logging.info("restoration of database %s completed successfully",dbname)
                return 0
            else:
                logging.error("restoration of database {} failed".format(dbname))
                return 1
        else:
            return 0
    except Exception as e:
        logging.error("common::run_command() : [ERROR]: output = %s, error code = %s\n" % (e.output, e.returncode))
        raise Exception('Error while restoring databases')


def get_excluded_and_destination_only_databases(source_endpoint,destination_endpoint):
    # Get list of databases excluded from refresh and databases only in UAT
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    request_number = get_techops_request()
    cur_source, conn_source = connect(source_endpoint, 'sa', sa_pass, 'postgres')
    cur_dest, conn_dest = connect(destination_endpoint, 'sa', sa_pass, 'postgres')

    cur_source.execute("select datname from pg_database order by datname")
    cur_dest.execute("select datname from pg_database order by datname")

    rows = cur_source.fetchall()
    source_db_list = []
    dest_db_list = []
    for row in rows:
        source_db_list.append(str(row[0]))
    rows = cur_dest.fetchall()
    for row in rows:
        dest_db_list.append(str(row[0]))
    excl_db = list(set(dest_db_list) - set(source_db_list))
    logging.info("uat only databases are: " + str(excl_db)[1:-1])
    # Getting exclude database list
    query = "select dbname from dbainfra.dbo.refresh_db_exclusion_list where expires_dt > CURRENT_TIMESTAMP and dbname not in " \
            "('sandbox','postgres','rdsadmin') and instancename='"+destination_endpoint.split('.')[0]+"';"
    cur_sql_dest, conn_sql_dest = sql_connect()
    conn_sql_dest.autocommit = True
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchall()
    for row in result:
        excl_db.append(str(row[0]))
    logging.info("uat only databases and excluded databases list:"+ str(excl_db)[1:-1])
    for db in excl_db:
        query = "if not exists (select * from  dbainfra.dbo.backup_status where source_instance='"+source_endpoint.split('.')[0]+"' and destination_instance='"+destination_endpoint.split('.')[0]+"' and database_name='"+str(db)+"' and techops_request='"+request_number+"')" \
                "insert into dbainfra.dbo.backup_status values('"+source_endpoint.split('.')[0]+"','"+destination_endpoint.split('.')[0]+"','"+request_number+"','"+str(db)+"',NULL,NULL,NULL)"
        cur_sql_dest.execute(query)
    conn_source.close()
    conn_dest.close()
    conn_sql_dest.close()


def delete_old_backups():
    oldbackupfiles = subprocess.Popen(["find /g/dba/importexport/postgresqlbackups/ -type f -name '*.dmp' -mtime +3"],shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = oldbackupfiles.communicate()
    if oldbackupfiles.returncode != 0:
        return 1
    logging.info("Files older than three days are {}".format(output))
    logging.info("Deleting the files older than three days")
    removefiles = subprocess.Popen(["find /g/dba/importexport/postgresqlbackups/ -type f -name '*.dmp' -mtime +3 -exec rm {} \;"], shell=True)
    (output, err) = removefiles.communicate()
    if removefiles.returncode != 0:
        return 1
    logging.info("Removed files older than two days {}".format(output))


def backup_databases_excluded_from_refresh(source_endpoint,destination_endpoint):
    # Get the uat only databases , get the databases from exclude list and take the backup of those databases
    get_excluded_and_destination_only_databases(source_endpoint, destination_endpoint)
    request_number = get_techops_request()
    cur_sql_dest, conn_sql_dest = sql_connect()
    conn_sql_dest.autocommit = True
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    sql = "select database_name from dbainfra.dbo.backup_status where ( backup_status != 'Success' or backup_status is NULL ) and " \
          "source_instance='"+source_endpoint.split('.')[0]+"' and " \
          "destination_instance='"+destination_endpoint.split('.')[0]+"' and techops_request='"+request_number+"';"
    cur_sql_dest.execute(sql)
    result = cur_sql_dest.fetchall()
    if result:
        for db in result:
            dbexists = check_db_exists(destination_endpoint, str(db[0]))
            if dbexists == 1:
                logging.warning("The database : {} excluded does not exists in the destination : {}".format(str(db[0]),str(destination_endpoint.split('.')[0])))
                continue
            ret_code = make_super_user(destination_endpoint, str(db[0]))
            if ret_code == 1:
                logging.error("Error while making the sa user as super usre to take the backup instance:"+destination_endpoint.split('.')[0]+"for database:"+str(db[0]))
                raise Exception("Error while making the sa user as super usre to take the backup instance:"+destination_endpoint.split('.')[0]+"for database:"+str(db[0]))
            backup_file = '/g/dba/importexport/postgresqlbackups/' + destination_endpoint.split('.')[0] + '_' + str(db[0]) + '_' + str(date_t) + '.dmp'
            logging.info("Taking backup of database %s to file %s", str(db[0]),backup_file)
            ret_code = backup_database(destination_endpoint, str(db[0]), 'sa', sa_pass,backup_file)
            if ret_code == 0:
                query = "update dbainfra.dbo.backup_status set backup_status='Success',backup_file_name='"+backup_file+"' where source_instance='"+source_endpoint.split('.')[0]+\
                        "' and destination_instance='"+destination_endpoint.split('.')[0]+"' and techops_request='"+request_number+"' and database_name='"+str(db[0])+"'"
                cur_sql_dest.execute(query)
                continue
            else:
                logging.error("backup of database:%s failed", str(db[0]))
                query = "update dbainfra.dbo.backup_status set backup_status='Fail',backup_file_name='"+backup_file+"' where source_instance='"+source_endpoint.split('.')[0]+\
                        "' and destination_instance='"+destination_endpoint.split('.')[0]+"' and techops_request='"+request_number+"' and database_name='"+str(db[0])+"'"
                cur_sql_dest.execute(query)
                raise Exception("backup of database:%s failed", str(db[0]))
    else:
        logging.info("no database exclusions")


def restore_db_backup_files(client,destination_endpoint,source_instance,destination_instnace):
    # Restore backup files
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    ret_code = make_super_user(destination_endpoint, 'postgres')
    if ret_code == 1:
        logging.error("Error while restoring the excluded databases: error while making sa as super usre on instance : {}".format(destination_instnace))
        raise Exception("Error while restoring the excluded databases: error while making sa as super usre on instance : {}".format(destination_instnace))
    request_number = get_techops_request()
    cur_sql_dest, conn_sql_dest = sql_connect()
    conn_sql_dest.autocommit = True
    sql = "select database_name,backup_file_name from dbainfra.dbo.backup_status where ( restore_status != 1 or restore_status is NULL ) and backup_status = 'Success' and " \
          "source_instance='"+source_instance+"' and " \
          "destination_instance='"+destination_instnace+"' and techops_request='"+str(request_number)+"';"
    cur_sql_dest.execute(sql)
    result = cur_sql_dest.fetchall()
    for dumpfile in result:
        ret_code = restore_database(client,destination_endpoint, 'sa', sa_pass, str(dumpfile[1]),str(dumpfile[0]))
        if ret_code == 0:
            logging.info("Database : %s restoration completed successfully", str(dumpfile[0]))
            query = "update dbainfra.dbo.backup_status set restore_status=1 " \
                    "where source_instance='" + source_instance + "' and " \
                    "destination_instance='" + destination_instnace + "' " \
                    "and techops_request='" + request_number + "' and database_name='" + str(dumpfile[0]) + "'"
            cur_sql_dest.execute(query)
        else:
            logging.error("Restoration of database:"+str(dumpfile[0])+" failed")
            raise Exception("Restoration of database:{} failed".format(str(dumpfile[0])))
    return 0


def reset_passwords(pod,destination_endpoint, destination_instance):
    # Reset passwords of all db users in RDS instance
    logging.info("Reset user credentials in endpoint : {}, instance : {}".format(destination_endpoint,destination_instance))
    error = 0
    check_dba_vault = 0
    cur_sql, conn_sql = sql_connect()
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
    cur.execute("select usename from pg_user where usename not in ('rdsadmin','sa','rdsrepladmin','dumprestoreuser','dbmon')")
    result = cur.fetchall()
    for row in result:
        user = row[0]
        query_sql = "select TOP 1 vaultpath from dbainfra.dbo.pg_vault_path where username = '" + row[0] + "'"
        rows = cur_sql.execute(query_sql)
        row = rows.fetchone()
        if row is not None:
            vaultpath = row[0]
            path = str(vaultpath).replace("$MACHINE_POD", pod)
            try:
                user_pass = get_app_user_password(path)
                if user_pass is None:
                    logging.error("The vaultpath does not exists for user : {} in pod : {}".format(user,pod))
                    error = 1
                    continue
                logging.info("Resetting password of user {} using credentials from {}".format(user,path))
            except Exception as e:
                logging.error("Error while resetting the password for user : {} in pod : {}".format(user, pod))
                error = 1
                continue
        else:
            logging.error("No vault path entry found for user : {} in repository table, checking in DBA vault".format(user))
            check_dba_vault = 1
        if check_dba_vault == 1:
            vaultpath = "/secret/default/v1/db-postgres-credentials/password/{}/{}".format(pod,destination_instance)
            try:
                user_pass = get_user_password(vaultpath,user)
                if user_pass is None:
                    logging.error("The vaultpath does not exists for user : {} in pod : {}".format(user, pod))
                    continue
            except Exception as e:
                logging.error("Error while resetting the password for user : {} in pod : {}".format(user, pod))
                continue
        check_dba_vault = 0
        query = "alter user {} password '{}'".format(str(user),str(user_pass))
        cur.execute(query)
        conn.commit()
        time.sleep(10)
        logging.info('password reset completed for user:'+str(user))
    conn.close()
    if error == 1:
        return 1


def get_users(destination_endpoint):
    # Get the list of the users
    bkp_users_file = '/g/dba/importexport/postgresqlbackups/backup_users_'+str(destination_endpoint).split('.')[0]+'_'+date_t+'.sql'
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
    query = 'select {},rolcanlogin from pg_roles order by rolname'.format('\'"\'||rolname||\'"\'')
    cur.execute(query)
    rows = cur.fetchall()
    file_obj = open(bkp_users_file, 'a')
    for row in rows:
        file_obj.write(str(row[0])+','+str(row[1])+'\n')
    return bkp_users_file


def create_users(destination_endpoint, bkp_users_file):
    # Create the users
    if os.stat(bkp_users_file).st_size > 0:
        sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
        cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
        file_obj = open(bkp_users_file)
        for user in file_obj:
            query = "select 1 from pg_roles where rolname='"+user.split(',')[0].strip("\"\n\r")+"'"
            cur.execute(query)
            rows = cur.fetchall()
            if not rows:
                user = user.strip("\n\r")
                username = user.split(',')[0]
                rolcanlogin = user.split(',')[1]
                if rolcanlogin == 'True':
                    query="create user "+username+" password 'test123'"
                else:
                    query = "create role {}".format(username)
                cur.execute(query)
                conn.commit()
        conn.close()


def backup_privileges(destination_endpoint):
    # Take backup of privileges
    bkp_priv_file = '/g/dba/importexport/postgresqlbackups/backup_privs_'+str(destination_endpoint).split('.')[0]+'_'+date_t+'.sql'
    query = "WITH T as (SELECT 'GRANT ' || (SELECT rolname FROM pg_roles WHERE oid = roleid and rolname not in ('rdsadmin','rds_superuser','rds_iam','rds_replication','rdsrepladmin') and rolname not like '%-%') || ' TO ' || (SELECT rolname  as query FROM pg_roles WHERE oid = member and rolname not in ('rdsadmin','rds_superuser','rds_iam','rds_replication','rdsrepladmin') and rolname not like '%-%') ||';' as query FROM pg_auth_members) select query::text from T where query is not null"
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
    cur.execute(query)
    file_obj = open(bkp_priv_file,'a')
    rows = cur.fetchall()
    for row in rows:
        file_obj.write(row[0]+'\n')
    return bkp_priv_file


def restore_privileges(destination_endpoint, bkp_priv_file):
    # Restoring privileges
    if os.stat(bkp_priv_file).st_size > 0:
        sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
        cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
        file_obj = open(bkp_priv_file)
        for query in file_obj:
            cur.execute(query)
            conn.commit()
        conn.close()


def check_refresh_possibility(destination_instance):
    # Restoring privileges
    query = "select count(1) as cnt from dbainfra.dbo.refresh_server_inventory where lower(destinationservername) = '"+ str(destination_instance).lower()+"' and performrefresh=1"
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    if result[0] == 0:
        logging.error("Backup is not scheduled for this instance or no entry in refresh inventory(dbainfra.dbo.refresh_server_inventory) %s" %(destination_instance))
        return 1


def check_dest_not_prod_get_pod(instancename):
    query = "select TOP 1 lower(Env),lower(Pod) from dbainfra.dbo.database_server_inventory where lower(Alias) = '"+ str(instancename).lower()+"'"
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    if not result:
        logging.error("Not able to find the instance : {} details in inventory".format(instancename))
        raise Exception("Not able to find the instance : {} details in inventory".format(instancename))
    return result[0],result[1]


def get_account_region_of_instnace(instance_name):
    arcboto.install()
    cur_sql, conn_sql = sql_connect()
    cur_sql.execute("select lower(AvailabilityZone) from dbainfra.dbo.database_server_inventory where ServerType='PGDB' and lower(Alias)='{}'".format(str(instance_name).lower()))
    result = cur_sql.fetchone()
    if not result:
        logging.error("Not able to find the instance : {} details in inventory".format(instance_name))
        return 1,1
    region = result[0]
    query = "select account_name from [dbainfra].[dbo].[rds_accounts]"
    rows = cur_sql.execute(query)
    for row in rows.fetchall():
        account = row[0]
        rds,ec2,kms,iam = get_rds_ec2_kms_clients(account, region)
        try:
            response = rds.describe_db_instances(DBInstanceIdentifier='{}'.format(str(instance_name).lower()))
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logging.info('instance not found in account {} , checking in another account'.format(account))
                continue
        return account,region
    return 1,1


def verify_user_connection(destination_endpoint, user, user_pass):
    try:
        cur_dest, conn_dest = connect(destination_endpoint, user, user_pass, 'postgres')
        cur_dest.execute("select 1")
        result = cur_dest.fetchall()
        if result[0][0] == 1:
            logging.info("Verified the user {} password, it is working".format(user))
            conn_dest.close()
            return 0
        else:
            logging.error("Verified the user {} password, it is not working".format(user))
            conn_dest.close()
            return 1
    except Exception as e:
        logging.error("Error while creating database connection using user {}, can be wrong password".format(user))
        return 1


def verify_users(pod,destination_endpoint, destination_instance):
    # Reset passwords of all db users in RDS instance
    error = 0
    check_dba_vault = 0
    cur_sql, conn_sql = sql_connect()
    sa_pass = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur, conn = connect(destination_endpoint, 'sa', sa_pass, 'postgres')
    query = "select rolname from pg_roles where rolcanlogin = 't' and rolname not like '%_sa' and rolname " \
            "not in ('dumprestoreuser','sa','dbmon','pganalyze','rdsrepladmin','rdsadmin','cocoadbo','test','test_user')"
    cur.execute(query)
    result = cur.fetchall()
    conn.close()
    if result:
        for row in result:
            user = row[0]
            query_sql = "select TOP 1 vaultpath from dbainfra.dbo.pg_vault_path where username = '{}'".format(user)
            rows = cur_sql.execute(query_sql)
            row = rows.fetchone()
            if row is not None:
                vaultpath = row[0]
                path = str(vaultpath).replace("$MACHINE_POD", pod)
                try:
                    user_pass = get_app_user_password(path)
                    if user_pass is None:
                        logging.error("The vaultpath does not exists for user : {} in pod : {}".format(user, pod))
                        error = 1
                        continue
                    return_code = verify_user_connection(destination_endpoint, user, user_pass)
                    if return_code == 1:
                        logging.error("Failed to connect to the instance {} using user {}".format(destination_instance,user))
                        error = 1
                except Exception as e:
                    logging.error("Error while verifying the password for user : {} in pod : {}".format(user, pod))
                    error = 1
                    continue
            else:
                logging.info("No vault path entry found for user : {} in repository table, checking in DBA vault".format(user))
                check_dba_vault = 1
            if check_dba_vault == 1:
                vaultpath = "/secret/default/v1/db-postgres-credentials/password/{}/{}".format(pod,destination_instance)
                try:
                    user_pass = get_user_password(vaultpath,user)
                    if user_pass is None:
                        logging.error("The vaultpath does not exists for user : {} in pod : {}".format(user, pod))
                        continue
                    return_code = verify_user_connection(destination_endpoint, user, user_pass)
                    if return_code == 1:
                        logging.error("Failed to connect to the instance {} using user {}".format(destination_instance, user))
                except Exception as e:
                    logging.error("Error while resetting the password for user : {} in pod : {}".format(user, pod))
                    continue
            check_dba_vault = 0
    if error == 1:
        return 1


def change_store_passwords(account,region,pod, instancename):
    rds, ec2, kms, iam = get_rds_ec2_kms_clients(account, region)
    response = get_instance_details(rds,instancename)
    endpoint = response['DBInstances'][0]['Endpoint']['Address']
    # function to change the passwords of db users not present in vault and store passwords in vault
    passw = get_user_password('/secret/default/v1/db-postgres-credentials/dba_users','sa')
    cur_pgsql, conn_pgsql = connect(endpoint,'sa',passw,'postgres')
    pass_length = 32
    query = "select rolname from pg_roles where rolcanlogin = 't' and rolname not like '%_sa' and rolname not in  ('rdsadmin','rds_iam','rds_replication','rds_superuser','rdsrepladmin',"
    var = ""
    vaultpath = "http://vault.ia55.net/v1/secret/default/v1/db-postgres-credentials/password/{}/{}/".format(pod,instancename)
    vaultpath = vaultpath + '?list=true'
    users = get_user_list(vaultpath)
    for user in users:
        var += "'"+str(user)+"',"
    cur_sql_dest, conn_sql_dest = sql_connect()
    cur_sql_dest.execute("select lower(username) from dbainfra.dbo.pg_vault_path where vaultpath is not null and username is not null")
    users = cur_sql_dest.fetchall()
    for user in users:
        var += "'"+str(user[0])+"',"
    var = var + "'')"
    query = query + var
    logging.info("query to find users not in vault".format(query))
    cur_pgsql.execute(query)
    result = cur_pgsql.fetchall()
    logging.info("list of users not in vault {}".format(result))
    for user in result:
        logging.info("changing password for user {}".format(user[0]))
        x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(pass_length))
        query = "alter user \"" + user[0] + "\" password \'" + x + "\'"
        cur_pgsql.execute(query)
        write_dba_user_password(pod, instancename, user[0], x)
        conn_pgsql.commit()
    conn_pgsql.close()


def get_prod_instances():
    prod_instances = {}
    cur, conn_sql = sql_connect()
    arcboto.install()
    client = boto3.client('ec2')
    regions = [region['RegionName'] for region in client.describe_regions()['Regions']]
    for region in regions:
        regionclient = boto3.client('rds', region_name=region)
        instances = regionclient.describe_db_instances()['DBInstances']
        if instances:
            for instance in instances:
                instancename = instance['DBInstanceIdentifier']
                query = "select lower(Env) as env,lower(pod) as pod from dbainfra.dbo.database_server_inventory where lower(Alias)='{}'".format(instancename)
                rows = cur.execute(query)
                row = rows.fetchone()
                if row != None:
                    if row.env == 'prod':
                        prod_instances[instancename] = [region, row.pod]
    return prod_instances


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_app_user_password(vaultpath):
    try:
        vaultpath_req = "http://vault.ia55.net/v1{}".format(vaultpath)
        response = requests.get(vaultpath_req,auth=HTTPKerberosAuth())
        if response:
            passwd = response.json()['data']['secret']
            return passwd
        if response.status_code == 404 or response.status_code == 403:
            logging.error("vaultpath does not exists or permission denied".format(vaultpath,response.content))
            return
        else:
            logging.error("Failed to retrieve credentials from {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to retrieve credentials from {} with error {}".format(vaultpath,response.content))
    except Exception as e:
        logging.error("Failed to retrieve credentials from {} with error {}, trying again".format(vaultpath,str(e)))
        raise Exception("Failed to retrieve credentials from {} with error {}".format(vaultpath, str(e)))


def get_account_region_of_instnaces():
    dictionary = {}
    arcboto.install()
    client = boto3.client('ec2')
    regions = [region['RegionName'] for region in client.describe_regions()['Regions']]
    cur, conn_sql = sql_connect()
    query = "select account_name from [dbainfra].[dbo].[rds_accounts]"
    rows = cur.execute(query)
    for row in rows.fetchall():
        account = row[0]
        for region in regions:
            rds,ec2,kms,iam = get_rds_ec2_kms_clients(account, region)
            instances = rds.describe_db_instances()['DBInstances']
            for instance in instances:
                instancename             = instance['DBInstanceIdentifier']
                dictionary[instancename] = [ account, region ]
    return dictionary


def change_instance_class(instance_name,new_class):
    account, region    = get_account_region_of_instnace(instance_name)
    rds, ec2, kms, iam = get_rds_ec2_kms_clients(account, region)
    instance_details   = get_instance_details(rds,instance_name)
    instance_class     = str(instance_details['DBInstances'][0]['DBInstanceClass']).split('.')[1]
    instance_size      = str(instance_details['DBInstances'][0]['DBInstanceClass']).split('.')[2]
    if instance_class  != str(new_class).lower():
        logging.info("instance class is not {} class, proceeding to change the class".format(new_class))
        try:
            new_instance_class = 'db.'+new_class+'.'+instance_size
            logging.info("changing the instance class to {}".format(new_instance_class))
            response = rds.modify_db_instance(DBInstanceIdentifier=instance_name,DBInstanceClass=new_instance_class,ApplyImmediately=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidDBInstanceState':
                logging.error("Instance %s is in invalid state", instance_name)
                return 1
            else:
                logging.error("Changing instance class is failed with error {}".format(str(e)))
                return 1
        retcode = check_instance_status_for_create(rds,instance_name)
        if retcode == 0:
            logging.info("Instance class changed successfully for {}".format(instance_name))
            return 0
        else:
            logging.error("Changing instance class failed for {}".format(instance_name))
            return 1
