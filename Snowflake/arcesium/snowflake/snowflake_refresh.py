"""
owner       : oguri
Description : This is to refresh the Snowflake databases from source to destination
"""
import sys
import argparse
from datetime import datetime
import traceback
import json

sys.path.append('/g/dba/pythonutilities/')
from pythonutils import PythonUtils

sys.path.append('/g/dba/radarutil/')
from radarutil import RadarUtil
radarutil=RadarUtil()

sys.path.append('/g/dba/rds')
import pod_automation_util
import arcesium.snowflake.snowflakeutil as snowflakeutil

import dbrefreshutil
from dbrefreshutil import DBRefreshUtil

import vaultutil

logger = ''

def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True,
                                     description=
                                     'example : sudo -u sqlexec python snowflake_refresh.py -s baam -d baamuat')
    parser.add_argument("-s", "--source-pod",
                        dest="source_pod",
                        help="source pod to copy database",
                        required=True)
    parser.add_argument('-d', '--destination-pod',
                        dest='destination_pod', default='none',
                        help='destination pod to restore database', required=True)
    parser.add_argument('-db', '--dbname',
                        dest='dbname', default='none',
                        help='dbname to be copied from source to destination else all databases will be copied', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    return parser.parse_args()


def update_current_running_status(sourceservername, destinationservername, statuscode, comments):
    """
    update the current status of the refresh in dbmonitor server in table refresh_current_running_status table
    """
    query = "insert into dbainfra.dbo.refresh_current_running_status values('" + sourceservername + "','" + \
            destinationservername + "', getdate() ,'" + str(statuscode) + "','" + comments + "')"
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


def check_refresh_possibility(destination_instance):
    """
    before proceeding for fresh check the table refresh_server_inventory for entry if there is no entry exit
    """
    query = "select count(1) as cnt from dbainfra.dbo.refresh_server_inventory " \
            "where lower(destinationservername) = '"+ str(destination_instance).lower()+"' and performrefresh=1"
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    if result[0] == 0:
        logger.error("Backup is not scheduled for this instance or no entry for pod {} in refresh inventory table "
                     "dbainfra.dbo.refresh_server_inventory".format(destination_instance))
        return 1


def replicate_database_from_source(source_account, destination_account, destination_pod, dbname):
    """
    taking example of cocoa database

    After replication is enabled from source to destination, login to destination account (uat)
    1. create a database cocoa_new which is replica of cocoa database from source account
    2. rename existing cocoa database in destination to cocoa_old
    3. create a clone of the cocoa_new with name cocoa
    this completes enabling replication and copying the database
    """
    source_account = str(source_account).split('.')[0]
    connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
    cursor.execute("show replication accounts")
    cursor.execute("create or replace temporary table refresh_accounts(snowflake_region,created_on,account_name,"
                   "description) as select * from table(result_scan(last_query_id()))")
    accountname = cursor.execute("select snowflake_region||'.'||account_name from refresh_accounts "
                                 "where account_name=upper('{}')".format(source_account)).fetchone()
    acc_dbname = str(accountname)+str(dbname)
    cursor.execute("create database if not exists {}_new as replica of {}".format(dbname, acc_dbname))
    # refresh process will take more time based on database size.
    cursor.execute("alter database {}_new refresh")
    count = cursor.execute("select count(*) from information_schema.databases "
                           "where lower(DATABASE_NAME) = '{}_old'".format(str(dbname).lower()))
    # if count != 1:
    #    cursor.execute("alter database if exists {} rename to {}_old".format(dbname, dbname))
    cursor.execute("create database if not exists {}_clone clone {}_new".format(dbname, dbname))
    return 0


def check_enable_refresh(source_account, source_pod, destination_account, destination_pod, dbname):
    """
    login to source account (production) check the replication accounts(uat) to which replication is enabled ,
    if the replication is enabled there will be an entry in the table. if not raise exception. if there is entry
    enable the replication to destination (uat) account.
    """
    # ex : Get arc1000 from arc1000.us-east-1.privatelink
    destination_account = str(destination_account).split('.')[0]
    connection, cursor = snowflakeutil.get_admin_connection(source_account, source_pod)
    cursor.execute("show replication accounts")
    cursor.execute("create or replace temporary table refresh_accounts(snowflake_region,created_on,account_name,"
                   "description) as select * from table(result_scan(last_query_id()))")
    count = cursor.execute("select count(*) as result from refresh_accounts "
                           "where account_name=upper('{}')".format(destination_account)).fetchone()
    if count == 0:
        logger.error("refresh is not enabled "
                     "from source pod : {} to destination pod : {}".format(source_pod, destination_pod))
        return 1
    accountname = cursor.execute("select snowflake_region||'.'||account_name from refresh_accounts "
                                 "where account_name=upper('{}')".format(destination_account)).fetchone()
    cursor.execute("alter database {} enable replication to accounts {}".format(dbname, accountname))
    return 0


def backup_stages_pipes_tasks(destination_account, destination_pod, dbname):
    """
    This will take backup of pipes, stages, file formats and tasks.
    1. Create a table stage_properties which holds the properties of stages
    2. Create a table stages_pipes_streams_tasks which holds definition and order in which order the statements need to
    be executed
    """
    connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
    cursor.execute("create or replace table stage_properties (schemaname varchar, stagename varchar, "
                   "parent_property varchar, property varchar, property_type varchar, "
                   "property_value varchar, property_default varchar)")
    # Backup stages and definition of stages
    cursor.execute("create or replace table stage_pipes_streams_tasks(ordr int,def varchar)")
    cursor.execute("select PIPE_SCHEMA||'.'||PIPE_NAME as pipe_name from information_schema.pipes where pipe_catalog='{}'".format(dbname))
    for var in cursor.fetchall():
        pipe_name = var[0]
        cursor.execute("insert into stage_pipes_streams_tasks select 5, get_ddl('pipe', '{}')".format(pipe_name))
    # Backup tasks and definitions
    cursor.execute("show tasks in database")
    cursor.execute("select \"schema_name\"||.||\"name\" as task_name from table(result_scan(last_query_id()))")
    for var in cursor.fetchall():
        task_name = var[0]
        cursor.execute("insert into stage_pipes_streams_tasks select 4, get_ddl('task', '{}')".format(task_name))
    # Backup streams and definitions
    cursor.execute("show streams in database")
    cursor.execute("select \"schema_name\"||.||\"name\" as task_name from table(result_scan(last_query_id()))")
    for var in cursor.fetchall():
        stream_name = var[0]
        cursor.execute("insert into stage_pipes_streams_tasks select 3, get_ddl('stream', '{}')".format(stream_name))
    # Backup file formats and definitions
    cursor.execute("show file formats in database")
    cursor.execute("select \"schema_name\"||.||\"name\" as task_name from table(result_scan(last_query_id()))")
    for var in cursor.fetchall():
        format_name = var[0]
        cursor.execute("insert into stage_pipes_streams_tasks select 1, get_ddl('file_format', '{}')".format(format_name))
    # Backup of stages and properties
    cursor.execute("select STAGE_SCHEMA, STAGE_NAME from information_schema.stages where stage_catalog='{}'".format(dbname))
    for var in cursor.fetchall():
        stage_schema = var[0]
        stage_name   = var[1]
        stg_name = stage_schema+'.'+stage_name
        cursor.execute("desc stage {}".format(stg_name))
        cursor.execute("insert into stage_properties select '{}','{}',* from table(result_scan(last_query_id()))".format(stage_schema, stage_name))
    stage_def = """
    insert into stage_pipes_streams_tasks
    WITH T AS (
    select
    SCHEMANAME||'.'||STAGENAME as stagename,
    CASE
    WHEN parent_property = 'STAGE_LOCATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'["','\''),'"]','\''),' ')
    WHEN parent_property = 'STAGE_INTEGRATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[','\''),']','\''),' ')
    WHEN parent_property = 'STAGE_COPY_OPTIONS' THEN 'COPY_OPTIONS = ('||LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[',' '),']',' '),', ')||')'
    WHEN parent_property = 'STAGE_FILE_FORMAT'  THEN 'FILE_FORMAT = ('|| LISTAGG(property||'='||REPLACE(REPLACE((CASE
                                                                                                                WHEN PROPERTY_VALUE = 'true' THEN PROPERTY_VALUE
                                                                                                                WHEN PROPERTY_VALUE = 'false' THEN PROPERTY_VALUE
                                                                                                                WHEN PROPERTY_VALUE = '0' THEN PROPERTY_VALUE
                                                                                                                WHEN PROPERTY_VALUE = '1' THEN PROPERTY_VALUE
                                                                                                                ELSE concat('\'',PROPERTY_VALUE,'\'') END)
                                                                                                                ,'[',' '),']',' '),', ')||')'
    ELSE ' '
    END as options
    from stage_properties
    where PROPERTY_VALUE is not null and PROPERTY_VALUE != ''
    group by SCHEMANAME,STAGENAME,stagename,parent_property
    order by schemaname,stagename)
    select 2,'CREATE STAGE '||STAGENAME||' '||LISTAGG(OPTIONS,' ')||';' from T
    group by STAGENAME
    """
    return 0


def backup_users_roles_permissions(destination_account, destination_pod,dbname):
    """
    by default snowflake refresh do not take care of permissions so permissions need to be copied explicitly
    """
    connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
    cursor.execute("show users")
    cursor.execute("create or replace table dbusers as select *  from table(result_scan(last_query_id()))")
    cursor.execute("show roles")
    cursor.execute("create or replace table dbroles as select * from table(result_scan(last_query_id()))")
    cursor.execute("CREATE OR replace TABLE dbgrants(created_on timestamp_ltz,privilege varchar,granted_on varchar,"
                   "name varchar,granted_to varchar,grantee_name varchar,grant_option varchar,granted_by varchar)")
    cursor.execute("SELECT \"name\" as NAME FROM DBROLES")
    for var in cursor.fetchall():
        rolname = var[0]
        cursor.execute("show grants to role {}".format(rolname))
        cursor.execute("insert into dbgrants select * from table(result_scan(last_query_id()))")
        cursor.execute("show grants on role {}".format(rolname))
        cursor.execute("insert into dbgrants select * from table(result_scan(last_query_id()))")
    cursor.execute("SELECT \"name\" as NAME FROM DBUSERS")
    for var in cursor.fetchall():
        username = var[0]
        cursor.execute("show grants to user {}".format(username))
        cursor.execute("insert into dbgrants select *,null,null,null from table(result_scan(last_query_id()))")
        cursor.execute("show grants on user {}".format(username))
        cursor.execute("insert into dbgrants select *,null,null,null from table(result_scan(last_query_id()))")
    cursor.execute("show shares")
    cursor.execute("select \"name\" from table(result_scan(last_query_id()))"
                   " where \"kind\"='OUTBOUND' and \"database_name\"='{}'".format(dbname))
    for var in cursor.fetchall():
        share_name = var[0]
        cursor.execute("show grants to share {}".format(share_name))
        cursor.execute("insert into dbgrants select * from table(result_scan(last_query_id()))")
        cursor.execute("show grants on share {}".format(share_name))
        cursor.execute("insert into dbgrants select * from table(result_scan(last_query_id()))")
    return 0


def restore_stages_pipes_tasks_permissions(destination_account, destination_pod, dbname):
    """
    Restore the ddl statements created for stages, pipes, permissions etc in previous step to the database. This where
    the actual downtime starts.
    """
    connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
    cursor.execute("alter database {} rename to {}_old".format(dbname,dbname))
    cursor.execute("alter database {}_clone rename to {}".format(dbname,dbname))
    cursor.execute("select def from stage_pipes_streams_tasks order by ordr")
    cursor.execute("use database {}".format(dbname))
    for var in cursor.fetchall():
        sql_statement = var[0]
        cursor.execute(sql_statement)
    query = """
    select 'GRANT '||PRIVILEGE||' ON '||GRANTED_ON||' '||NAME||' TO '||GRANTEE_NAME||';' 
    from dbgrants where granted_on not in ('ACCOUNT') and GRANTEE_NAME not in ('ACCOUNTADMIN','SECURITYADMIN') 
    and name not like 'SNOWFLAKE_SAMPLE_DATA%' and strtok(NAME,'.',1) = '{}'
    """.format(str(dbname).upper())
    cursor.execute(query)
    for var in cursor.fetchall():
        sql_statement = var[0]
        cursor.execute(sql_statement)
    return 0


def main():
    try:
        args = parse_arguments()
        # Get the input arguments
        source_pod      = args.source_pod
        destination_pod = args.destination_pod
        dbname          = args.dbname
        # Get account details and host information
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber from dbainfra.dbo.database_server_inventory "
                                    "where lower(ServerType)='snowflake' and lower(pod) = '{}'".format(str(source_pod).lower()))
        row = rows.fetchone()
        source_account = row[0]
        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber,lower(Env) as env "
                                    "from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake'"
                                    " and lower(pod) = '{}'".format(str(destination_pod).lower()))
        row = rows.fetchone()
        destination_account = row[0]
        destination_env     = row[1]
        # Variables for radar alerts
        alert_source = "dba"
        alert_class = "Page"
        alert_severity = "CRITICAL",
        alert_key = "Snowflake refresh"
        alert_summary = "Snowflake Refresh" + source_pod + " to " + destination_pod
        # Create object for dbrefreshutil
        dbrefreshutil = DBRefreshUtil(logger=None)
        # Enable logging
        logfile = '/g/dba/logs/dbrefresh/snowflakerefresh_{}_{}_{}.log'.format(source_account, destination_account,
                                                                               datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        global logger
        logger = snowflakeutil.setup_logging(logfile=logfile)
        """
        if the destination environment is prod we should not proceed with refresh
        """
        if destination_env == 'prod':
            logger.error("Destination pod {} is prod, refresh is not possible".format(destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                             "Destination pod should not be production. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,comments='Destination pod should not be production')
            sys.exit(1)
        """
        verify refresh is scheduled for this instance by checking the refresh_server_inventory table.
        """
        retcode = check_refresh_possibility(destination_pod)
        if retcode == 1:
            logger.error("Refresh is not scheduled for this pod {}".format(destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                             "Refresh is not scheduled for this instance. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,comments='Refresh is not scheduled for this pod')
            sys.exit(1)

        """
        Read credentials of source and destination pod from vault
        """
        password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(source_pod))
        source_account_pwd = json.loads(password)['password']
        password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(destination_pod))
        destination_account_pwd = json.loads(password)['password']

        """
        To perform the refresh between two accounts enable the replication/refresh between the source and destination
        accounts. This should be enabled by Snowflake team between two accounts. After that login to source account(prod)
        and enable replication for the database to destination account (uat).
        """
        update_current_running_status(source_pod, destination_pod, statuscode=2, comments="Refresh is possible.Enabling "
                                     "replication between source pod {} and destination pod {}".format(source_pod,destination_pod))
        logger.info("Enabling replication from source pod {} to destination pod {}".format(source_pod,destination_pod))
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Refresh is possible." \
                 "Enabling replication beteen source pod {} and destination pod {} \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod,source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        """
        enable the replication between source and destination accounts
        """
        return_code = check_enable_refresh(source_account, source_pod, destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to enable the replication from source pod {} to destination pod {}".format(source_pod,destination_pod))
            # update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Refresh is possible." \
                 "Failed to enable replication beteen source pod {} and destination pod {} \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod,source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Error while enabling replication between source pod {} " \
                                "and destination pod {} , check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully enabled replication from source pod {} to destination pod {}".format(source_pod,destination_pod))

        """
        Once the replication is enabled to destination account (uat), login to destination account (uat) and start 
        database refresh by copying database from source to destination
        """
        # updating the status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=3,
                                      comments='Replicating database {} from source pod {} to destination pod {}'.format(dbname,source_pod,destination_pod))
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Replication Enabled and Replicating the database from source pod to destination pod. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        logger.info("replicate database {} from source account {} to destination account {}".format(dbname,source_account,destination_account))
        logger.info("Database replication takes time based on database size")
        return_code = replicate_database_from_source(source_account, destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to replicate database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
            # update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Replicating Database." \
                 "Failed to replicate database beteen source pod {} and destination pod {} \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod,source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Error while replicating database between source pod {} and destination pod {} , check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully replicated database {} from source pod {} to destination pod {}".format(dbname, source_pod, destination_pod))
        """
        Snowflake refresh do not take the backup of stages, tasks, pipes and file formats, so these objects need to be
        backup and restore after the replication is completed.
        """
        logger.info("Generate DDL commands for taking backup of stages,tasks,pipes and file formats and store in table")
        # updating the status on Desflow
        update_current_running_status(source_pod, destination_pod, statuscode=4, comments='Taking backup of DDL statements for stages, tasks, pipes into table')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Taking backup of DDL statements for stages, tasks, pipes into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        return_code = backup_stages_pipes_tasks(destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to generate and store DDL commands for backup of stages, pipes, file formats and tasks")
            # update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Replicating Database." \
                 "Failed to backup DDL statements for stages, tasks, pipes into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to backup DDL statements for stages, tasks, pipes into table , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of stages, tasks , pipes and file formats and stored in table")
        """
        Snowflake replication do not handle the user permissions on objects, so permissions on objects need to be backup
        and restore the permissions on destination pod
        """
        logger.info("Generate DDL commands of users , roles , privileges and store in table")
        # Update the status on the desflow request
        update_current_running_status(source_pod, destination_pod, statuscode=5,comments='Taking backup of privilages into table')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Taking backup of DDL statements of privilages into table. \n" \
                 "Please check the attached log file for further details".format(source_pod, destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        return_code = backup_users_roles_permissions(destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to generate and store DDL commands for backup of users, roles and permissions")
            # update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus:" \
                 "Failed to backup DDL statements of privialges into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to backup  DDL statements of privileges into table , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary, alert_description)
            sys.exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of users, roles , permissions and stored in table")
        """
        Now all the ddl statements backup is completed. Now we need to rename the existing database to old and rename the 
        replication database to old. After that restore the stages and other ddls into that database.
        """
        # update the status on the Desflow
        update_current_running_status(source_pod, destination_pod, statuscode=6,comments='Create SQL file with DDL of privilages, stages etc')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Create SQL file with DDL of privilages, stages etc. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        # status updated on desflow
        return_code = restore_stages_pipes_tasks_permissions(destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to restore the stages , pipes or permissions")
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
		     "Status: Failed to Create SQL file with DDL of privilages, stages etc. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to restore the stages , pipes or permissions , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully restored stages, pipes and file formats created in previous step")
        logger.info("Database refresh completed successfully for database {}".format(dbname))
        # Cleanup old databases
        # logger.info("Clean old databases created from replication and old uat database")
        update_current_running_status(source_pod, destination_pod, statuscode=8,comments='Refresh completed successfully')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
             "Status: Refresh Completed successfully. \n" \
             "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
    except Exception as e:
        logger.error(e)
        traceback.print_exc()
        # update the status of the failure on desflow and raise radar alert
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Database refresh failed etc. \n" \
                     "Please check the attached log file for further details".format(source_pod, destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        alert_description = "Failed to refresh database from {} to {} etc. , check logfile {}".format(source_pod,destination_pod,logfile)
        radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
        sys.exit(1)


if __name__ == "__main__":
    main()