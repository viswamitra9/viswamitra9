"""
owner       : oguri
Description : This is to refresh the Snowflake databases from source to destination account
"""
import sys
sys.path.append('/g/dba/snowflake')
import argparse
from datetime import datetime
import traceback
import snowflakeutil
import logging

logger = logging.getLogger('snowflake_refresh')
logfile = ''

# variables for radar aler
alert_source    = "dba"
alert_class     = "Page"
alert_severity  = "CRITICAL",
alert_key       = "Snowflake refresh"


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


def update_current_running_refresh_status_on_desflow(status_message, files_to_attach=[]):
    """
    This function updates the status of current running refresh to DESFlow request. The DESFlow request details are fetched from the table [dbainfra].[dbo].[refresh_desflow_ticket_details] on DBMONITOR1B

    Arguments:
            status_message (string): The status message that has to be updated on the ticket

    Returns:
            bool: indicating whether status is updated or not

    Examples:
            >>> update_current_running_refresh_status_on_desflow(status_message='Testing status of refresh')
    """

    assert type(files_to_attach) == list

    # Get connection to DBMONITOR
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()

    # Get DESFlow ticket number from table [dbainfra].[dbo].[refresh_desflow_ticket_details] on DBMONITOR1B
    query = "SELECT * FROM [dbainfra].[dbo].[refresh_desflow_ticket_details]"
    result = cur_sql_dest.execute(query)
    row = result.fetchone()
    if row is None:
        logger.error('There are no DESFlow request details in table [dbainfra].[dbo].[refresh_desflow_ticket_details] in DBMONITOR')
        logger.error('Cannot update status to DESFlow. Returning')
        return False
    sub = "ArcTechOps#" + str(row.archelpnumber) + ": " + row.archelpsubject
    snowflakeutil.send_mail('dba-ops@arcesium.com', ['dba-requests@arcesium.com'], sub, status_message,files_to_attach)


def update_current_running_status(sourceservername, destinationservername, statuscode, comments):
    """
    update the current status of the refresh in dbmonitor server in table refresh_current_running_status table
    """
    query = "insert into dbainfra.dbo.refresh_current_running_status(sourceservername,destinationservername," \
            "time,statuscode,comments) values ('{}','{}',{},'{}','{}')".format(sourceservername,destinationservername,
                                                                               'getdate()',str(statuscode),comments)
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


def check_refresh_possibility(dest_pod):
    """
    before proceeding for fresh check the table refresh_server_inventory for entry if there is no entry exit
    """
    logger.info("checking the possibility of refresh")
    query = "select count(1) from dbainfra.dbo.refresh_server_inventory " \
            "where lower(dest_pod) = '{}' and performrefresh=1".format(str(dest_pod).lower())
    cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchone()
    if result[0] == 0:
        logger.error("Backup is not scheduled for this instance or no entry for pod {} in refresh inventory table "
                     "dbainfra.dbo.refresh_server_inventory".format(dest_pod))
        return 1
    logger.info("Refresh is scheduled for snowflake pod {}, proceeding further".format(dest_pod))


def replicate_database_from_source(source_account, destination_account, destination_pod, dbname, source_pod):
    """
    taking example of cocoa database

    After replication is enabled from source to destination, login to destination account (uat)
    1. create a database <source_pod>_replica_cocoa which is replica of cocoa database from source account
    2. Refresh the <source_pod>_replica_cocoa database which will copy the database cocoa from production to uat
    3. create a clone of the <source_pod>_replica_cocoa with name <source_pod>_clone_cocoa
    this completes enabling replication and copying the database
    """
    try:
        logger.info("Configuring replication for Snowflake accounts "
                    "source : {} and destination : {}".format(source_account, destination_account))
        source_account = str(source_account).split('.')[0]
        connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
        cursor.execute("show replication accounts")
        cursor.execute("create or replace temporary table refresh_accounts(snowflake_region,created_on,account_name,"
                       "description,organization_name) as select * from table(result_scan(last_query_id()))")
        accountname = cursor.execute("select snowflake_region||'.'||account_name from refresh_accounts "
                                     "where account_name=upper('{}')".format(source_account)).fetchone()[0]
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
        logger.info("To see the status of the replication login to "
                    "the target account {} and run below command {}".format(destination_account, query))
        cursor.execute("alter database {}_replica_{} refresh".format(source_pod,dbname))
        cursor.execute("create or replace database {}_clone_{} clone {}_replica_{}".format(source_pod,dbname,source_pod, dbname))
        # cursor.execute("drop database if exists {}_new".format(dbname))
        return 0
    except Exception as e:
        logger.error("Error {} occured while replicating database from source {} to destination {}".format(str(e),source_account,destination_account))
        raise Exception("Error {} occured while replicating database from source {} to destination {}".format(str(e),source_account,destination_account))


def check_replication(source_account, source_pod, destination_account, destination_pod):
    """
    1. login to source account (production), check if replication is enabled to destination accounts(uat)
    2. if replication is not enabled from snowflake side, return 1 or failure message
    """
    try:
        # ex : Get arc1000 from arc1000.us-east-1.privatelink
        logger.info("checking replication enabled from source pod {} to destination pod {}".format(source_pod, destination_pod))
        destination_account = str(destination_account).split('.')[0]
        connection, cursor = snowflakeutil.get_admin_connection(source_account, source_pod)
        cursor.execute("show replication accounts")
        cursor.execute("create or replace table audit_archive.public.refresh_accounts(snowflake_region,created_on,account_name,"
                       "description,organization_name) as select * from table(result_scan(last_query_id()))")
        count = cursor.execute("select count(*) as result from audit_archive.public.refresh_accounts "
                               "where account_name=upper('{}')".format(destination_account)).fetchone()[0]
        if count == 0:
            logger.error("replication is not enabled from source pod : {} to destination pod : {}".format(source_pod, destination_pod))
            return 1
        return 0
    except Exception as e:
        logger.error("Error occurred while verifying replication between source pod : {} and destination pod : {}".format(source_pod, destination_pod))
        raise Exception("Error occurred while verifying replication between source pod : {} and destination pod : {}".format(source_pod, destination_pod))


def enable_replication(source_account, source_pod, destination_account, destination_pod, dbname):
    """
    1. Snowflake replication works on database wise.
    2. Login to source account, enable replication for database
    3. return 1 in case of failure
    """
    try:
        destination_account = str(destination_account).split('.')[0]
        connection, cursor  = snowflakeutil.get_admin_connection(source_account, source_pod)
        accountname = cursor.execute("select snowflake_region||'.'||account_name from audit_archive.public.refresh_accounts "
                                     "where account_name='{}'".format(str(destination_account)).upper()).fetchone()[0]
        logger.info("enabling replication for database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
        logger.info("alter database {} enable replication to accounts {}".format(dbname, accountname))
        cursor.execute("alter database {} enable replication to accounts {}".format(dbname, accountname))
        logger.info("enabled replication for database {} from source pod {} to destination pod".format(dbname,source_pod,destination_pod))
        return 0
    except Exception as e:
        logger.error("Error {} occurred while enabling replication for database {} between "
                     "source pod : {} and destination pod : {}".format(str(e),dbname,source_pod, destination_pod))
        raise Exception("Error {} occurred while enabling replication for database {} between "
                        "source pod : {} and destination pod : {}".format(str(e),dbname,source_pod, destination_pod))


def backup_stages(destination_account, destination_pod, dbname):
    """
    Take backup of file formats, stages
    """
    try:
        logger.info("Started taking backup of stages in pod {} from database {}".format(destination_pod, dbname))
        connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database {}".format(dbname))
        #logger.info("Taking backup of pipes in pod {} from database {}".format(destination_pod, dbname))
        #cursor.execute("select PIPE_SCHEMA||'.'||PIPE_NAME as pipe_name from information_schema.pipes where pipe_catalog='{}'".format(dbname))
        #result = cursor.fetchall()
        #if len(result) > 0:
        #    for var in result:
        #        pipe_name = var[0]
        #        cursor.execute("insert into audit_archive.public.stage_pipes_streams_tasks select 5, get_ddl('pipe', '{}',TRUE)".format(pipe_name))
        # Backup tasks and definitions
        #logger.info("Taking backup of tasks in pod {} from database {}".format(destination_pod, dbname))
        #cursor.execute("show tasks in database {}".format(dbname))
        #cursor.execute("select \"schema_name\"||'.'||\"name\" as task_name from table(result_scan(last_query_id()))")
        #result = cursor.fetchall()
        #if len(result) > 0:
        #    for var in result:
        #        task_name = var[0]
        #        cursor.execute("insert into audit_archive.public.stage_pipes_streams_tasks select 4, get_ddl('task', '{}',TRUE)".format(task_name))
        # Backup streams and definitions
        #logger.info("Taking backup of streams in pod {} from database {}".format(destination_pod, dbname))
        #cursor.execute("show streams in database {}".format(dbname))
        #cursor.execute("select \"schema_name\"||'.'||\"name\" as stream_name from table(result_scan(last_query_id()))")
        #result = cursor.fetchall()
        #if len(result) > 0:
        #    for var in result:
        #        stream_name = var[0]
        #        cursor.execute("insert into audit_archive.public.stage_pipes_streams_tasks select 3, get_ddl('stream', '{}',TRUE)".format(stream_name))
        # Backup file formats and definitions
        logger.info("Taking backup of file formats in pod {} from database {}".format(destination_pod, dbname))
        cursor.execute("show file formats in database {}".format(dbname))
        cursor.execute("select \"schema_name\",\"name\" from table(result_scan(last_query_id()))")
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                schemaname = var[0]
                formatname = var[1]
                format_name = str(schemaname)+'.'+str(formatname)
                cursor.execute("insert into audit_archive.public.stage_backup select '{}','{}',1, get_ddl('file_format','{}',TRUE)".format(dbname,schemaname,format_name))
        # Backup of stages and properties
        logger.info("Taking backup of stages in pod {} from database {}".format(destination_pod, dbname))
        cursor.execute("show stages in database {}".format(dbname))
        cursor.execute("select \"schema_name\",\"name\" from table(result_scan(last_query_id()))")
        # cursor.execute("select STAGE_SCHEMA, STAGE_NAME from information_schema.stages where stage_catalog='{}'".format(str(dbname).upper()))
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                stage_schema = var[0]
                stage_name   = var[1]
                stg_name     = stage_schema+'.'+stage_name
                cursor.execute("desc stage {}".format(stg_name))
                cursor.execute("insert into audit_archive.public.stage_properties select '{}','{}','{}',* from table(result_scan(last_query_id()))".format(dbname,stage_schema,stage_name))
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
        logger.info("Completed taking backup of stages in database {} from pod {}".format(dbname, destination_pod))
        return 0
    except Exception as e:
        logger.error("Error {} occurred while taking backup of stages/pipes/tasks/streams from pod {} in database {}".format(str(e),destination_pod, dbname))
        raise Exception("Error {} occurred while taking backup of stages/pipes/tasks/streams from pod {} in database {}".format(str(e),destination_pod, dbname))


def backup_users_roles_permissions(destination_account, destination_pod, dbname):
    """
    by default snowflake refresh do not take care of permissions so permissions need to be copied explicitly
    """
    try:
        logger.info("Started taking backup of privileges in pod {}".format(destination_pod))
        connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database audit_archive")
        cursor.execute("show users")
        cursor.execute("create or replace table audit_archive.public.dbusers as select *  from table(result_scan(last_query_id()))")
        cursor.execute("show roles")
        cursor.execute("create or replace table audit_archive.public.dbroles as select * from table(result_scan(last_query_id()))")
        cursor.execute("CREATE OR replace TABLE audit_archive.public.dbgrants(created_on timestamp_ltz,privilege varchar,granted_on varchar,"
                       "name varchar,granted_to varchar,grantee_name varchar,grant_option varchar,granted_by varchar)")
        cursor.execute("SELECT \"name\" as NAME FROM DBROLES")
        for var in cursor.fetchall():
            rolname = var[0]
            cursor.execute("show grants to role {}".format(rolname))
            cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
            cursor.execute("show grants on role {}".format(rolname))
            cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
        cursor.execute("SELECT \"name\" as NAME FROM DBUSERS")
        for var in cursor.fetchall():
            username = var[0]
            cursor.execute("show grants to user {}".format(username))
            cursor.execute("insert into audit_archive.public.dbgrants select *,null,null,null from table(result_scan(last_query_id()))")
            cursor.execute("show grants on user {}".format(username))
            cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
        logger.info("Taking backup of permissions to shares in database {} from pod {}".format(dbname, destination_pod))
        cursor.execute("show shares")
        cursor.execute("select \"name\" from table(result_scan(last_query_id()))"
                       " where \"kind\"='OUTBOUND' and \"database_name\"='{}'".format(str(dbname).upper()))
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                share_name = var[0]
                cursor.execute("show grants to share {}".format(share_name))
                cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
                cursor.execute("show grants on share {}".format(share_name))
                cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
            logger.info("Completed taking backup of shares privileges in pod {}".format(destination_pod, dbname))
        return 0
    except Exception as e:
        logger.error("Error {} occurred while taking backup of roles and privileges in pod {}".format(str(e),destination_pod))
        raise Exception("Error {} occurred while taking backup of roles and privileges in pod {}".format(str(e),destination_pod))


def restore_stages_permissions(destination_account, destination_pod, dbname, arc_techops_number):
    """
    1. Rename the existing database to dbname_old (this is where the downtime starts)
    2. Rename the cloned database from production to actual database
    3. restore the stages/permissions
    """
    error = 0
    try:
        connection, cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
        cursor.execute("use database {}".format(dbname))
        logger.info("Restoring stages and file formats")
        cursor.execute("select schemaname,def from audit_archive.public.stage_backup order by ordr")
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                schemaname    = var[0]
                sql_statement = var[1]
                logger.info(sql_statement)
                try:
                    cursor.execute("use schema {}".format(schemaname))
                    cursor.execute(sql_statement)
                except Exception as e:
                    logger.error("Failed to execute statement {}, continuing with next statement".format(sql_statement))
                    error = 1
                    continue
            logger.info("Successfully Restored stages and file formats")
        # Taking backup of shares
        logger.info("Taking backup of permissions to shares in database {} from pod {}".format(dbname, destination_pod))
        cursor.execute("show shares")
        cursor.execute("select \"name\" from table(result_scan(last_query_id()))"
                       " where \"kind\"='OUTBOUND' and \"database_name\"='{}_{}'".format(str(dbname).upper(),arc_techops_number))
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                share_name = var[0]
                cursor.execute("show grants to share {}".format(share_name))
                cursor.execute("insert into audit_archive.public.dbgrants select * from table(result_scan(last_query_id()))")
            logger.info("Completed taking backup of shares privileges in pod {}".format(destination_pod))
        logger.info("Revoking permissions from shares on old database")
        query = """
        select 'REVOKE '||PRIVILEGE||' ON '||GRANTED_ON||' '||NAME||' FROM '||GRANTED_TO||' '||GRANTEE_NAME||';'
        from audit_archive.public.dbgrants where granted_to='SHARE' and NAME like '{}_{}%'
        """.format(str(dbname).upper(),arc_techops_number)
        cursor.execute(query)
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                sql_statement = var[0]
                logger.info(sql_statement)
                try:
                    cursor.execute(sql_statement)
                except Exception as e:
                    logger.error("Failed to execute statement {}, continuing with next statement".format(sql_statement))
                    error = 1
                    continue
            logger.info("Successfully revoked permissions from shares on old database")
        logger.info("Granting permissions on database {} to shares/users/roles".format(dbname))
        query = """
        select CASE WHEN GRANTED_ON = 'ROLE' THEN 'GRANT '||replace(GRANTED_ON,'_',' ')||' '|| NAME ||' TO '||GRANTED_TO||' '||GRANTEE_NAME||';'
        ELSE 'GRANT '||PRIVILEGE||' ON '||replace(GRANTED_ON,'_',' ')||' '|| NAME ||' TO '||GRANTED_TO||' '||GRANTEE_NAME||';' END as cmd
        from audit_archive.public.dbgrants where granted_on not in ('ACCOUNT') and GRANTEE_NAME not in ('ACCOUNTADMIN','SECURITYADMIN')
        and name not like 'SNOWFLAKE_SAMPLE_DATA%' and NAME not in ('SNOWFLAKE','DS_USAGE','ORGANIZATION_USAGE','MONITORING_OWNER') and NAME not like '%{}%'
        """.format(arc_techops_number)
        logger.info(query)
        cursor.execute(query)
        result = cursor.fetchall()
        if len(result) > 0:
            for var in result:
                sql_statement = var[0]
                logger.info("executing statement {}".format(sql_statement))
                try:
                    cursor.execute(sql_statement)
                except Exception as e:
                    logger.error("Failed to execute statement {}, continuing with next statement".format(sql_statement))
                    error = 1
                    continue
            logger.info("Successfully granted permissions on database {} to shares".format(dbname))
        if error == 1:
            logger.error("Failed to restore the permissions/stages")
            return 1
        return 0
    except Exception as e:
        logger.error("Error occurred while restoring stages/permissions in pod".format(destination_pod))
        raise Exception("Error occurred while restoring stages/permissions in pod".format(destination_pod))


def main():
    args = parse_arguments()
    # Get the input arguments
    source_pod = args.source_pod
    destination_pod = args.destination_pod
    dbname = args.dbname

    try:
        global logfile
        # Enable logging
        logfile = '/g/dba/logs/dbrefresh/snowflakerefresh_{}_{}_{}.log'.format(source_pod, destination_pod,
                                                                               datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        global logger
        logger = snowflakeutil.setup_logging(logfile=logfile)

        # Get account details and host information
        cur_sql_dest, conn_sql_dest = snowflakeutil.sql_connect()
        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber from dbainfra.dbo.database_server_inventory "
                                    "where lower(ServerType)='snowflake' and lower(pod) = '{}'".format(str(source_pod).lower()))
        source_account = rows.fetchone()[0]

        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber,lower(Env) as env "
                                    "from dbainfra.dbo.database_server_inventory where lower(ServerType)='snowflake'"
                                    " and lower(pod) = '{}'".format(str(destination_pod).lower()))
        row = rows.fetchone()
        destination_account = row[0]
        destination_env     = row[1]

        cur_sql_dest.execute("select archelpnumber from dbainfra.dbo.refresh_desflow_ticket_details")
        arc_techops_number = cur_sql_dest.fetchone()[0]

        # Creating connections to the source and destination accounts
        destination_connection, destination_cursor = snowflakeutil.get_admin_connection(destination_account, destination_pod)
        source_connection, source_cursor           = snowflakeutil.get_admin_connection(source_account, source_pod)

        # create table to store the refresh status, once the database rename step is completed/failed the script should
        # not re-run
        destination_cursor.execute("create table if not exists audit_archive.public.refresh_status("
                                   "request_number varchar(50),step_start_time timestamp,step_end_time timestamp,"
                                   "step_name varchar(500),step_status varchar(1),comments varchar(500))")
        rename_step = destination_cursor.execute("select count(*) from audit_archive.public.refresh_status "
                                                 "where request_number='{}' and "
                                                 "step_name='rename_database'".format(arc_techops_number)).fetchone()[0]
        if rename_step != 0:
            logger.error("If the database rename step is failed, you should not re-run the script. Please check"
                         "http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation")
            raise Exception("If the database rename step is failed, you should not re-run the script. Please check"
                            "http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation")

        alert_summary   = "Snowflake Refresh" + source_pod + " to " + destination_pod
        """
        if the destination environment is prod we should not proceed with refresh
        """
        logger.info("checking the destination pod environment, if it is prod refresh will stop here")
        if destination_env == 'prod':
            logger.error("Destination pod {} is prod, refresh is not possible".format(destination_pod))
            status_message = "Refresh environment \n      Source: {} \n      Destination: {} \n Status: " \
                             "Destination pod should not be production. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=1,comments='Destination pod should not be production')
            sys.exit(1)

        """
        verify refresh is scheduled for this instance by checking the refresh_server_inventory table.
        """
        logger.info("checking the schedule of refresh, if not scheduled will stop here")
        retcode = check_refresh_possibility(destination_pod)
        if retcode == 1:
            logger.error("Refresh is not scheduled for this pod {}".format(destination_pod))
            status_message = "Refresh environment \n      Source: {} \n      Destination: {} \n Status: " \
                             "Refresh is not scheduled for this instance. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=1,comments='Refresh is not scheduled for this pod')
            sys.exit(1)

        """
        Verify replication is enabled between source pod and destination pod
        """
        update_current_running_status(source_pod, destination_pod, statuscode=2, comments="Refresh is scheduled. Verifying "
                                     "if replication enabled between source pod {} and destination pod {}".format(source_pod,destination_pod))
        logger.info("Verifying if replication enabled from source pod {} to destination pod {}".format(source_pod,destination_pod))
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Refresh is possible." \
                 "Verifying replication beteen source pod {} and destination pod {} \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod,source_pod,destination_pod)
        update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        retcode = check_replication(source_account, source_pod, destination_account, destination_pod)
        if retcode == 1:
            logger.error("Replication is not enabled between source pod {} and destination pod {}".format(source_pod, destination_pod))
            status_message = "Refresh environment \n      Source: {} \n      Destination: {} \n Status: " \
                             "Replication is not enabled between  source and destination. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,comments='Refresh is not scheduled for this pod')
            sys.exit(1)
        """
        Snowflake replication do not handle the stages and permissions. So before refresh take a backup of definitions of stages, file formats
        and permissions. Create backup tables in audit_archive database of destination pod to store DDL of stages and file formats.         
        """
        logger.info("Creating inventory tables stage_properties, stage_backup")
        # creating backup tables
        destination_cursor.execute("create or replace table audit_archive.public.stage_properties "
                                   "(dbname varchar,schemaname varchar, stagename varchar, "
                       "parent_property varchar, property varchar, property_type varchar, "
                       "property_value varchar, property_default varchar)")
        destination_cursor.execute("create or replace table audit_archive.public.stage_backup"
                                   "(dbname varchar,schemaname varchar,ordr int,def varchar)")
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
        update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        return_code = backup_users_roles_permissions(destination_account, destination_pod, dbname)
        if return_code != 0:
            logger.error("Failed to generate and store DDL commands for backup of users, roles and permissions")
            # update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus:" \
                 "Failed to backup DDL statements of privialges into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to backup  DDL statements of privileges into table , " \
                                "check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
            snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary, alert_description)
            sys.exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of users, roles , permissions and stored in table")
        """
        Snowflake replication work for database, in a Snowflake account there are multiple databases.
        So we need to replicate one by one database from source to destination.
        Login to the DBMONITOR get the list of databases, select each database and enable replication from source to destination
        """
        databases = []
        if args.dbname != 'none':
            databases.append(args.dbname)
        if args.dbname == 'none':
            cur_sql_dest.execute("select dbname from dbainfra.dbo.snowflake_db_refresh_inventory "
                                 "where pod='{}' and excluded=0".format(str(source_pod).lower()))
            result = cur_sql_dest.fetchall()
            if len(result) > 0:
                for i in result:
                    databases.append(i[0])
            if len(result) == 0:
                logger.info("No databases to refresh")
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                                 "There are no databases to refresh for source and destination pods in table snowflake_db_refresh_inventory. \n" \
                                 "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to backup DDL statements for stages into table , " \
                                    "check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
        logger.info("List of databases to be refreshed from source pod {} to destination pod {} are {}".format(source_pod, destination_pod, databases))

        for dbname in databases:
            logger.info("Enabling replication for database {} from source pod {} to destination pod {}".format(dbname, source_pod, destination_pod))
            # Update the status on the desflow request
            update_current_running_status(source_pod, destination_pod, statuscode=5,
                                          comments='Enabling replication for database {} from '
                                                   'source pod {} to destination pod {}'.format(dbname, source_pod, destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                             "Status: Enabling replication for database {} \n" \
                             "Please check the attached log file for further details".format(source_pod,
                                                                                             destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message, files_to_attach=[logfile])
            return_code = enable_replication(source_account, source_pod, destination_account, destination_pod, dbname)
            if return_code != 0:
                logger.error("Failed to enable the replication "
                             "from source pod {} "
                             "to destination pod {} for database {}".format(source_pod,destination_pod,dbname))
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                 "Failed to enable replication for database\n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Error while enabling replication between source pod {} " \
                                "and destination pod {} for database {}, check logfile {}, " \
                                "WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(source_pod,destination_pod,dbname,logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully enabled replication from source pod {} "
                        "to destination pod {} for database {}".format(source_pod,destination_pod,dbname))

            """
            Once the replication is enabled to destination account (uat), login to destination account (uat) and start 
            database refresh by copying database from source to destination
            """
            # updating the status on desflow
            update_current_running_status(source_pod, destination_pod, statuscode=3,
                                          comments='Replicating database {} '
                                                   'from source pod {} '
                                                   'to destination pod {}'.format(dbname,source_pod,destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Replication Enabled and Replicating the database {} from source pod to destination pod. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            logger.info("replicating database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
            logger.info("Database replication takes time based on database size")
            return_code = replicate_database_from_source(source_account, destination_account, destination_pod, dbname, source_pod)
            if return_code != 0:
                logger.error("Failed to replicate database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Replicating Database." \
                     "Failed to replicate database {} beteen source pod and destination pod \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Error while replicating database {} between " \
                                    "source pod {} and destination pod {} , check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(dbname,source_pod,destination_pod,logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully replicated database {} from source pod {} to destination pod {}".format(dbname, source_pod, destination_pod))
            """
            Snowflake refresh do not take the backup of stages and file formats, so these objects need to be
            backup and restore after the replication is completed.
            """
            logger.info("Generate DDL commands for taking backup of stages and file formats and store in table")
            # updating the status on Desflow
            update_current_running_status(source_pod, destination_pod, statuscode=4, comments='Taking backup of stages in database {}'.format(dbname))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Taking backup of stages in database {}. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            return_code = backup_stages(destination_account, destination_pod, dbname)
            if return_code != 0:
                logger.error("Failed to backup stages in database {}".format(dbname))
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                     "Failed to backup stages in database {}. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to backup DDL statements for stages into table , check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully Generated DDL commands for taking backup of stages, file formats and stored in table")
            """
            Now all the ddl statements backup is completed. Now we need to rename the existing database to old and rename the 
            replication database to actual. After that restore the stages and other ddls into that database.
            """
            # Rename the existing database to old and clone to actual database
            destination_cursor.execute("alter database IF EXISTS {} rename to {}_{}".format(dbname, dbname,arc_techops_number))
            destination_cursor.execute("alter database IF EXISTS {}_clone_{} rename to {}".format(source_pod,dbname, dbname))
            # Make an entry into the table to remove them after two days
            cur_sql_dest.execute("insert into dbainfra.dbo.snowflake_old_databases(accountname,pod,dbname,deleted) values"
                                 "('{}','{}','{}_{}',0)".format(destination_account, destination_pod,dbname,arc_techops_number))
        # Make entry after database rename
        destination_cursor.execute("insert into audit_archive.public.refresh_status(request_number,step_name,"
                                   "step_status,comments) values('{}','rename_database','s','Rename database')".format(arc_techops_number))
        # update the status on the Desflow
        update_current_running_status(source_pod, destination_pod, statuscode=6,comments='Restoring stages, permissions')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Restoring stages and permissions \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        # status updated on desflow
        return_code = restore_stages_permissions(destination_account, destination_pod, dbname,arc_techops_number)
        if return_code != 0:
            logger.error("Failed to restore the stages or permissions")
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
             "Status: Failed to Create SQL file with DDL of privilages, stages etc. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to restore the stages or permissions , check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
            snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully restored stages, file formats created in previous step")

        """
        Some times the objects in prod are not present in the uat, so it is required to apply the permissions to default
        roles which in turn applied to the users.
        """
        for dbname in databases:
            snowflakeutil.create_database(destination_account, dbname, destination_pod)

        logger.info("Database refresh completed successfully for database {}".format(databases))
        update_current_running_status(source_pod, destination_pod, statuscode=8,comments='Refresh completed successfully')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
             "Status: Refresh Completed successfully. \n" \
             "Please check the attached log file for further details".format(source_pod,destination_pod)
        update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
    except Exception as e:
        alert_summary   = "Snowflake Refresh" + source_pod + " to " + destination_pod
        logger.error("error occurred while performing refresh from source pod {} to "
                     "destination pod {} with error {}".format(source_pod, destination_pod, str(e)))
        traceback.print_exc()
        # update the status of the failure on desflow and raise radar alert
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Database refresh failed etc. \n" \
                     "Please check the attached log file for further details".format(source_pod, destination_pod)
        update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        alert_description = "Failed to refresh database from {} to {} etc. , " \
                            "check logfile {}, WIKI for automation " \
                            "is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(source_pod,destination_pod,logfile)
        snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
        sys.exit(1)


if __name__ == "__main__":
    main()
