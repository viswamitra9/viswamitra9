"""
owner       : oguri
Description : This is to refresh the Snowflake databases from source to destination
"""
import sys
import argparse
from datetime import datetime
import subprocess
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
        update_current_running_status(source_pod, destination_pod, statuscode=2, comments="Refresh is possible.Enabling replication beteen source pod {} and destination pod {}".format(source_pod,destination_pod))
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
            alert_description = "Error while enabling replication between source pod {} and destination pod {} , check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully enabled replication from source pod {} to destination pod {}".format(source_pod,destination_pod))

        """
        Once the replication is enabled to destination account (uat), login to destination account (uat) and start 
        database refresh by copying database from source to destination
        """
        # updating the status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=3, comments='Replicating database {} from source pod {} to destination pod {}'.format(DBNAME,source_pod,destination_pod))
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
        olddbname = str(dbname) + "_OLD"
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh -f /g/dba/snowflake/snowflake_refresh/3_backup_stages_pipes_tasks.sql -o quiet=true -o friendly=false -o header=false -s public -D DBNAME='{}' -o exit_on_error=true".format(destination_account_pwd,destination_host,olddbname,olddbname)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to generage and store DDL commands for backup of stages, pipes, file formats and tasks output : {} error: {}".format(str(output),str(err)))
            ## update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Replicating Database." \
                 "Failed to backup DDL statements for stages, tasks, pipes into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to backup DDL statements for stages, tasks, pipes into table , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
	    sys.exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of stages, tasks , pipes and file formats and stored in table")
        # Generate DDL comands for taking backup of grants and privilages
        logger.info("Generate DDL commands of users , roles , privilages and store in table")
        ## Update the status on the desflow request
        update_current_running_status(source_pod, destination_pod, statuscode=5,comments='Taking backup of privilages into table')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Taking backup of DDL statements of privilages into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh -f /g/dba/snowflake/snowflake_refresh/4_backup_users_roles_permissions.sql -o quiet=true -o friendly=false -o header=false -s public -o exit_on_error=true".format(destination_account_pwd,destination_host,olddbname)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to generage and store DDL commands for backup of users, roles and permissions. output : {} error: {}".format(str(output),str(err)))
            ## update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus:" \
                 "Failed to backup DDL statements of privialges into table. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to backup  DDL statements of privilages into table , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
            sys.exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of users, roles , permissions and stored in table")
        # Copy DDL statements from table to a file
        # update the status on the Desflow
        update_current_running_status(source_pod, destination_pod, statuscode=6,comments='Create SQL file with DDL of privilages, stages etc')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Create SQL file with DDL of privilages, stages etc. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        # status updated on desflow
        statementsfile = '/g/dba/snowflake/snowflake_refresh/backup_statements_{}_{}.sql'.format(destination_pod,datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        logger.info("Copy DDL statements created in previous step to a file")
	command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh -f /g/dba/snowflake/snowflake_refresh/5_post_backup_stages_tasks_pipes.sql -o quiet=true -o friendly=false -o header=false -s public -D DBNAME='{}' -o exit_on_error=true -o output_file={} -o output_format=plain".format(destination_account_pwd,destination_host,olddbname,olddbname,statementsfile)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
	output, err = pipes.communicate()
	if pipes.returncode != 0:
	    logger.error("Failed to copy DDL statements to file")
            logger.error("Error : {}".format(str(err)))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
		     "Status: Failed to Create SQL file with DDL of privilages, stages etc. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to Create SQL file with DDL of privilages, stages etc. , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
	    sys.exit(1)
        logger.info("Copied DDL statements created in previous step to a file")
	# Restore the objects
	logger.info("Restore the stages, pipes and file formats created in previous step")
        # update the status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=7,comments='Restore stages and privilages')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Restore stages and privilages etc. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        # status updated on desflow
	command = "export SNOWSQL_PWD={};tail -n+2 {} | /g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh -o quiet=true -o friendly=false -o header=false -s public -o exit_on_error=true".format(destination_account_pwd,statementsfile,destination_host,DBNAME)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
	output, err = pipes.communicate()
	if pipes.returncode != 0:
	    logger.error("Failed to restore the objects")
            logger.error("Error : {}".format(str(err)))
            ## update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
		     "Status: Failed to Restore stages and privilages etc. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Restore stages and privilages etc. , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
	    sys.exit(1)
        logger.info("Successfully restored stages, pipes and file formats created in previous step")
	# Cleanup old databases
	logger.info("Clean old databases created from replication and old uat database")
        # update status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=8,comments='Clean old databases')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Clean old databases etc. \n" \
                 "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        # updated the status on desflow
	command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh -f /g/dba/snowflake/snowflake_refresh/6_cleanup.sql -o quiet=true -o friendly=false -o header=false -s public -o exit_on_error=true".format(destination_account_pwd,destination_host,DBNAME)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
	output, err = pipes.communicate()
	if pipes.returncode != 0:
	    logger.error("Failed to clean old databases")
            logger.error("Error : {}".format(str(err)))
            ## update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
		         "Status: Failed to clean old databases etc. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            alert_description = "Failed to clean old databases during snowflake refresh from {} to {} etc. , check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
	    sys.exit(1)
        logger.info("Cleaned old databases! refresh completed successfully")
        update_current_running_status(source_pod, destination_pod, statuscode=8,comments='Refresh completed successfully')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
             "Status: Refresh Completed successfully. \n" \
             "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
    except Exception as e:
        logger.error(e)
        traceback.print_exc()
        ## update the status of the failure on desflow and raise radar alert
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
		     "Status: Database refresh failed etc. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
        alert_description = "Failed to refresh database from {} to {} etc. , check logfile {}".format(source_pod,destination_pod,logfile)
        radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
        sys.exit(1)


if __name__ == "__main__":
    main()