import logging
import sys
import argparse
import time
from datetime import datetime
import subprocess
import os
import traceback

from snowflake.connector.secret_detector import SecretDetector
sys.path.append('/g/dba/pythonutilities/')
from pythonutils import PythonUtils

sys.path.append('/g/dba/radarutil/')
from radarutil import RadarUtil
radarutil=RadarUtil()

sys.path.append('/g/dba/rds')
import pod_automation_util

import dbrefreshutil
from dbrefreshutil import DBRefreshUtil

logger = logging.getLogger()

# Variables for radar alerts
alert_source   = "dba"
alert_class    = "Page"
alert_severity = "CRITICAL",
alert_key      = "Snowflake refresh"


def setup_logging(logfile):
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


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True,
                                     description=
                                     'example : sudo -u sqlexec python snowflake_refresh.py -s bamuat -d terra')
    parser.add_argument("-s", "--source-pod",
                        dest="source_pod",
                        help="source pod to copy database",
                        required=True)
    parser.add_argument('-d', '--destination-pod',
                        dest='destination_pod', default='none',
                        help='destination pod to restore database', required=True)
    parser.add_argument('-db', '--dbname',
                        dest='dbname', default='none',
                        help='dbname to be copied from source to destination', required=True)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    return parser.parse_args()


def update_current_running_status(sourceservername, destinationservername, statuscode, comments):
    query = "insert into dbainfra.dbo.refresh_current_running_status values('" + sourceservername + "','" + \
            destinationservername + "', getdate() ,'" + str(statuscode) + "','" + comments + "')"
    cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


def main():
    # parse input arguments and get variables
    args = parse_arguments()
    source_pod = args.source_pod
    destination_pod = args.destination_pod
    DBNAME = args.dbname
    alert_summary = "Snowflake Refresh {} to {}".format(source_pod, destination_pod)
    # configure logging
    logfile = '/g/dba/logs/dbrefresh/snowflakerefresh_{}_{}_{}.log'.format(source_pod, destination_pod,
                                                                           datetime.now().strftime(
                                                                               "%d-%b-%Y-%H-%M-%S"))
    setup_logging(logfile)

    ## Create object for dbrefreshutil
    dbrefreshutil = DBRefreshUtil(logger=None)
    try:
        ## Get account details and host information
        cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber "
                                    "from dbainfra.dbo.database_server_inventory "
                                    "where ServerType='snowflake' and pod = '{}'".format(source_pod))
        row = rows.fetchone()
        source_host = row[0]
        source_account = str(source_host).split('.')[0]
        rows = cur_sql_dest.execute("select upper(FriendlyName) as accountnumber,lower(Env) as env "
                                    "from dbainfra.dbo.database_server_inventory "
                                    "where ServerType='snowflake' and pod = '{}'".format(destination_pod))
        row = rows.fetchone()
        destination_host    = row[0]
        destination_env     = row[1]
        destination_account = str(destination_host).split('.')[0]

        """
        Before performing the actual refresh, verify the destination pod not belongs to prod, if it belongs to prod
        exit from the code and update the request.
        """
        if destination_env == 'prod':
            logging.error("Destination pod {} is prod, refresh is not possible".format(destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                             "Destination pod should not be production. \n" \
                             "Please check the attached log file for more details".format(source_pod, destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow\
                (status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,
                                          comments='Destination pod should not be production')
            exit(1)

        """
        Verify the refresh is scheduled for the instance, if the refresh is not scheduled for the pod, code will exit
        with return code 1
        """
        retcode = pod_automation_util.check_refresh_possibility(destination_pod)
        if retcode == 1:
            logging.error("Refresh is not scheduled for this pod {}".format(destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                             "Refresh is not scheduled for this instance. \n" \
                             "Please check the attached log file for more details".format(source_pod, destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow\
                (status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,
                                          comments='Refresh is not scheduled for this pod')
            exit(1)

        """
        Snowflake refresh works based on replication, so first step is enabling replication between source and 
        destination accounts. If replication is not enabled update the request with error and exit with return code 1
        """
        source_account_pwd      = pod_automation_util.get_app_user_password\
            ('/secret/v2/snowflake/{}/db/sa'.format(source_pod))
        destination_account_pwd = pod_automation_util.get_app_user_password\
            ('/secret/v2/snowflake/{}/db/sa'.format(destination_pod))

        update_current_running_status(source_pod, destination_pod, statuscode=2,
                                      comments="Refresh is possible.Enabling replication beteen source pod {} "
                                               "and destination pod {}".format(source_pod,destination_pod))
        logger.info("Enabling replication from source pod {} to destination pod {}".format(source_pod,destination_pod))
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Refresh is possible." \
                         "Enabling replication beteen source pod {} and destination pod {} \n" \
                         "Please check the attached log file for further " \
                         "details".format(source_pod,destination_pod,source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])

        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/1_check_enable_refresh.sql -o quiet=true " \
                  "-o friendly=false -o header=false -s public -D DBNAME='{}' -D ACCOUNTNAME='{}' " \
                  "-o exit_on_error=true".format(source_account_pwd,source_host,DBNAME,DBNAME,destination_account)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to enable the replication from source pod {} to "
                         "destination pod {}".format(source_pod,destination_pod))
            logger.error("Output : {} , Error : {}".format(str(output),str(err)))
            ## update the status of the failure on desflow and raise radar alert
            status_message = "Refresh environment\n      Source: {}\n   Destination: {}\nStatus: Refresh is possible." \
                             "Failed to enable replication beteen source pod {} and destination pod {} \n" \
                             "Please check the attached log file for further " \
                             "details".format(source_pod,destination_pod,source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Error while enabling replication between source pod {} and destination pod {} , " \
                                "check logfile {}".format(source_pod,destination_pod,logfile)

            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class,
                                        alert_key, alert_summary, alert_description)
            exit(1)
        logger.info("Successfully enabled replication from source account {} to "
                    "destination account {}".format(source_host,destination_host))

        """
        After refresh is enabled successfully , Replicate the database from source to destination. To perform this 
        Snowflake will use the cloud services warehouses. We will refresh the database with different name in 
        destination (uat). Replicate the database with name "<dbname>_new".
        """
        update_current_running_status(source_pod, destination_pod, statuscode=3,
                                      comments='Replicating database {} from source pod {} to '
                                               'destination pod {}'.format(DBNAME, source_pod, destination_pod))
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Replication Enabled and Replicating the database" \
                         " from source pod to destination pod. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        logger.info("replicate database {} from source account {} to "
                    "destination account {}".format(DBNAME,source_account, destination_account))
        logger.info("Database replication takes time based on database size")
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/2_replicate_database_from_source.sql -o quiet=true " \
                  "-o friendly=false -o header=false -s public -D DBNAME='{}' -D ACCOUNTNAME='{}' " \
                  "-o exit_on_error=true".format(destination_account_pwd,destination_host,DBNAME,DBNAME,source_account)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to replicate database {} from source account {} to "
                         "destination account {}".format(DBNAME,source_host,destination_host))
            logger.error("Error : {}".format(str(err)))

            status_message = "Refresh environment\n      Source: {}\n  Destination: {}\nStatus: Replicating Database." \
                             "Failed to replicate database beteen source pod {} and destination pod {} \n" \
                             "Please check the attached log file for further  " \
                             "details".format(source_pod,destination_pod,source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Error while replicating database between source pod {} and destination pod {} ," \
                                " check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key,
                                        alert_summary,alert_description)
            exit(1)
        logger.info("Successfully replicated database {} from source account {} to "
                    "destination account {}".format(DBNAME,source_account,destination_account))

        """
        Snowflake replication do not handle stages, tasks, pipes, file formats and permissions. 
        So before performing refresh take the backup of stages and other objects. After refresh is completed this 
        backup will be restored.
        """
        logger.info("Generate DDL commands for taking backup of stages, tasks, pipes and file formats to table")

        update_current_running_status(source_pod, destination_pod, statuscode=4,
                                      comments='Taking backup of DDL statements for stages, tasks, pipes into table')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Taking backup of DDL statements for stages, tasks, pipes into table. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        olddbname = str(DBNAME) + "_OLD"
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/3_backup_stages_pipes_tasks.sql -o quiet=true " \
                  "-o friendly=false -o header=false -s public -D DBNAME='{}' " \
                  "-o exit_on_error=true".format(destination_account_pwd,destination_host,olddbname,olddbname)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to generage and store DDL commands for backup of stages, pipes, file formats and "
                         "tasks output : {} error: {}".format(str(output),str(err)))

            status_message = "Refresh environment\n      Source: {}\n  Destination: {}\nStatus: Replicating Database." \
                             "Failed to backup DDL statements for stages, tasks, pipes into table. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Failed to backup DDL statements for stages, tasks, pipes into table," \
                                " check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                        alert_description)
            exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of stages, tasks , "
                    "pipes and file formats and stored in table")
        """
        Take backup of users , roles and permissions in uat and store in to a table. Which will be restored after
        refresh is completed.
        """
        logger.info("Generate DDL commands of users , roles , privilages and store in table")
        update_current_running_status(source_pod, destination_pod, statuscode=5,
                                      comments='Taking backup of privilages into table')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Taking backup of DDL statements of privilages into table. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/4_backup_users_roles_permissions.sql -o quiet=true " \
                  "-o friendly=false -o header=false -s public " \
                  "-o exit_on_error=true".format(destination_account_pwd,destination_host,olddbname)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0 or output.strip() != 'SUCCESS':
            logger.error("Failed to generage and store DDL commands for backup of users, roles and permissions. "
                         "output : {} error: {}".format(str(output),str(err)))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus:" \
                             "Failed to backup DDL statements of privialges into table. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Failed to backup  DDL statements of privilages into table , " \
                                "check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                        alert_description)
            exit(1)
        logger.info("Successfully Generated DDL commands for taking backup of users, roles , permissions and "
                    "stored in table")
        """
        Create a sql file with DDL for create stages, pipes, file formats, users and permissions the metadata gathered 
        in previous step. Execute this sql file to complete the restoration.
        """
        update_current_running_status(source_pod, destination_pod, statuscode=6,
                                      comments='Create SQL file with DDL of privilages, stages etc')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Create SQL file with DDL of privilages, stages etc. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        # backup file
        statementsfile = '/g/dba/snowflake/snowflake_refresh/backup_statements_{}_{}.sql'.format(destination_pod,
                                                             datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        logger.info("Backup DDL statements created in previous step to a file")
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/5_post_backup_stages_tasks_pipes.sql -o quiet=true " \
                  "-o friendly=false -o header=false -s public -D DBNAME='{}' -o exit_on_error=true " \
                  "-o output_file={} -o output_format=plain".format(destination_account_pwd, destination_host,
                                                                    olddbname,olddbname,statementsfile)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0:
            logger.error("Failed to copy DDL statements to file")
            logger.error("Error : {}".format(str(err)))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                             "Status: Failed to Create SQL file with DDL of privilages, stages etc. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Failed to Create SQL file with DDL of privilages, stages etc. , " \
                                "check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                        alert_description)
            exit(1)
        logger.info("Copied DDL statements created in previous step to a file")
        """
        Restore the backup of stages, pipes and file formats to database replicated from source pod. This will restore 
        the stages, pipes, file formats and permissions.
        """
        logger.info("Restore the stages, pipes and file formats created in previous step")
        # update the status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=7,
                                      comments='Restore stages and privilages')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Restore stages and privilages etc. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        command = "export SNOWSQL_PWD={};tail -n+2 {} | /g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-o quiet=true -o friendly=false -o header=false -s public " \
                  "-o exit_on_error=true".format(destination_account_pwd,statementsfile,destination_host,DBNAME)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0:
            logger.error("Failed to restore stages, pipes, file formats and permissions with error {}".format(str(err)))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                             "Status: Failed to Restore stages and privilages etc. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Restore stages and privilages etc. , check logfile {}".format(logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                        alert_description)
            exit(1)
        logger.info("Successfully restored stages, pipes and file formats created in previous step")
        # Cleanup old databases
        logger.info("Clean old databases created from replication and old uat database")
        # update status on desflow
        update_current_running_status(source_pod, destination_pod, statuscode=8,comments='Clean old databases')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Clean old databases etc. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        # updated the status on desflow
        command = "export SNOWSQL_PWD={};/g/dba/snowflake/bin/snowsql -a {} -d {} -u sa -w dba_wh " \
                  "-f /g/dba/snowflake/snowflake_refresh/6_cleanup.sql -o quiet=true -o friendly=false " \
                  "-o header=false -s public " \
                  "-o exit_on_error=true".format(destination_account_pwd,destination_host,DBNAME)
        pipes = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = pipes.communicate()
        if pipes.returncode != 0:
            logger.error("Failed to clean old databases with error {}".format(str(err)))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                             "Status: Failed to clean old databases etc. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Failed to clean old databases during snowflake refresh from {} to {} etc. ," \
                                " check logfile {}".format(source_pod,destination_pod,logfile)
            radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                        alert_description)
            exit(1)
        logger.info("Cleaned old databases! refresh completed successfully")
        update_current_running_status(source_pod, destination_pod, statuscode=8,
                                      comments='Refresh completed successfully')
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Refresh Completed successfully. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
    except Exception as e:
        logger.error(e)
        traceback.print_exc()
        ## update the status of the failure on desflow and raise radar alert
        status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                         "Status: Database refresh failed etc. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Failed to refresh database from {} to {} etc. , " \
                            "check logfile {}".format(source_pod,destination_pod,logfile)
        radarutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                    alert_description)
        exit(1)


if __name__ == "__main__":
    main()