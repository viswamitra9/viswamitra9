"""
owner       : oguri
Description : This is to refresh the Snowflake databases from source to destination account
"""
import sys
sys.path.append('/g/dba/snowflake/')
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


def main():
    args = parse_arguments()
    # Get the input arguments
    source_pod      = args.source_pod
    destination_pod = args.destination_pod
    dbname          = args.dbname

    try:
        global logfile
        # Enable logging
        logfile = '/g/dba/logs/dbrefresh/snowflakerefresh_{}_{}_{}.log'.format(source_pod, destination_pod,datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
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

        # create table to store the refresh status, once the database rename step is completed/failed the script should not re-run
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
        verify refresh is scheduled for this instance by checking the refresh_server_inventory table in DBMONITOR.
        """
        logger.info("checking the schedule of refresh, if not scheduled will stop here")
        retcode = snowflakeutil.check_refresh_possibility(destination_pod)
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
        retcode = snowflakeutil.check_replication(source_account, source_pod, destination_account, destination_pod)
        if retcode == 1:
            logger.error("Replication is not enabled between source pod {} and destination pod {}".format(source_pod, destination_pod))
            status_message = "Refresh environment \n      Source: {} \n      Destination: {} \n Status: " \
                             "Replication is not enabled between  source and destination. \n" \
                             "Please check the attached log file for further details".format(source_pod, destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            update_current_running_status(source_pod, destination_pod, statuscode=11,comments='Refresh is not scheduled for this pod')
            sys.exit(1)
        """
        Snowflake replication do not handle the stages and shares permissions. So before refresh take a backup of definitions of internal stages and share
        permissions. Create backup tables in audit_archive database of destination pod to store DDL of stages and file formats.
        """
        logger.info("Creating inventory tables stage_properties, stage_backup")
        # creating backup tables
        destination_cursor.execute("create table if not exists audit_archive.public.stage_properties "
                                   "(dbname varchar,schemaname varchar, stagename varchar, parent_property varchar, "
                                   "property varchar, property_type varchar,property_value varchar, property_default varchar)")
        destination_cursor.execute("create table if not exists audit_archive.public.stage_backup"
                                   "(dbname varchar,schemaname varchar,ordr int,def varchar)")
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
                alert_description = "There are no databases to refresh for source and destination pods in table snowflake_db_refresh_inventory. , " \
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
                             "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message, files_to_attach=[logfile])
            return_code = snowflakeutil.enable_replication_for_database(source_account, source_pod, destination_account, destination_pod, dbname)
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
            logger.info("Successfully enabled replication from source pod {} to destination pod {} for database {}".format(source_pod,destination_pod,dbname))

            """
            Snowflake replication do not handle the permissions given to shares for a database. Take a backup and restore 
            them after refresh
            """
            logger.info("Backup permissions granted to shares")
            # Update the status on the desflow request
            update_current_running_status(source_pod, destination_pod, statuscode=5,comments='Taking backup of permissions assigned to shares')
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                             "Status: Taking backup of permissions assigned to shares. \n" \
                             "Please check the attached log file for further details".format(source_pod,destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message, files_to_attach=[logfile])
            return_code = snowflakeutil.backup_shares_permissions(destination_account, destination_pod, dbname)
            if return_code != 0:
                logger.error("Failed to backup permissions assigned to shares")
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus:" \
                                 "Failed to backup permissions assigned to shares \n" \
                                 "Please check the attached log file for further details".format(source_pod,destination_pod)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to backup permissions assigned to shares , " \
                                    "check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully backup permissions assigned to shares")

            """
            Once the replication is enabled to destination account (uat), login to destination account (uat) and start 
            database refresh by copying database from source to destination
            """
            # updating the status on desflow
            update_current_running_status(source_pod, destination_pod, statuscode=3,
                                          comments='Replicating database {} from source pod {} to destination pod {}'.format(dbname,source_pod,destination_pod))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Replication Enabled and Replicating the database {} from source pod to destination pod. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            logger.info("replicating database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
            logger.info("Database replication takes time based on database size")
            return_code = snowflakeutil.replicate_database_from_source(source_account, destination_account, destination_pod, dbname, source_pod)
            if return_code != 0:
                logger.error("Failed to replicate database {} from source pod {} to destination pod {}".format(dbname,source_pod,destination_pod))
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: Replicating Database." \
                     "Failed to replicate database {} beteen source pod and destination pod \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Error while replicating database {} between " \
                                    "source pod {} and destination pod {} , check logfile {}, " \
                                    "WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(dbname,source_pod,destination_pod,logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully replicated database {} from source pod {} to destination pod {}".format(dbname, source_pod, destination_pod))
            """
            Snowflake refresh do not take the backup of stages and file formats, so these objects need to be
            backup and restore after the replication is completed.
            """
            logger.info("Generate DDL commands for taking backup of internal stages")
            # updating the status on Desflow
            update_current_running_status(source_pod, destination_pod, statuscode=4, comments='Taking backup of internal stages in database {}'.format(dbname))
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Taking backup of internal stages in database {}. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            return_code = snowflakeutil.backup_internal_stages(destination_account, destination_pod, dbname)
            if return_code != 0:
                logger.error("Failed to take backup of internal stages in database {}".format(dbname))
                # update the status of the failure on desflow and raise radar alert
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\nStatus: " \
                     "Failed to backup stages in database {}. \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod,dbname)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to take backup of internal stages in database , check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully Generated DDL commands for taking backup of internal stages")
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
            destination_cursor.execute("insert into audit_archive.public.refresh_status(request_number,step_name,step_status) values('{}','rename_database','s')".format(arc_techops_number))
            # update the status on the Desflow
            update_current_running_status(source_pod, destination_pod, statuscode=6,comments='Restoring stages, permissions')
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Restoring stages and fileformats \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            # status updated on desflow
            return_code = snowflakeutil.restore_stages_fileformats(destination_account, destination_pod, dbname, arc_techops_number)
            if return_code != 0:
                logger.error("Failed to restore the stages or file formats")
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Failed to restore the stages or file formats. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to restore the stages or file formats , " \
                                    "check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully restored stages, file formats")
            # Restore permissions of objects and permissions granted to share
            # update the status on the Desflow
            update_current_running_status(source_pod, destination_pod, statuscode=6,comments='Restoring stages, permissions')
            status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                     "Status: Restore object permissions and permissions assigned to shares \n" \
                     "Please check the attached log file for further details".format(source_pod,destination_pod)
            update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
            # status updated on desflow
            return_code = snowflakeutil.restore_shares_permissions(destination_account, destination_pod, dbname, arc_techops_number)
            if return_code != 0:
                logger.error("Failed to restore object permissions and permissions assigned to shares")
                status_message = "Refresh environment\n      Source: {}\n      Destination: {}\n" \
                 "Status: Failed to restore object permissions and permissions assigned to shares. \n" \
                         "Please check the attached log file for further details".format(source_pod,destination_pod)
                update_current_running_refresh_status_on_desflow(status_message=status_message,files_to_attach=[logfile])
                alert_description = "Failed to restore object permissions and permissions assigned to shares , " \
                                    "check logfile {}, WIKI for automation is : http://wiki.ia55.net/display/TECHDOCS/Snowflake+Database+Refresh+Automation".format(logfile)
                snowflakeutil.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,alert_description)
                sys.exit(1)
            logger.info("Successfully restored object permissions and permissions assigned to shares")
            # Database refresh completed successfully
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
