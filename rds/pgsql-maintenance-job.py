#!/usr/bin/env python2

import argparse
import logging
import sys
import pyodbc

logger = logging.getLogger('pgsql-maintenance-job')


def setup_logging(loglevel, logfile):
    logger.setLevel(logging.getLevelName(loglevel.upper()))
    if logfile == '-':
        ch = logging.StreamHandler(sys.stdout)
    elif logfile == 'STDERR':
        ch = logging.StreamHandler(sys.stderr)
    else:
        ch = logging.handlers.RotatingFileHandler(logfile,
                                                  maxBytes=20 * 1024 * 1024,
                                                  backupCount=1)
    formatter = logging.Formatter('%(asctime)s %(levelname)-7s %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


from retrying import retry
@retry(stop_max_attempt_number=5, wait_fixed=1000)
def sql_connect():
    # create a SQL connection to DBMONITOR1B database and return the connection and cursor object
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor5b.win.ia55.net;APP=Hammer;database=dbainfra')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logger.error("Failed to connect to DBMONITOR with error : {}, trying again".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create weekend maintenance job")
    createordelete.add_argument("--delete", action='store_true', help="To delete weekend maintenance job")
    # Required arguments
    parser.add_argument('--pod', dest='pod', help='Give pod information example: gicuat', required=True)
    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="Dry run the maintenance job creation/deletion")
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    return parser.parse_args()


def create_maintenance_job(pod, dry_run):
    # function to create maintenance job for newly created RDS instance
    dataserver = 'dbpostgres.' + pod + '.c.ia55.net'
    cur_sql, conn_sql = sql_connect()
    query = """
    USE [msdb]

    /****** Object: Job [(dba) Postgres Defragment/Statistics/Vacuum:{server}] ******/
    BEGIN TRANSACTION
    DECLARE @ReturnCode INT
    SELECT @ReturnCode = 0
    /****** Object: JobCategory [(dba) Enable in PROD and During DR] ******/
    IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'(dba) Enable in PROD and During DR' AND category_class=1)
    BEGIN
    EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'(dba) Enable in PROD and During DR'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

    END

    DECLARE @jobId BINARY(16)
    EXEC @ReturnCode = msdb.dbo.sp_add_job @job_name=N'(dba) Postgres Defragment/Statistics/Vacuum:{server}', 
            @enabled=1, 
            @notify_level_eventlog=0, 
            @notify_level_email=0, 
            @notify_level_netsend=0, 
            @notify_level_page=0, 
            @delete_level=0, 
            @description=N'No description available.', 
            @category_name=N'(dba) Enable in PROD and During DR', 
            @owner_login_name=N'sa', @job_id = @jobId OUTPUT
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    /****** Object:  Step [Run Index Maintainance] ******/
    EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Run Index Maintainance', 
            @step_id=1, 
            @cmdexec_success_code=0, 
            @on_success_action=1, 
            @on_success_step_id=0, 
            @on_fail_action=2, 
            @on_fail_step_id=0, 
            @retry_attempts=0, 
            @retry_interval=0, 
            @os_run_priority=0, @subsystem=N'CmdExec', 
            @command=N'Powershell.exe \\\win.ia55.net\windows\scripts\dba\Monitoring\PostgresMaintenance\postgresmaintenance.ps1 -server {server}',
            @flags=8
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'Regular', 
            @enabled=1, 
            @freq_type=8, 
            @freq_interval=64, 
            @freq_subday_type=1, 
            @freq_subday_interval=0, 
            @freq_relative_interval=0, 
            @freq_recurrence_factor=1, 
            @active_start_date=20180502, 
            @active_end_date=99991231, 
            @active_start_time=0, 
            @active_end_time=235959, 
            @schedule_uid=N'3fac15db-d7bd-4592-bf66-02fc2718c0b7'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    COMMIT TRANSACTION
    GOTO EndSave
    QuitWithRollback:
        IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
    EndSave:

    """
    if dry_run:
        logger.info("dry run: run the below query in dbmonitor SQL server")
        logger.info("dry run: " + query.format(server = dataserver))
    else:
        try:
            query_cnt = "select count(1) from msdb.dbo.sysjobs where name = N'(dba) Postgres Defragment/Statistics/Vacuum:" + dataserver + "'"
            rows = cur_sql.execute(query_cnt)
            row = rows.fetchone()
            if row[0] == 0:
                cur_sql.execute(query.format(server = dataserver))
                cur_sql.commit()
            else:
                logger.info("Maintenance job already exists")
            conn_sql.close()
        except Exception as ex:
            logger.error("Error while creating the maintenance job: {}".format(str(ex)))
            exit(1)


def delete_maintenance_job(pod, dry_run):
    # function to remove maintenance job
    dataserver = 'dbpostgres.' + pod + '.c.ia55.net'
    cur_sql, conn_sql = sql_connect()
    query = """
    USE [msdb]

    EXEC msdb.dbo.sp_delete_job @job_name=N'(dba) Postgres Defragment/Statistics/Vacuum:{server}'
    """
    if dry_run:
        logger.info("dry run: run the below query in dbmonitor SQL server")
        logger.info("dry run: " + query.format(server = dataserver))
    else:
        try:
            query_cnt = "select count(1) from msdb.dbo.sysjobs where name = N'(dba) Postgres Defragment/Statistics/Vacuum:" + dataserver + "'"
            rows = cur_sql.execute(query_cnt)
            row = rows.fetchone()
            if row[0] == 0:
                logger.info("Maintenance job does not exist, skipping...")
            else:
                cur_sql.execute(query.format(server = dataserver))
                cur_sql.commit()
            conn_sql.close()
        except Exception as ex:
            logger.error("Error while deleting the maintenance job: {}".format(str(ex)))
            exit(1)


def main():
    # Get the user inputs
    args = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    pod = args.pod
    dryrun = args.dry_run
    instance_action = ''

    if args.create:
        instance_action = 'create'
    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '
    else:
        dry_run = ''

    if instance_action == 'create':
        create_maintenance_job(pod, dry_run)
    if instance_action == 'delete':
        delete_maintenance_job(pod, dry_run)


if __name__ == "__main__":
    main()
