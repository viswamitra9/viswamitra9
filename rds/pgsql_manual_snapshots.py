#!/usr/bin/env python2
"""
Author        : oguri
jobexec Job   : PostgreSQL_prod_snapshots
Descriptiopn  : This script take snapshot backup of all production RDS instances on every month 9th.
"""

import argparse
import logging
import datetime
from datetime import datetime
import arcesium.infra.boto as arcboto
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
# for multi-processing
from multiprocessing import Process
import time
from arcesium.radar.client import SendAlertRequest
from arcesium.radar.client import RadarService
# for SQL connection
import sys
import pyodbc

config = Config(
    retries=dict(
        max_attempts=20
    )
)

# multi processing related parameters
MAX_PROCESSES        = 5
SLEEP_TIME           = 300
MAX_RETRIES          = 20
SQL_CONN_RETRY_COUNT = 5

logger = logging.getLogger('pgsql-snapshot')
# creating file handler
logfile = '/g/dba/logs/dbbackup/pgsql_prod_snapshot_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))

# variables for SQL server connection and cursor
cur_sql  = ''
conn_sql = ''


def set_logging():
    # default log level for root handler
    logger.setLevel(logging.INFO)
    ch = logging.FileHandler(logfile)
    ch.setLevel(logging.INFO)
    # creating stream handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.ERROR)
    # create formatter
    logging_format = logging.Formatter('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s')
    ch.setFormatter(logging_format)
    sh.setFormatter(logging_format)
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)


def sql_connect():
    """
    Crate connection to DBMONITOR server
    Returns:
    cursor and connection
    """
    retry_count = 0
    while retry_count < SQL_CONN_RETRY_COUNT:
        try:
            conn_sql_dest = pyodbc.connect(
                'DRIVER={Easysoft ODBC-SQL Server};'
                'Server=DBMONITOR1B.win.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=pgsql;')
            cur_sql_dest = conn_sql_dest.cursor()
            conn_sql_dest.autocommit = True
            return cur_sql_dest, conn_sql_dest
        except Exception as e:
            logging.error("Error while creating database connection to DBMONITOR server {}, trying again {}".format(str(e), retry_count))
    retry_count += 1
    raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def raise_radar_alert(alert_description):
    request = SendAlertRequest()
    request.alert_source      = 'dba'
    request.alert_key         = 'PostgreSQL-Generate-Snapshot-Failure'
    request.alert_summary     = 'PostgreSQL snapshot generation failure for production instances'
    request.alert_class       = 'PAGE'
    request.alert_description = alert_description + " Please check the {} file for details and reference the {} documentation for more information.".format(logfile,'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots')
    request.alert_severity    = 'CRITICAL'
    request.alertKB           = 'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots'

    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def parse_arguments():
    """
    Parse input argements
    """
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create snapshot")
    return parser.parse_args()


def get_rds_clients(region, account='prod'):
    """
    Args:
        account: Account name "ex: prod "
        region: region "ex: us-east-1"
    Returns:
        returns a boto3 session to AWS
    """
    try:
        arcboto.install()
        session = boto3.session.Session(profile_name='{}/dba'.format(account))
        rds = session.client('rds', region_name='{}'.format(region), config=config)
        return rds
    except Exception as e:
        logger.error("exception while fetching boto3 connection {}".format(str(e)))
        alert_description = "Error while taking rds monthly backup, not able to create rds session"
        raise_radar_alert(alert_description)
        exit(1)


def create_snapshot(pod, region, instance, account='prod'):
    """
    Create snapshot of the given PostgreSQL RDS cluster and make an entry of it
    Args:
        pod: "pod name ex: balyuat"
        account:  "account ex: prod"
        region:  "region ex: us-east-1"
        instance: "name of instance ex: balydbpg1a"
    Returns: null
    """
    rds          = get_rds_clients(region, account)
    response     = rds.describe_db_instances(DBInstanceIdentifier=instance)
    cluster      = response['DBInstances'][0]['DBClusterIdentifier']
    snapshotname = instance + '-monthly-snapshot-' + format(datetime.now().strftime("%m-%Y"))
    logger.info("Taking backup of instance : {}".format(instance))
    try:
        rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshotname, DBClusterIdentifier=cluster)
        snapshot_arn = wait_snapshot_available(rds, snapshotname)
        make_entry_for_snapshot(region=region, account=account, snapshotname=snapshotname, arn=snapshot_arn, pod=pod)
        logger.info("snapshot {} creation completed successfully for instance {}".format(snapshotname, instance))
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterSnapshotAlreadyExistsFault':
            logger.info("The snapshot {} already completed".format(snapshotname))
            snapshot_arn = wait_snapshot_available(rds, snapshotname)
            make_entry_for_snapshot(region=region, account=account, snapshotname=snapshotname, pod=pod,arn=snapshot_arn)
        else:
            logger.error("Error occured while taking snapshot of instance {}, error: {}".format(instance,e))
            # alert_description = "Error while taking snapshot for instance {}, " \
                                # "Please check error log for more details".format(instance)
            # raise_radar_alert(alert_description)
            exit(1)


def wait_snapshot_available(rds, snapshotname):
    """
    snapshot creation is async operation, wait for snapshot to complete.
    Args:
        rds: session to boto3
        snapshotname: name of snapshotname
    Returns: response of snapshot
    """
    retry_count = 0
    try:
        response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        while response['DBClusterSnapshots'][0]['Status'] != 'available':
            logger.info("still waiting for snapshot : {} to complete, "
                        "retry count : {}".format(snapshotname, retry_count))
            time.sleep(SLEEP_TIME)
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
            retry_count += 1
            if retry_count == MAX_RETRIES:
                """
                if the backup is running for more than 100 min raise an alert to check the job
                """
                logger.error("Manual snapshot for instance {} is running for more than 100 min, check log file "
                             "more details".format(str(snapshotname).split('-')[0]))
                alert_description = "Manual snapshot for instance {} is running for more than 100 min, " \
                                    "Please check the job PostgreSQL_prod_snapshots for more " \
                                    "details".format(str(snapshotname).split('-')[0])
                raise_radar_alert(alert_description)
                exit(1)
        return response['DBClusterSnapshots'][0]['DBClusterSnapshotArn']
    except ClientError as e:
        logger.error("Error while creating snapshot {} , error : {}".format(snapshotname,e))
        alert_description = "Error while taking snapshot {}, " \
                            "Please check error log for more details".format(snapshotname)
        raise_radar_alert(alert_description)
        exit(1)


def make_entry_for_snapshot(pod, region, snapshotname, arn, account='prod'):
    """
    Args:
        pod: "ex: baly
        region:  "ex : us-east-1"
        snapshotname: "baamdbpg1a-09-11-2019-07-54-36"
        arn: "ex: arn:aws:rds:us-east-1:674283286888:cluster-snapshot:baamdbpg1a-09-11-2019-07-54-36"
        account: "ex: prod"
    Returns: null
    """
    cur_sql, conn_sql = sql_connect()
    try:
        query = "SELECT count(*) FROM dbainfra.dbo.monthly_snapshots  WHERE arn = '{}'".format(arn)
        cur_sql.execute(query)
        result = cur_sql.fetchone()
        if result:
            if result[0] == 0:
                query = "insert into " \
                        "dbainfra.dbo.monthly_snapshots(s_c_time,pod,region,account,snapshotname,arn,deleted) " \
                        "values ({},'{}','{}','{}','{}','{}','{}')".format('GETDATE()',pod,region,account,snapshotname,arn,0)
                cur_sql.execute(query)
            else:
                logger.info("Entry for snapshot {} already exists".format(snapshotname))
        conn_sql.commit()
    except Exception as ex:
        logger.error("Error while making an entry for snapshot : {}".format(str(ex)))
        # alert_description = "Error while taking rds monthly backup, not able to connect dbmonitor1b"
        # raise_radar_alert(alert_description)
        exit(1)


def get_prod_instances():
    """
    Get the list of production instances with region information
    Returns: dictionary of instances with region and pod. ex: prod_instances['balydbpg1a']=['us-east-1','baly']
    """
    try:
        prod_instances = []
        arcboto.install()
        client = boto3.client('ec2')
        regions = [region['RegionName'] for region in client.describe_regions()['Regions']]
        for region in regions:
            regionclient = boto3.client('rds', region_name=region)
            instances = regionclient.describe_db_instances()['DBInstances']
            if instances:
                for instance in instances:
                    instancename = instance['DBInstanceIdentifier']
                    query = "select lower(pod) as pod from dbainfra.dbo.database_server_inventory " \
                            "where ServerType='PGDB' and IsActive=1 and " \
                            "Monitor='Yes' and lower(Env) = 'prod' and lower(Alias)='{}'".format(instancename)
                    cur_sql.execute(query)
                    for row in cur_sql.fetchall():
                        if row is not None:
                            # creating a temporary variable to store the instance information
                            prod_instance_temp = []
                            prod_instance_temp.append(instancename)
                            prod_instance_temp.append(region)
                            prod_instance_temp.append(row.pod)
                            prod_instances.append(prod_instance_temp)
        logger.info("Production instance's to be backup are : {}".format(prod_instances))
        return prod_instances
    except Exception as ex:
        logger.error("Error while getting list of production instances : {}".format(str(ex)))
        alert_description = "Error while taking rds monthly backup, not able to get list of production instances"
        raise_radar_alert(alert_description)
        exit(1)


def main():
    # Get the user inputs
    args = parse_arguments()
    # configure logging
    set_logging()
    process_count    = 0
    failed_instances = []
    # list of current running processes
    current_running  = {}

    instance_action = ''
    if args.create:
        instance_action = 'create'

    if instance_action == 'create':
        """
        Creating the SQL connection here because we need to run statements for multiple times. 
        So making this as global variable.
        """
        global cur_sql, conn_sql
        cur_sql, conn_sql = sql_connect()
        # print logfile information
        print("Please check the logfile in case of any error : {}".format(logfile))
        # Get the list of prod instances
        prod_instances = get_prod_instances()
        # total instances to backup
        total_instances = len(prod_instances)
        logger.info("Starting backup of production instances, total are : {}".format(total_instances))
        while total_instances > 0:
            while process_count < min(MAX_PROCESSES, total_instances):
                """
                Here I am getting list of prod instances in a list of lists called prod_instances.
                I pop one of the instance from that and create process to take the backup of 
                that instance, add the process to dict called "current_running". I will wait 
                until the processes in current_running is complete. I will pop the instances 
                until it reaches the maximum process I can start or if the number of instances 
                in the dictionary is less than the allocated parallel processes (MAX_PROCESSES).
                """
                temp     = prod_instances.pop() # get the instance into temp variable
                instance = temp[0]
                region   = temp[1]
                pod      = temp[2]
                process  = Process(target=create_snapshot, args=(pod, region, instance,))
                process.start()
                process_count += 1
                current_running[instance] = process
            # reset the variable back to zero, to start the processes again
            process_count   = 0
            total_instances = total_instances - min(MAX_PROCESSES, total_instances)
            # join all the processes, inst is a temporary loop variable to hold the instance name
            for inst in current_running.keys():
                current_running_proc = current_running[inst]
                current_running_proc.join()
                # check the return code of the process
                if current_running_proc.exitcode != 0:
                    logger.error("process with id {} taking backup of instance {} "
                                 "is failed".format(current_running_proc.pid, inst))
                    failed_instances.append(inst)
    if len(failed_instances) > 0:
        alert_description = "An error was encountered while generating a " \
                            "snapshot for one or more instances {} ".format(failed_instances)
        raise_radar_alert(alert_description)
    # closing the database connection
    conn_sql.close()


if __name__ == "__main__":
    main()
