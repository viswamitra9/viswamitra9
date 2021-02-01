#!/usr/bin/env python2

"""
Script to create snapshot of golden instance in us-east-1
or from the given source region/account

@author: oguri
"""

import argparse
import logging
import sys
from datetime import datetime
import time
import arcesium.infra.boto as arcboto
import boto3
import pyodbc
from botocore.exceptions import ClientError
from botocore.config import Config
from retrying import retry

config = Config(
    retries=dict(
        max_attempts=20
    )
)

logger = logging.getLogger('prod:pgsql-golden-snapshot')


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


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def sql_connect():
    # create a SQL connection to DBMONITOR1B database and return the connection and cursor object
    try:
        conn_sql_dest = pyodbc.connect('DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
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
    createordelete.add_argument("--create", action='store_true', help="To create snapshot")
    createordelete.add_argument("--delete", action='store_true', help="To delete snapshot")

    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the snapshot creation")
    parser.add_argument("--source-instance", default="goldendb1", dest="source_instance",
                        help="Give the source instance name, whose clone needs to be created, example : goldendb1",
                        required=False)
    parser.add_argument('--source-account', default='prod', required=False)
    parser.add_argument('--source-region', default='us-east-1', required=False)
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)
    return parser.parse_args()


snapshot_sleep_time = 60


def get_rds_ec2_kms_clients(account, region):
    try:
        arcboto.install()
        session = boto3.session.Session(profile_name='{}/dba'.format(account))
        rds = session.client('rds', region_name='{}'.format(region), config=config)
        ec2 = session.client('ec2', region_name='{}'.format(region), config=config)
        kms = session.client('kms', region_name='{}'.format(region), config=config)
        return rds, ec2, kms
    except ClientError as e:
        logger.error('exception while fetching boto3 connection', e.response['Error']['Code'])
        sys.exit(1)


def wait_snapshot_available(rds, snapshotname,action):
    if action == 'create':
        try:
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
            while response['DBClusterSnapshots'][0]['Status'] != 'available':
                logger.info("still waiting for snapshot to complete")
                time.sleep(snapshot_sleep_time)
                response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
            return response['DBClusterSnapshots'][0]['DBClusterSnapshotArn']
        except ClientError as e:
            sys.exit(e)
    if action == 'delete':
        try:
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
            while response['DBClusterSnapshots'][0]['Status'] != 'deleting':
                logger.info("deleting the snapshot")
                time.sleep(snapshot_sleep_time)
                response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterSnapshotNotFoundFault':
                logger.warning("the snapshot deleted")
                return 0
            else:
                logger.error("error while deleting the snapshot {}".format(e))
                sys.exit(1)


def create_source_snapshot(pod,source_account, source_region, snapshotname, source_cluster,dry_run):
    # Create snapshot for PostgreSQL golden instance present in production (us-east-1)
    if dry_run:
        logger.info(dry_run + " Creating Snapshot")
        logger.info(dry_run + " rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=" + snapshotname +
                    "DBClusterIdentifier=" + source_cluster + ")")
        make_entry_for_snapshot(region=source_region, account=source_account, snapshotname=snapshotname,pod=pod,
                                arn='snapshot_arn',dry_run=dry_run)
        logger.info(dry_run + "Snapshot Creation completed successfully".format(snapshotname))
        sys.exit(0)
    else:
        rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
        try:
            rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshotname, DBClusterIdentifier=source_cluster)
            snapshot_arn = wait_snapshot_available(rds, snapshotname,'create')
            make_entry_for_snapshot(region=source_region, account=source_account, snapshotname=snapshotname,pod=pod,
                                arn=snapshot_arn,dry_run=dry_run)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterSnapshotAlreadyExistsFault':
                logger.info("The snapshot already exists")
                snapshot_arn = wait_snapshot_available(rds, snapshotname,'create')
                make_entry_for_snapshot(region=source_region, account=source_account, snapshotname=snapshotname,pod=pod,
                                    arn=snapshot_arn,dry_run=dry_run)
            else:
                logger.error("failure while taking the snapshot of source instance {}".format(e))
                sys.exit(1)


def make_entry_for_snapshot(pod,region, account, snapshotname,arn,dry_run):
    if dry_run:
        logger.info(dry_run + " insert into dbainfra.dbo.pod_creation_snapshots(s_c_time,pod,region,account,snapshotname,arn,deleted) " \
            "values" \
            "(GETDATE(),'" + str(pod) + \
            "','" + str(region) + "','" + str(account) + "','" + str(snapshotname) + "','" + str(arn) + "',0)")
    else:
        cur_sql_dest, conn_sql_dest = sql_connect()
        query = "insert into dbainfra.dbo.pod_creation_snapshots(s_c_time,pod,region,account,snapshotname,arn,deleted) " \
            "values" \
            "(GETDATE(),'" + str(pod) + \
            "','" + str(region) + "','" + str(account) + "','" + str(snapshotname) + "','" + str(arn) + "',0)"
        cur_sql_dest.execute(query)
        conn_sql_dest.commit()


def validate_input(source_region, source_account, source_instance,dry_run):
    # function to validate the input
    rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
    # Validating source instance (ex : golden)
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=source_instance)
        if response['DBInstances'][0]['Engine'] != 'aurora-postgresql':
            logger.error(dry_run + 'The source instance : %s, you entered is not Aurora instance', source_instance)
            return 1
        if response['DBInstances'][0]['DBInstanceStatus'] != 'available':
            logger.error(
                dry_run + 'The source instance : %s is not in available state,'
                          'run the script after the instance is available',
                source_instance)
            return 1
        return 0
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            logger.error(dry_run + "The source instance : %s does not exists", source_instance)
            return 1
        else:
            logger.error(dry_run + "There is an error in finding the source instance : %s details :", source_instance,
                         e.response['Error']['Code'])
            return 1


def main():
    # Get the user inputs
    args                        =       parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    source_instance             =       args.source_instance
    dryrun                      =       args.dry_run
    instance_action             =       ''
    source_account              =       args.source_account
    source_region               =       args.source_region
    pod                         =       args.pod

    if args.create:
        instance_action         =       'create'
    if args.delete:
        instance_action         =       'delete'

    if dryrun:
        dry_run                 =       'dry run: '
    else:
        dry_run                 =       ''

    rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
    response = rds.describe_db_instances(DBInstanceIdentifier=source_instance)
    source_cluster = response['DBInstances'][0]['DBClusterIdentifier']

    if instance_action == 'create':
        # Create the snapshot for golden instance and make an entry for it in inventory
        date_t = format(datetime.now().strftime("%d-%m-%Y-%H-%M-%S"))
        snapshotname = source_instance + '-' + date_t
        ret_code = validate_input(source_region=source_region, source_account=source_account,
                                    source_instance=source_instance, dry_run=dry_run)
        if ret_code == 1:
            logger.error("Validation of input is failed")
            sys.exit(1)
        create_source_snapshot(pod=pod, source_account=source_account, source_region=source_region,
                               snapshotname=snapshotname, source_cluster=source_cluster,dry_run=dry_run)
        logger.info(dry_run+"snapshot {} creation completed successfully".format(snapshotname))

    if instance_action == 'delete':
        if dry_run == 'dry run: ':
            logger.info(dry_run + " Starting Delete Snapshot Process")
            logger.info(dry_run + " select TOP 1 snapshotname from dbo.pod_creation_snapshots where pod='"+pod+"' and " \
                "region='"+source_region+"' and account='"+source_account+"' and deleted != 1 order by s_c_time desc")
            logger.info(dry_run + " rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=str(row.snapshotname))")
            logger.info(dry_run + " Updating Deletion in inventory")
            logger.info(dry_run + " update dbo.pod_creation_snapshots set deleted = 1 where snapshotname=(row.snapshotname) " \
                "account='"+source_account+"' region='"+source_region+"' and pod='+"+pod+"'")
            logger.info(dry_run + " Snapshot deleted successfully")
        else:
            rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
            query = "select TOP 1 snapshotname from dbo.pod_creation_snapshots where pod='"+pod+"' and " \
                "region='"+source_region+"' and account='"+source_account+"' and deleted != 1 order by s_c_time desc"
            cur_sql_dest, conn_sql_dest = sql_connect()
            rows = cur_sql_dest.execute(query)
            row = rows.fetchone()
            snapshotname = row.snapshotname
            try:
                rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=str(row.snapshotname))
                wait_snapshot_available(rds, snapshotname, 'delete')
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBClusterSnapshotNotFoundFault':
                    logger.warning("the snapshot was already deleted")
                else:
                    logger.error("error while deleting the snapshot {}".format(e))
                    sys.exit(1)
            query = "update dbo.pod_creation_snapshots set deleted = 1 where snapshotname='"+str(row.snapshotname)+"' and " \
                    "account='"+source_account+"'and region='"+source_region+"' and pod='"+pod+"'"
            cur_sql_dest.execute(query)
            conn_sql_dest.commit()
            logger.info("snapshot {} deleted successfully".format(row.snapshotname))
            conn_sql_dest.close()


if __name__ == "__main__":
    main()
