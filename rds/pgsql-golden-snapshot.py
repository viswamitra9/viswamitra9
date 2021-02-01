#!/usr/bin/env python2

"""
Script to copy snapshot of golden instance in us-east-1
to destination region/account

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

config = Config(
    retries=dict(
        max_attempts=20
    )
)

logger = logging.getLogger('pgsql-golden-snapshot')


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


def parse_arguments():
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create snapshot")
    createordelete.add_argument("--delete", action='store_true', help="To delete snapshot")

    parser.add_argument('--account-name', required=True)
    parser.add_argument('--region', required=True)

    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the snapshot creation")
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


def wait_snapshot_available(rds, snapshotname):
    try:
        response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        while response['DBClusterSnapshots'][0]['Status'] != 'available':
            logger.info("still waiting for snapshot to complete")
            time.sleep(snapshot_sleep_time)
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        return response['DBClusterSnapshots'][0]['DBClusterSnapshotArn']
    except ClientError as e:
        sys.exit(e)


def make_entry_for_snapshot(pod, region, account, snapshotname, arn):
    cur_sql_dest, conn_sql_dest = sql_connect()
    query = "insert into dbainfra.dbo.pod_creation_snapshots(s_c_time,pod,region,account,snapshotname,arn,deleted) " \
            "values" \
            "(GETDATE(),'" + str(pod) + \
            "','" + str(region) + "','" + str(account) + "','" + str(snapshotname) + "','" + str(arn) + "',0)"
    cur_sql_dest.execute(query)
    conn_sql_dest.commit()


def get_latest_snapshot(source_account, source_region,pod):
    # rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
    query = "select TOP 1 snapshotname,arn from dbainfra.dbo.pod_creation_snapshots where pod='"+pod+"' and " \
            "region='"+source_region+"' and account='"+source_account+"' and deleted != 1 order by s_c_time desc"
    cur_sql_dest, conn_sql_dest = sql_connect()
    rows = cur_sql_dest.execute(query)
    if rows:
        row = rows.fetchone()
        conn_sql_dest.close()
        return row.snapshotname,row.arn
    else:
        logger.error("There is no latest golden snapshot")
        sys.exit(1)


def share_snapshot(source_account, source_region, snapshotname, account):
    try:
        account_id = get_account_id(account)
        rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
        rds.modify_db_cluster_snapshot_attribute(AttributeName='restore', DBClusterSnapshotIdentifier=snapshotname,
                                                 ValuesToAdd=[str(account_id)])
    except ClientError as e:
        logger.error("failure while sharing the snapshot {}".format(e))
        sys.exit(1)


def get_account_id(account):
    try:
        dev = boto3.session.Session(profile_name='{}/dba'.format(account))
        return dev.client('sts').get_caller_identity().get('Account')
    except ClientError as e:
        logger.error("failure while getting account id {}".format(e))
        sys.exit(1)


def copy_snapshot(dest_region, dest_account, snapshot_arn, source_region, kms_key, snapshotname,pod):
    # Copy snapshot to destination region
    rds, ec2, kms = get_rds_ec2_kms_clients(dest_account, dest_region)
    try:
        rds.copy_db_cluster_snapshot(SourceDBClusterSnapshotIdentifier=snapshot_arn, KmsKeyId=kms_key,
                                     TargetDBClusterSnapshotIdentifier=snapshotname, SourceRegion=source_region)
        snapshot_arn = wait_snapshot_available(rds, snapshotname)
        make_entry_for_snapshot(pod, dest_region, dest_account, snapshotname, snapshot_arn)
        return snapshot_arn
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterSnapshotAlreadyExistsFault':
            snapshot_arn = wait_snapshot_available(rds, snapshotname)
            make_entry_for_snapshot(pod, dest_region, dest_account, snapshotname, snapshot_arn)
            return snapshot_arn
        else:
            logger.error("failure while copying the snapshot {}".format(e))
            sys.exit(1)


def delete_snapshot(region, account, snapshotname):
    rds, ec2, kms = get_rds_ec2_kms_clients(account, region)
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshotname)
        response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        while response['DBClusterSnapshots'][0]['Status'] != 'deleting':
            logger.info("deleting the snapshot")
            time.sleep(snapshot_sleep_time)
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterSnapshotNotFoundFault':
            logger.warning("the snapshot deleted")
            query = "update dbo.pod_creation_snapshots set deleted = 1 where snapshotname='"+str(snapshotname)+"' and" \
                                    " account='" + account + "' and  region='" + region + "'"
            cur_sql_dest, conn_sql_dest = sql_connect()
            cur_sql_dest.execute(query)
            conn_sql_dest.commit()
            return 0
        else:
            logger.error("error while deleting the snapshot {}".format(e))
            sys.exit(1)


def create_copy_snapshot_destination(source_region, source_account, destination_region, destination_account,
                                     snapshot_arn, default_kms_key, kms_key_id, snapshotname,pod):
    logger.info("Sharing the snapshot {} with {}".format(snapshotname, destination_account))
    share_snapshot(source_account, source_region, snapshotname, destination_account)
    logger.info(
        "Copying the snapshot {} to account {} in region {}".format(snapshotname, destination_account, source_region))
    snapshot_arn = copy_snapshot(source_region, destination_account, snapshot_arn, source_region, default_kms_key,
                                 snapshotname,pod)
    logger.info("copying the snapshot {} to {} region".format(snapshotname, destination_region))
    copy_snapshot(destination_region, destination_account, snapshot_arn, source_region, kms_key_id, snapshotname,pod)


def main():
    # Get the user inputs
    args                                = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    pod                                 = args.pod
    dryrun                              = args.dry_run
    instance_action     = ''
    destination_region  = args.region
    destination_account = args.account_name
    source_account              = args.source_account
    source_region               = args.source_region

    if args.create:
        instance_action = 'create'
    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '
    else:
        dry_run = ''

    kms_key_id = 'alias/pod/{}'.format(pod)
    default_kms_key = 'alias/aws/rds'

    if instance_action == 'create':
        # This method is used to copy the snapshot to destination account:region
        snapshotname,snapshot_arn = get_latest_snapshot(source_account=source_account,source_region=source_region,
                                                        pod=pod)
        create_copy_snapshot_destination(source_region, source_account, destination_region,
                                     destination_account,snapshot_arn, default_kms_key, kms_key_id, snapshotname,pod)
        logger.info("Snapshot copied successfully to region: {} account: {}".format(destination_region,
                                                                                    destination_account))

    if instance_action == 'delete':
        query = "select account,region,snapshotname from dbainfra.dbo.pod_creation_snapshots where account!='"+source_account + "' and pod = '"+pod+"' and deleted != 1"
        cur_sql_dest, conn_sql_dest = sql_connect()
        cur_sql_dest.execute(query)
        result = cur_sql_dest.fetchall()
        if result:
            for row in result:
                #delete_snapshot(region, account, snapshotname):
                delete_snapshot(str(row.region),str(row.account),str(row.snapshotname))
            logger.info("All intermediate snapshots are deleted")
        else:
            logger.warning("There are no snapshots to delete")


if __name__ == "__main__":
    main()
