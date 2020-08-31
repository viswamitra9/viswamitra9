#!/usr/bin/env python2
# Author      : Srinivas
# Job         : rds_delete_expired_prod_snapshots
# Description : this job is to delete the expired production snapshots which are older than client given retention period

import logging
import argparse
from botocore.exceptions import ClientError
from botocore.config import Config
from datetime import datetime

config = Config(
    retries=dict(
        max_attempts=20
    )
)
from arcesium.radar.client import SendAlertRequest
from arcesium.radar.client import RadarService
import sys
sys.path.append('/g/dba/rds/')
import pod_automation_util

SLEEP_TIME  = 60

logger  = logging.getLogger('pgsql-snapshot-cleanup')
logfile = '/g/dba/logs/dbbackup/delete_expired_snapshots_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))

print("please check the logfile {} for more information".format(logfile))


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


def raise_radar_alert(alert_description):
    request = SendAlertRequest()
    request.alert_source      = 'dba'
    request.alert_key         = 'PostgreSQL snapshot'
    request.alert_summary     = 'PostgreSQL snapshot for production instances'
    request.alert_class       = 'PAGE'
    request.alert_description = alert_description + " please check log file {}".format(logfile)
    request.alert_severity    = 'CRITICAL'
    request.alertKB           = 'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots'
    service = RadarService()
    try:
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def wait_snapshot_deleted(rds, snapshotname):
    """
    snapshot deletion is async operation, wait for snapshot deletion to complete.
    Args:
        rds: session to boto3
        snapshotname: name of snapshot
    Returns: return 1 if failed 0 for success
    """
    try:
        response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
        while response['DBClusterSnapshots'][0]['Status'] is not None:
            response = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshotname)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBClusterSnapshotNotFoundFault':
            return 0
        else:
            logger.error("Error while creating snapshot {} , error : {}".format(snapshotname,e))
            return 1


def delete_expired_snapshots():
    """
    Get the list of snapshots which are expired using dbainfra.dbo.monthly_snapshots,
    dbainfra.dbo.pg_monthly_snapshot_retention and delete them.
    Returns: none
    """
    failed_snapshots        = []
    alert_description       = ''
    raise_alert             = 0
    pods_without_retention  = []

    query = "select region,account,snapshotname from dbainfra.dbo.monthly_snapshots where deleted=0 and " \
            "DATEDIFF(day,s_c_time,current_timestamp) > (select retention_in_days " \
            "from dbainfra.dbo.pg_monthly_snapshot_retention " \
            "where dbainfra.dbo.monthly_snapshots.pod = dbainfra.dbo.pg_monthly_snapshot_retention.pod " \
            "and retention_in_days!=-1)"
    cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchall()
    if result is not None:
        for snapshot in result:
            region       = snapshot[0]
            account      = snapshot[1]
            snapshotname = snapshot[2]
            client, ec2, kms, iam = pod_automation_util.get_rds_ec2_kms_clients(account, region)
            try:
                client.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshotname)
                return_code = wait_snapshot_deleted(client, snapshotname)
                if return_code != 0:
                    failed_snapshots.append(snapshotname)
                else:
                    logger.info("snapshot {} : has been deleted successfully \n".format(snapshotname))
                    cur_sql_dest.execute("update dbainfra.dbo.monthly_snapshots set deleted=1 "
                                         "where snapshotname='{}'".format(snapshotname))
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBClusterSnapshotNotFoundFault':
                    logger.info("Snapshot {} was already deleted".format(snapshotname))
                    cur_sql_dest.execute("update dbainfra.dbo.monthly_snapshots set deleted=1 "
                                         "where snapshotname='{}'".format(snapshotname))
                elif e.response['Error']['Code'] == 'InvalidDBClusterSnapshotStateFault':
                    logger.error("failed to delete the snapshot {} with error Invalid snapshots state")
                    failed_snapshots.append(snapshotname)
                else:
                    logger.error("failed to delete the snapshot {} with error {}".format(snapshotname, str(e)))
                    failed_snapshots.append(snapshotname)

        cur_sql_dest.execute("select distinct pod from dbainfra.dbo.monthly_snapshots as ms where not exists "
                             "(select pod from dbainfra.dbo.pg_monthly_snapshot_retention mr where ms.pod=mr.pod)")
        result = cur_sql_dest.fetchall()
        if result is not None:
            for i in result:
                pods_without_retention.append(str(i[0]))
            alert_description += "Some of the pods {} are not configured with retention. " \
                                 "Please refer http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots \n".format(pods_without_retention)
            raise_alert = 1

        if len(failed_snapshots) > 0:
            alert_description += "Error while deleting some of snapshots {} \n \n".format(failed_snapshots)
            raise_alert = 1


        #if raise_alert == 1:
        #    raise_radar_alert(alert_description)

        print(alert_description)

def parse_arguments():
    """
    Parse input argements
    """
    # take input arguments and parse
    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--delete", action='store_true', help="To create snapshot")
    return parser.parse_args()


def main():
    args = parse_arguments()
    set_logging()
    instance_action = ''
    if args.delete:
        instance_action = 'delete'

    if instance_action == 'delete':
        logger.info("Started deletion of expired snapshots")
        delete_expired_snapshots()


if __name__ == "__main__":
    main()
