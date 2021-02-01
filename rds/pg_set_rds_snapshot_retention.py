#!/usr/bin/env python2
"""
Author        : oguri
jobexec Job   :
Description  : This script is to maintain the DSC for RDS snapshot retention period.
"""
import logging
import sys
from datetime import datetime

sys.path.append('/g/dba/rds/')
import pod_automation_util
# packages for radar alert
from arcesium.radar.client import SendAlertRequest
from arcesium.radar.client import RadarService


logger = logging.getLogger('pgsql-set-snapshot-retention')


def setup_logging(logfile):
    """
    Args:
        logfile: logfile where to write the information or errors
    Returns:
        configure the error logging file to write the errors or information
    """
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
    ch.setFormatter(logging.Formatter('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    sh.setFormatter(logging.Formatter('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)
    return logger


from retrying import retry
@retry(stop_max_attempt_number=5, wait_fixed=1000)
def set_cluster_retention(rds, clusteridentifier, retention):
    retry_count = 0
    rds.modify_db_cluster(DBClusterIdentifier=clusteridentifier, BackupRetentionPeriod=retention, ApplyImmediately=True)
    cluster_retention = rds.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['BackupRetentionPeriod']
    if cluster_retention != retention:
        logger.warning("Checking status again : {}".format(retry_count+1))
        raise


def raise_radar_alert(alert_description):
    """
    PURPOSE:
        raise a radar alert
    Args:
        alert_description:
    Returns:
    """
    request = SendAlertRequest()
    request.alert_source = 'dba'
    request.alert_class = 'Page'
    request.alert_severity = 'CRITICAL'
    request.alert_key = 'Set cluster snapshot retention'
    request.alert_summary = "Failed to set cluster snapshot retention"
    request.alert_description = alert_description + " Please check the documentation {} for more information.".format('http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots')
    request.alertKB = 'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots'
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def main():
    try:
        # Enable logging
        logfile = '/g/dba/logs/postgresql/rds_set_snapshot_retention_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        global logger
        logger = setup_logging(logfile=logfile)
        cur_sql, conn_sql = pod_automation_util.sql_connect()
        # Get list of DEV and QA instances, also get the list of uat instances with refresh configured
        # set the cluster snapshot retention period to 1 day
        cur_sql.execute("select lower(Alias) as Instance from dbainfra.dbo.database_server_inventory"
                        " where IsActive=1 and lower(Monitor)='yes' and ServerType='PGDB' and lower(Env) in ('dev','qa')"
                        " union select lower(di.Alias) as Instance,lower(di.Env) as env "
                        "from dbainfra.dbo.database_server_inventory di join dbainfra.dbo.refresh_server_inventory ri on"
                        " (lower(di.Alias)=lower(ri.destinationservername)) where di.IsActive=1 and"
                        " lower(di.Monitor)='yes' and di.ServerType='PGDB' and lower(di.Env) in ('uat')")
        result = cur_sql.fetchall()
        for instance in result:
            instance_name      = instance[0]
            account, region    = pod_automation_util.get_account_region_of_instnace(instance_name)
            rds, ec2, kms, iam = pod_automation_util.get_rds_ec2_kms_clients(account, region)
            instance_details   = pod_automation_util.get_instance_details(rds, instance_name)
            cluster_identifier = instance_details['DBInstances'][0]['DBClusterIdentifier']
            cluster_details    = pod_automation_util.get_cluster_details(rds,cluster_identifier)
            retention          = cluster_details['DBClusters'][0]['BackupRetentionPeriod']
            if retention > 1:
                logger.info("Configuring retention for instance {}".format(instance_name))
                set_cluster_retention(rds, cluster_identifier,1)
                logger.info("Successfully configured retention for instance {}".format(instance_name))
    except Exception as e:
        global logger
        alert_description   = "Failed to set cluster snapshot retention period"
        logger.error("Failed to set the cluster retention period with error {}".format(str(e)))
        raise_radar_alert(alert_description)


if __name__ == "__main__":
    main()