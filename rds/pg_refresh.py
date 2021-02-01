#!/usr/local/bin/python
import sys
sys.path.append('/g/dba/oguri/dba/rds/')
sys.path.append('/g/dba/rds/')
import pod_automation_util
import logging
import argparse
import time
from datetime import datetime, timedelta
import subprocess
from dbrefreshutil import DBRefreshUtil

sys.path.append('/g/dba/pythonutilities/')
from pythonutils import PythonUtils

# packages for radar alert
from arcesium.radar.client import SendAlertRequest
from arcesium.radar.client import RadarService

logger = logging.getLogger()

from botocore.config import Config

config = Config(
    retries=dict(
        max_attempts=15
    )
)


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True,
                                     description=
                                     'example : sudo -u sqlexec python pg_refresh.py -s balydbpg1a -d balyuatdbpg1a')
    parser.add_argument("-s", "--source-instance",
                        dest="source_instance",
                        help="instance identifier for the aurora postgres instance that should be cloned",
                        required=True)
    parser.add_argument('-d', '--destination-instance',
                        dest='destination_instance', default='none',
                        help='instance identifier for the new aurora postgres clone', required=True)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    return parser.parse_args()


def raise_radar_alert(source_instance, destination_instance, alert_description):
    """
    PURPOSE:
        raise a radar alert
    Args:
        source_instance:
        destination_instance:
        alert_description:
    Returns:
    """
    request = SendAlertRequest()
    request.alert_source = 'dba'
    request.alert_class = 'Page'
    request.alert_severity = 'CRITICAL'
    request.alert_key = 'PostgreSQL Refresh'
    request.alert_summary = "PostgreSQL Refresh from " + source_instance + " to " + destination_instance
    request.alert_description = alert_description + " Please check the documentation for more " \
                                                    "information.".format('http://wiki.ia55.net/pages/'
                                                                          'viewpage.action?spaceKey=TECHDOCS&title=Amazon+Aurora+PostgreSQL+Refresh')
    request.alertKB = 'http://wiki.ia55.net/pages/viewpage.action?spaceKey=TECHDOCS&title=Amazon+Aurora+PostgreSQL+Refresh'

    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))


def update_current_running_status(sourceservername, destinationservername, statuscode, comments):
    query = "insert into dbainfra.dbo.refresh_current_running_status values('" + sourceservername + "','" + \
            destinationservername + "', getdate() ,'" + str(statuscode) + "','" + comments + "')"
    cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


def main():
    try:
        # If the destination pod is in pods then we need to do additional step (reset passwords for users not in vault)
        pods = ['terra', 'mars', 'phobos']
        # pdb.set_trace()
        args = parse_arguments()
        source_instance = args.source_instance
        destination_instance = args.destination_instance
        # Enable logging
        logfile = '/g/dba/logs/dbrefresh/pgdbrefresh_{}_{}_{}.log'.format(source_instance, destination_instance,
                                                                          datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', filename=logfile,
                            level=logging.INFO)
        ## Get the account , region of source instance and assume the same for destination instance
        account, region = pod_automation_util.get_account_region_of_instnace(args.source_instance)
        client, ec2, kms, iam = pod_automation_util.get_rds_ec2_kms_clients(account, region)
        source_response = pod_automation_util.get_instance_details(client, source_instance)
        source_endpoint = source_response['DBInstances'][0]['Endpoint']['Address']
        source_cluster = source_response['DBInstances'][0]['DBClusterIdentifier']
        destination_cluster_clone = destination_instance + '-clone-cluster'
        destination_instance_clone = destination_instance + '-clone'
        destination_response = pod_automation_util.get_instance_details(client, destination_instance)
        destination_endpoint = destination_response['DBInstances'][0]['Endpoint']['Address']
        destination_preferred_mwindow = destination_response['DBInstances'][0]['PreferredMaintenanceWindow']
        destination_kms_key = destination_response['DBInstances'][0]['KmsKeyId']
        destination_subnet_group = destination_response['DBInstances'][0]['DBSubnetGroup']['DBSubnetGroupName']
        # destination_subnet_group = 'ia55-db-customer'
        destination_dbinstance_class = destination_response['DBInstances'][0]['DBInstanceClass']
        destination_dbpgroup = destination_response['DBInstances'][0]['DBParameterGroups'][0]['DBParameterGroupName']
        destination_cluster = destination_response['DBInstances'][0]['DBClusterIdentifier']
        destination_vpc_sec_groups = []
        for sec in destination_response['DBInstances'][0]['VpcSecurityGroups']:
            destination_vpc_sec_groups.append(sec['VpcSecurityGroupId'])
        destination_tags = \
            client.list_tags_for_resource(ResourceName=destination_response['DBInstances'][0]['DBInstanceArn'])[
                'TagList']
        destination_cluster_response = pod_automation_util.get_cluster_details(client, destination_cluster)
        destination_clusterpgroup = destination_cluster_response['DBClusters'][0]['DBClusterParameterGroup']
        dbrefreshutil = DBRefreshUtil(logger=None)

        ## Variables for radar alerts
        # setup_logging(args.log_level, args.log_file)
    except Exception as e:
        source_instance = args.source_instance
        logfile = '/g/dba/logs/dbrefresh/pgdbrefresh_{}_{}_{}.log'.format(source_instance, destination_instance,
                                                                          datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))
        dbrefreshutil = DBRefreshUtil(logger=None)
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Error while checking instances. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while checking instances, check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)

    # Create the required folders
    BACKUP_DIR = '/g/dba/importexport/postgresqlbackups'
    command = "mkdir -p {}".format(BACKUP_DIR)
    pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    pipes.communicate()
    if pipes.returncode == 0:
        logging.info("Backup directory {} created successfully".format(BACKUP_DIR))
    else:
        status_message = "Error while creating required folder for backups source : {} destination : {}".format(
            args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        logging.error("Error while creating the backup directory {}".format(BACKUP_DIR))
        sys.exit(1)

    # Checking the possibility of refresh
    try:
        update_current_running_status(source_instance, destination_instance, statuscode='1',
                                      comments='Checking the possibility of refresh')
        env, pod = pod_automation_util.check_dest_not_prod_get_pod(destination_instance)
        if env == 'prod':
            logging.error("Destination instance should not be production %s", destination_instance)
            status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                             "Destination instance should not be production. \n" \
                             "Please check the attached log file for further details" % (
                             source_instance, destination_instance)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            update_current_running_status(source_instance, destination_instance, statuscode=11,
                                          comments='Destination instance should not be production')
            sys.exit(1)

        bkp_p = pod_automation_util.check_refresh_possibility(destination_instance)
        if bkp_p == 1:
            logging.error("Backup is not scheduled for this instance %s", destination_instance)
            status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                             "Refresh is not scheduled for this instance. \n" \
                             "Please check the attached log file for further details" % (
                             source_instance, destination_instance)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            update_current_running_status(source_instance, destination_instance, statuscode=11,
                                          comments='Refresh is not scheduled for this instance')
            sys.exit(1)
    except Exception as e:
        logging.error(e)

    # Taking backup of uat privileges
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=2,
                                      comments='Refresh is possible.Taking backup of uat privileges')
        logging.info("Taking backup of uat privileges and users")
        grant_queries = pod_automation_util.backup_privileges(destination_endpoint)
        # taking backup of uat users
        uat_only_users = pod_automation_util.get_users(destination_endpoint)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: Refresh is possible. " \
                         "Taken backup of uat privileges and users. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        update_current_running_status(source_instance, destination_instance, statuscode=22,
                                      comments='Taken backup of uat privileges and users')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while taking backup of privilages. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while taking backup of privilages and users, check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # taking backup of excluded and uat only databases
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=3,
                                      comments='Taking backup of exclude and uat only databases')
        pod_automation_util.backup_databases_excluded_from_refresh(source_endpoint, destination_endpoint)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\n" \
                         "Status: Taken backup of uat only and excluded databases. \n" \
                         "Please check the attached log file for further details" % (source_instance,
                                                                                     destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        update_current_running_status(source_instance, destination_instance, statuscode=33,
                                      comments='Taken backup of exclude and uat only databases')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while taking backup of uat only databases. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while taking backup of excluded databases , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # Starting clone creation for production cluster
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=4,
                                      comments='Starting clone creation for production cluster')
        logging.info("starting cluster clone creation")
        status_message = "Refresh environment\n      Source: %s\n      " \
                         "Destination: %s\nStatus: Taking clone of source cluster. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        pod_automation_util.create_cluster(client, destination_cluster_clone, source_cluster, destination_subnet_group,
                                           destination_vpc_sec_groups, destination_kms_key,
                                           destination_clusterpgroup)
        update_current_running_status(source_instance, destination_instance, statuscode=44,
                                      comments='Clone creation for production cluster completed')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while creating clone of production cluster. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while creating clone of production cluster , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # Starting clone creation for production instance
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=5,
                                      comments='Starting clone creation for production instance')
        logging.info("starting instance clone creation")
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      Destination: %s\n" \
                         "Status: Taking clone of source instance. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        response = iam.get_role(RoleName='rds-monitoring-role')
        MonitoringRoleArn = response['Role']['Arn']
        pod_automation_util.create_instance(client, destination_instance_clone, destination_dbinstance_class,
                                            destination_preferred_mwindow, destination_dbpgroup,
                                            destination_cluster_clone, destination_tags, region, MonitoringRoleArn)
        update_current_running_status(source_instance, destination_instance, statuscode=55,
                                      comments='Clone creation for production instance completed')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while creating clone of instance. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while creating clone of production instance , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # restore uat only users and their privileges
    try:
        destination_clone_response = pod_automation_util.get_instance_details(client, destination_instance_clone)
        destination_clone_endpoint = destination_clone_response['DBInstances'][0]['Endpoint']['Address']
        update_current_running_status(source_instance, destination_instance, statuscode=6,
                                      comments='Restoring uat only users and privileges')
        logging.info("creating uat only users")
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      " \
                         "Destination: %s\n" \
                         "Status: Creating uat only users. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        pod_automation_util.create_users(destination_clone_endpoint, uat_only_users)

        # Resetting passwords of uat instance from vault
        logging.info("resetting passwords for users")
        pass_reset_err = pod_automation_util.reset_passwords(pod, destination_clone_endpoint, destination_instance)
        if pass_reset_err == 1:
            status_message = "There is some issue in resetting password for the instance {}, Please check error log for more details".format(
                args.destination_instance)
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Error while resetting password for the instance {}, Please check error log for more details".format(
                args.destination_instance)
            raise_radar_alert(source_instance, destination_instance, alert_description)
            # sys.exit(1)
        # Restoring privilages
        logging.info("Restoring uat privilages")
        pod_automation_util.restore_privileges(destination_clone_endpoint, grant_queries)

        update_current_running_status(source_instance, destination_instance, statuscode=66,
                                      comments='Restored uat only users and privileges')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while restoring users and privileges. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while restoring uat only users and privileges , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # restore uat only and excluded databases
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=7,
                                      comments='Restoring uat only and excluded databases')
        logging.info("restoring excluded databases and uat only databases")
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      " \
                         "Destination: %s\n" \
                         "Status: Restoring uat only databases. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        pod_automation_util.restore_db_backup_files(client, destination_clone_endpoint, source_instance,
                                                    destination_instance)
        update_current_running_status(source_instance, destination_instance, statuscode=77,
                                      comments='Restored uat only and excluded databases')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while restoring excluded databases. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while restoring uat only and excluded databases, check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)
    logging.info("Restoration of all databases completed successfully")

    # Muting radar alert for the refresh duration
    logging.info("Muting Radar for pod {}".format(pod))
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=5,
                                      comments='Muting radar alert for the refresh duration')
        status_message = "Muting Radar for pod {}".format(pod)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        start_time_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        expiry_time_utc = (datetime.utcnow() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        req_no = pod_automation_util.get_techops_request()
        reason = "DB Refresh" + req_no
        rule_id = pod + '_' + req_no + '_' + datetime.utcnow().strftime("%Y%m%d%H%M%S")
        command = "radar mute-alert mute-pod -p '{}' --expiry-time-utc '{}' --start-time-utc '{}' --reason '{}' --rule-id '{}'".format(
            pod, expiry_time_utc, start_time_utc, reason, rule_id)
        muteradar = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = muteradar.communicate()
        if muteradar.returncode != 0:
            logging.error("Radar muting failed for pod {}".format(pod))
        update_current_running_status(source_instance, destination_instance, statuscode=5,
                                      comments='Muting radar alert for the refresh duration completed')
    except Exception as e:
        logging.info("radar muting failed")
        logging.info(e)
        alert_description = "Radar muting failed. Please investigate. \n %s" % (e)
        raise_radar_alert(source_instance, destination_instance, alert_description)

    # Rename existing destination cluster and instance to -old
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=8,
                                      comments='Renaming existing destination cluster and instance to -old')
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      " \
                         "Destination: %s\n" \
                         "Status: Renaming existing instance and cluster. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        # Renaming instance
        cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
        rows = cur_sql_dest.execute("SELECT * FROM [dbainfra].[dbo].[refresh_desflow_ticket_details]")
        row = rows.fetchone()
        conn_sql_dest.close()
        pod_automation_util.rename_instance(client, destination_instance,
                                            destination_instance + '-' + str(row.archelpnumber))
        logging.info(
            "destination instance " + destination_instance + " renamed successfully to " + destination_instance + '-' + str(
                row.archelpnumber))
        # Renaming cluster
        pod_automation_util.rename_cluster(client, destination_cluster,
                                           destination_cluster + '-' + str(row.archelpnumber))
        logging.info(
            "destination cluster" + destination_cluster + " renamed successfully to " + destination_cluster + '-' + str(
                row.archelpnumber))
        update_current_running_status(source_instance, destination_instance, statuscode=88,
                                      comments='Renamed existing destination cluster and instance to -old')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while renaming the existing instance or cluster to old. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while renaming uat cluster and instance , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    # When you rename a DB instance, the old DNS name that was used by the DB instance is immediately deleted,
    # although it could remain cached for a few minutes. The new DNS name for the renamed DB instance becomes
    # effective in about 10 minutes. The renamed DB instance is not available until the new name becomes effective.

    time.sleep(600)

    # re-name cloned destination instance and cluster
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=9,
                                      comments='Re-naming cloned instance and cluster')
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      " \
                         "Destination: %s\n" \
                         "Status: Renaming cloned instance and cluster to old. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        # Rename cloned instance
        pod_automation_util.rename_instance(client, destination_instance_clone, destination_instance)
        logging.info("instance rename completed successfully from %s to %s", destination_instance_clone,
                     destination_instance)
        # Rename cloned cluster
        pod_automation_util.rename_cluster(client, destination_cluster_clone, destination_cluster)
        logging.info("rename cluster completed successfully from %s to %s", destination_cluster_clone,
                     destination_cluster)
        update_current_running_status(source_instance, destination_instance, statuscode=99,
                                      comments='Re-named cloned destination instance and cluster')
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Refresh is failed, error while renaming the cloned instance or cluster to old. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while renaming cloned cluster and instance , check logfile {}".format(logfile)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    time.sleep(600)

    # Stop the old uat instances
    try:
        update_current_running_status(source_instance, destination_instance, statuscode=10,
                                      comments='Stopping old uat instances')
        status_message = "Refresh environment\n      " \
                         "Source: %s\n      " \
                         "Destination: %s\n" \
                         "Status: Stopping old uat instances. \n" \
                         "Please check the attached log file for further details" % (
                         source_instance, destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        pod_automation_util.stop_cluster(client, destination_cluster + '-' + str(row.archelpnumber))
        logging.info("Stopped the cluster {}".format(destination_cluster + '-' + str(row.archelpnumber)))
        update_current_running_status(source_instance, destination_instance, statuscode=100,
                                      comments='Stopping cluster {} completed'.format(
                                          destination_cluster + '-' + str(row.archelpnumber)))

        ## Making entry for old instances into database for deletion after 1 day
        techops_req = pod_automation_util.get_techops_request().partition('#')[2]
        instancename = destination_instance + '-' + str(techops_req)
        pod_automation_util.make_entry_for_instance(instancename, account, region)
    except Exception as e:
        logging.error(e)
        status_message = "Refresh environment\n      Source: %s\n      Destination: %s\nStatus: " \
                         "Stopping cluster failed, error while stopping cluster. \n" \
                         "Please check the attached log file for further details" % (
                             args.source_instance, args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while stopping cluster {}".format(destination_cluster + "-" + str(row.archelpnumber))
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    ## Test the user passwords after refresh to confirm the refresh is successful
    logging.info("Verifying users passwords by checking from vault")
    retcode = pod_automation_util.verify_users(pod, destination_endpoint, destination_instance)
    # retcode = pod_automation_util.verify_users(account,region,pod,destination_instance)
    if retcode == 1:
        status_message = "Some users passwords are not working in instance {} check logfile for more details".format(
            args.destination_instance)
        dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                       files_to_attach=[logfile])
        alert_description = "Error while checking user passwords for instance {}, Please check error log for more details".format(
            args.destination_instance)
        raise_radar_alert(source_instance, destination_instance, alert_description)
        sys.exit(1)

    if pod in pods:
        retcode = pod_automation_util.change_store_passwords(account, region, pod, destination_instance)
        if retcode == 1:
            status_message = "Password reset for some users not in vault failed, please check logfile for more details"
            dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                           files_to_attach=[logfile])
            alert_description = "Error while setting passwords for users not in vault"
            raise_radar_alert(source_instance, destination_instance, alert_description)
            sys.exit(1)

    status_message = "Refresh environment\n      " \
                     "Source: %s\n      " \
                     "Destination: %s\n" \
                     "Status: Refresh completed successfully. \n" \
                     "Please check the attached log file for further details \n" \
                     "Please restart the application mentioned here " \
                     "http://wiki.ia55.net/display/TECHDOCS/Applications+running+on+PostgreSQL+instances" % (
                     source_instance, destination_instance)
    dbrefreshutil.update_current_running_refresh_status_on_desflow(status_message=status_message,
                                                                   files_to_attach=[logfile])

    logging.info("all steps completed successfully")
    update_current_running_status(source_instance, destination_instance, statuscode=0,
                                  comments='All steps of the refresh completed successfully')

    # Entry into dbainfra.dbo.refresh_status table
    status = "SUCCESS"
    refresh_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    query = "insert into dbainfra.dbo.refresh_status values('" + destination_instance + "','" + refresh_date + "','" + status + "')"
    cur_sql_dest, conn_sql_dest = pod_automation_util.sql_connect()
    cur_sql_dest.execute(query)
    conn_sql_dest.close()


if __name__ == "__main__":
    main()
