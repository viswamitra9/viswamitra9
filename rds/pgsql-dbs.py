#!/usr/bin/env python2

import argparse
import json
import logging
import sys
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

logger = logging.getLogger('pgsql-instance')


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
    createordelete.add_argument("--create", action='store_true', help="To create a RDS instance")
    createordelete.add_argument("--delete", action='store_true', help="To delete a RDS instance")

    # Required arguments
    parser.add_argument('--account-name', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--db-subnet-group', action='store', dest='subnet_group',
                        help='Give subnet group for destination instance, example : ia55-db-subnetgroup', required=True)
    parser.add_argument('--stability', dest='stability', help='Give stability information example : uat, prod',
                        required=True)
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)
    parser.add_argument('--vpc-name', dest='vpcname', help='Give vpc name, example : ia55-prod', required=True)
    parser.add_argument('--customer', dest='customer', help='Give customer name, example gic', required=True)
    parser.add_argument('--cost', required=True)
    parser.add_argument('--common-secgroup',
                        help='A string with the name of the common-secgroup [secgroup-common in us-east-1]',
                        required=True)

    # Optional arguments
    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the instance creation")
    parser.add_argument('--destination-instance', dest='destination_instance', default='none',
                        help='Give the name for the destination instance you want to create', required=False)
    parser.add_argument('--db-instance-class', default="db.r5.large", dest='db_instance_class',
                        help='Give instance class, it should be an r5 instance ex: r5.large, r5.xlarge etc',
                        required=False)
    parser.add_argument("--source-instance", default="goldendb1", dest="source_instance",
                        help="Give the source instance name, whose clone needs to be created, example : goldendb1",
                        required=False)
    parser.add_argument('--source-account', default='prod', required=False)
    parser.add_argument('--source-region', default='us-east-1', required=False)
    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")
    return parser.parse_args()


instance_sleep_time = 6


def get_latest_cluster_snapshot(destination_region,destination_account,pod):
    query = "select TOP 1 snapshotname from dbainfra.dbo.pod_creation_snapshots where pod='" + pod + "' and " \
            "region='" + destination_region + "' and account='" + destination_account + "' and deleted != 1 " \
                                                                              "order by s_c_time desc"
    cur_sql_dest, conn_sql_dest = sql_connect()
    rows = cur_sql_dest.execute(query)
    row = rows.fetchone()
    return row.snapshotname


def create_parametergroup(rds,pgversion,pgfamily):
    parametergroup = 'arcesium-custom-postgres{}'.format(pgversion[0])
    try:
        response = rds.create_db_cluster_parameter_group(
            DBClusterParameterGroupName=parametergroup,
            DBParameterGroupFamily =pgfamily,Description='default parameter group')
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBParameterGroupAlreadyExists':
            pass
        else:
            logger.error("Failed to create db parameter group : {}".format(str(e)))
            sys.exit(1)
    try:
        response = rds.create_db_parameter_group(DBParameterGroupName=parametergroup,
           DBParameterGroupFamily =pgfamily,Description='default parameter group')
        set_parameter_values(rds,str(parametergroup))
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBParameterGroupAlreadyExists':
            pass
        else:
            logger.error("Failed to create db parameter group : {}".format(str(e)))
            sys.exit(1)
    return parametergroup


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


def get_cluster_endpoint(rds, clusteridentifier):
    try:
        response = rds.describe_db_cluster_endpoints(DBClusterIdentifier=clusteridentifier)
        return {'pgsql-endpoint-reader': response['DBClusterEndpoints'][1]['Endpoint'],
                'pgsql-endpoint-writer': response['DBClusterEndpoints'][0]['Endpoint']}
    except ClientError as e:
        logger.error("Exception while getting cluster endpoint details: {}".format(e))
        sys.exit(1)


def check_cluster_status_for_create(destination_account, destination_region, clusteridentifier):
    # function to check the status of given cluster
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    retry_count = 1
    while retry_count <= 900:
        time.sleep(instance_sleep_time)
        try:
            status = rds.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['Status']
            logger.info("iteration : %s, status of the cluster is %s", retry_count, status)
            retry_count = retry_count + 1
            if status == 'available':
                return 0
        except ClientError as e:
            if e.response['Error']['Code'] == 'ExpiredToken':
                logger.error("Expired Token while checking cluster status")
                return 1
            elif e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                logger.warning('cluster not found trying again to check the status')
                retry_count = retry_count + 1
                continue
            else:
                logger.error('error occurred while checking cluster status %s', e.response['Error']['Code'])
                return 1
    return 1


def set_parameter_values(rds,parametergroup):
    cur_sql_dest, conn_sql_dest = sql_connect()
    query = "select * from dbainfra.dbo.pg_instance_parameters"
    cur_sql_dest.execute(query)
    result = cur_sql_dest.fetchall()
    if result:
        for row in result:
            rds.modify_db_parameter_group(DBParameterGroupName=parametergroup,Parameters=[{'ParameterName': row[0],'ParameterValue': row[1],'ApplyMethod': 'pending-reboot'}],)


def check_instance_status_for_create(destination_account, destination_region, instanceidentifier):
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    # function to check the status of given instance until it is available
    retry_count = 1
    while retry_count <= 900:
        time.sleep(instance_sleep_time)
        try:
            status = rds.describe_db_instances(DBInstanceIdentifier=instanceidentifier)['DBInstances'][0][
                'DBInstanceStatus']
            logger.info("iteration : %s, status of the instance is %s", retry_count, status)
            retry_count = retry_count + 1
            if status == 'available':
                return 0
        except ClientError as e:
            if e.response['Error']['Code'] == 'ExpiredToken':
                logger.error("Expired Token while checking instance status")
                return 1
            elif e.response['Error']['Code'] == 'DBInstanceNotFound':
                logger.warning('instance not found trying again to check the status')
                retry_count = retry_count + 1
                continue
            else:
                logger.error('error occurred while checking instance status %s', e.response['Error']['Code'])
                return 1
    return 1


def delete_instance(destination_account, destination_region, instanceidentifier, dry_run):
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    # function to delete an RDS instance
    retry_count = 1
    if dry_run:
        logger.info("dry run : rds.delete_db_instance(DBInstanceIdentifier=" + instanceidentifier + ")")
        return 0
    else:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=instanceidentifier)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logger.error('The instance is not found, it might be deleted already')
                return 0
            else:
                logger.error('error while deleting instance is %s', e.response['Error']['Code'])
                return 1
        while retry_count <= 500:
            time.sleep(instance_sleep_time)
            try:
                status = rds.describe_db_instances(DBInstanceIdentifier=instanceidentifier)['DBInstances'][0][
                    'DBInstanceStatus']
                logger.info("iteration : %s, status of the instance is %s", retry_count, status)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBInstanceNotFound':
                    logger.info("Instance deleted successfully")
                    return 0
                else:
                    logger.error("Instance deletion failed")
                    logger.error('error while deleting instance is %s', e.response['Error']['Code'])
                    return 1


def delete_cluster(destination_account, destination_region, clusteridentifier, dry_run):
    # function to delete an RDS cluster
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    retry_count = 1
    if dry_run:
        logger.info("dry run : rds.delete_db_cluster(DBClusterIdentifier = " + clusteridentifier + ",SkipFinalSnapshot=True)")
        return 0
    else:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=clusteridentifier,SkipFinalSnapshot=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                logger.error('The cluster is not found, it might be deleted already')
                return 0
            else:
                logger.error('error while deleting cluster is %s', e.response['Error']['Code'])
                return 1
        while retry_count <= 500:
            time.sleep(instance_sleep_time)
            try:
                status = rds.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['Status']
                logger.info("iteration : %s, status of the cluster is %s", retry_count, status)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBClusterNotFoundFault':
                    logger.info("Cluster deleted successfully")
                    return 0
                else:
                    logger.error("Cluster deletion failed")
                    logger.error('error while deleting cluster is %s', e.response['Error']['Code'])
                    return 1


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def set_cluster_retention(destination_account, destination_region, clusteridentifier, retention):
    retry_count = 0
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    rds.modify_db_cluster(DBClusterIdentifier=clusteridentifier, BackupRetentionPeriod=retention, ApplyImmediately=True)
    cluster_retention = rds.describe_db_clusters(DBClusterIdentifier=clusteridentifier)['DBClusters'][0]['BackupRetentionPeriod']
    if cluster_retention != retention:
        logger.warning("Checking status again : {}".format(retry_count+1))
        raise


def create_cluster(dbcluster_identifier_clone, snapshotname, subnet_group, vpc_sec_groups, kms_key_id, pgversion,
                   dry_run, tags,parametergroup,stability,destination_account, destination_region):
    # function to create RDS cluster
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    if dry_run:
        vpc_sec_groups_string = '[' + ','.join(str(i) for i in vpc_sec_groups) + ']'
        kms_key_id_string = "'" + ''.join(str(i) for i in kms_key_id) + "'"
        logger.info(
            "dry run : rds.restore_db_cluster_from_snapshot(DBClusterIdentifier=" + dbcluster_identifier_clone +
            ",SnapshotIdentifier=" + snapshotname +
            ",DBSubnetGroupName=" + subnet_group +
            ",VpcSecurityGroupIds=" + vpc_sec_groups_string +
            ",Engine='aurora-postgresql'" +
            ",EngineVersion=" + pgversion +
            ",KmsKeyId=" + kms_key_id_string + ")"
        )
        return 0
    else:
        retry = 0
        while retry <= 1:
            try:
                logger.info("Started the creation of cluster")
                rds.restore_db_cluster_from_snapshot(
                    DBClusterIdentifier=dbcluster_identifier_clone,
                    SnapshotIdentifier=snapshotname,
                    DBSubnetGroupName=subnet_group,
                    VpcSecurityGroupIds=vpc_sec_groups,
                    Engine='aurora-postgresql',
                    EngineVersion=pgversion,
                    KmsKeyId=kms_key_id,
                    DBClusterParameterGroupName=str(parametergroup),
                    Tags=tags)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBClusterAlreadyExistsFault':
                    logger.warning("Cluster already exists")
                    return 0
                else:
                    logger.error('Cluster copy failed with exceptions {}'.format(str(e)))
                    return 1
            retcode = check_cluster_status_for_create(destination_account, destination_region, dbcluster_identifier_clone)
            if retcode == 0:
                logger.info("Cluster copy created successfully")
                if str(stability).lower() == 'dev' or str(stability).lower() == 'qa':
                    logger.info("Modifying snapshot retention period for cluster")
                    set_cluster_retention(destination_account, destination_region, dbcluster_identifier_clone, 1)
                if str(stability).lower() == 'uat':
                    logger.info("Modifying snapshot retention period for cluster")
                    set_cluster_retention(destination_account, destination_region, dbcluster_identifier_clone, 14)
                return 0
            else:
                logger.error("Cluster copy creation failed, trying again")
                retry += 1
                ret_delete = delete_cluster(destination_account, destination_region, dbcluster_identifier_clone, dry_run)
                if ret_delete == 0:
                    logger.info("Deleting cluster, before retry the creation of cluster")
                else:
                    logger.error("Not able to delete the cluster, during the retry")
                    return 1
        return 1


def create_instance(destination_account, destination_region, input_instance_clone, dbinstance_class, preferred_mwindow,
                    dbcluster_identifier_clone, dry_run,tags,parametergroup):
    # function to create RDS instance
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    if dry_run:
        tags_string = "'" + ''.join(str(e) for e in tags) + "'"
        logger.info(
            "dry run : rds.create_db_instance(DBInstanceIdentifier=" + input_instance_clone +
            ",DBInstanceClass=" + dbinstance_class +
            ",Engine='aurora-postgresql'"
            ",PreferredMaintenanceWindow=" + preferred_mwindow +
            ",AutoMinorVersionUpgrade=False"
            ",PubliclyAccessible=False,"
            "Tags=" + tags_string +
            ",DBClusterIdentifier=" + dbcluster_identifier_clone + ")")
        return 0
    else:
        retry = 0
        while retry <= 1:
            try:
                logger.info("trying : %s time creating instance", retry)
                rds.create_db_instance(
                    DBInstanceIdentifier=input_instance_clone,
                    DBInstanceClass=dbinstance_class,
                    Engine='aurora-postgresql',
                    PreferredMaintenanceWindow=preferred_mwindow,
                    AutoMinorVersionUpgrade=False,
                    PubliclyAccessible=False,
                    Tags=tags,
                    DBClusterIdentifier=dbcluster_identifier_clone,
                    DBParameterGroupName=str(parametergroup))
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBInstanceAlreadyExists':
                    logger.warning("Instance already exists")
                    return 0
                else:
                    logger.error('Instance creation failed with exceptions %s', e.response['Error']['Code'])
                    return 1
            # Check the status of Instance creation, wait until Instance is available
            retcode = check_instance_status_for_create(destination_account, destination_region, input_instance_clone)
            if retcode == 0:
                logger.info("Instance copy created successfully")
                return 0
            else:
                logger.error("Instance copy creation failed, trying again")
                retry += 1
                ret_delete = delete_instance(destination_account, destination_region, input_instance_clone, dry_run)
                if ret_delete == 0:
                    logger.info("Deleting instance, before retry the creation of instance")
                else:
                    logger.error("Not able to delete the instance, during the retry")
                    return 1
        return 1


def create_cluster_instance(destination_region, destination_account, snapshotname, destination_cluster,
                            destination_instance, db_instance_class, preferred_mwindow, subnet_group, vpc_sec_groups,
                            kms_key_id, pgversion, tags, pod, stability, dry_run,pgfamily):
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
    logger.info(dry_run + "Starting Cluster clone creation")
    logger.info("Started creation of parameter group")
    parametergroup  = create_parametergroup(rds,pgversion,pgfamily)
    retcode_cluster = create_cluster(destination_cluster, snapshotname, subnet_group, vpc_sec_groups,
                                     kms_key_id,pgversion, dry_run, tags,parametergroup,stability,destination_account, destination_region)
    if retcode_cluster == 0:
        retcode_instance = create_instance(destination_account, destination_region, destination_instance,
                                           db_instance_class, preferred_mwindow,destination_cluster, dry_run, tags, parametergroup)
        if retcode_instance == 0:
            logger.info(dry_run + "instance created successfully")
            print(json.dumps(get_cluster_endpoint(rds, destination_cluster)))
        else:
            logger.error('Instance creation failed')
            sys.exit(1)
    else:
        logger.error('Cluster creation failed')
        sys.exit(1)


def validate_input(source_region, source_account, source_instance, destination_instance, subnet_group, vpcname,secgroups,
                   destination_account, destination_region, dry_run):
    # function to validate the input
    # validate source instance
    rds, ec2, kms = get_rds_ec2_kms_clients(source_account, source_region)
    # Getting VPC ID using VPC NAME (also validate)
    # Validating source instance (ex : golden)
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=source_instance)
        if response['DBInstances'][0]['Engine'] != 'aurora-postgresql':
            logger.error(dry_run + 'The source instance : %s, you entered is not Aurora instance', source_instance)
            return 1
        if response['DBInstances'][0]['DBInstanceStatus'] != 'available':
            logger.error(dry_run + 'The source instance : %s is not in available state,run the script after the instance is available',source_instance)
            return 1
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            logger.error(dry_run + "The source instance : %s does not exists", source_instance)
            return 1
        else:
            logger.error(dry_run + "There is an error in finding the source instance : %s details :", source_instance,e.response['Error']['Code'])
            return 1

    # validate destination instance
    rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)

    vpc = ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [vpcname]}])['Vpcs']
    if vpc:
        vpc_id = vpc[0]['VpcId']
    else:
        logger.error(dry_run + 'The vpc name does not exists : %s', vpcname)
        return 1

    vpc_sec = []
    # Getting security group ID (also validating)
    for secgroup in secgroups:
        vpc_sec_id = \
        ec2.describe_security_groups(Filters=[{'Name': 'tag:Name', 'Values': [secgroup]}])['SecurityGroups'][0]['GroupId']
        if not vpc_sec_id:
            logger.error(dry_run + 'The security group is not created yet : %s', secgroup)
            return 1
        else:
            vpc_sec.append(str(vpc_sec_id))

    # Validating the destination_instance
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=destination_instance)
        if response['DBInstances'][0]['DBInstanceStatus'] == 'available' \
                or response['DBInstances'][0]['DBInstanceStatus'] == 'creating':
            logger.error(dry_run + 'The destination instance : %s you entered already exists and in available or creating state', destination_instance)
            return 1
        if response['DBInstances'][0]['DBInstanceStatus']:
            logger.error(dry_run + 'The destination instance : %s you entered already exists and not in proper state', destination_instance)
            return 1
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            logger.info(dry_run + "The destination instance : %s, does not exists, proceeding further",destination_instance)
    # Validate the subnet group
    try:
        response = rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBSubnetGroupNotFoundFault':
            logger.error(dry_run + 'subnet group : %s, entered is not found, enter a valid subnet group', subnet_group)
            return 1
    return vpc_sec


def main():
    # Get the user inputs
    args = parse_arguments()
    # Enabling logger
    setup_logging(args.log_level, args.log_file)

    # Create variables out of user input
    source_instance     = args.source_instance
    subnet_group        = args.subnet_group
    db_instance_class   = args.db_instance_class
    stability           = args.stability
    pod                 = args.pod
    vpcname             = args.vpcname
    customer            = args.customer
    cost                = args.cost
    secgroup_common     = args.common_secgroup
    secgroups           = ['secgroup-' + pod, secgroup_common]
    dryrun              = args.dry_run
    instance_action     = ''
    destination_region  = args.region
    destination_account = args.account_name
    source_account      = args.source_account
    source_region       = args.source_region

    if args.create:
        instance_action = 'create'
    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '
    else:
        dry_run = ''

    # defining the destination instance
    if args.destination_instance != 'none':
        destination_instance = args.destination_instance
    else:
        destination_instance = pod + 'dbpg1'
    # generated input
    destination_cluster = destination_instance + '-cluster'

    tags = [{'Key': 'cost',
             'Value': cost},
            {'Key': 'customer',
             'Value': customer},
            {'Key': 'pod',
             'Value': pod},
            {'Key': 'stability',
             'Value': stability},
            {'Key': 'workload-type',
             'Value': 'db'}]

    kms_key_id = 'alias/pod/{}'.format(pod)

    # Capture required parameters for creating new instance
    rds, ec2, kms     = get_rds_ec2_kms_clients(source_account, source_region)
    response          = rds.describe_db_instances(DBInstanceIdentifier=source_instance)
    pgversion         = response['DBInstances'][0]['EngineVersion']
    pggroup           = response['DBInstances'][0]['DBParameterGroups'][0]['DBParameterGroupName']
    pgfamily          = rds.describe_db_parameter_groups(DBParameterGroupName=str(pggroup))['DBParameterGroups'][0]['DBParameterGroupFamily']
    preferred_mwindow = response['DBInstances'][0]['PreferredMaintenanceWindow']

    if instance_action == 'create':
        vpc_sec_id = validate_input(source_region=source_region, source_account=source_account,
                                    source_instance=source_instance, destination_instance=destination_instance,
                                    subnet_group=subnet_group, vpcname=vpcname, secgroups=secgroups,
                                    destination_account=destination_account, destination_region=destination_region,
                                    dry_run=dry_run)
        if vpc_sec_id == 1:
            logger.error("Validation of input is failed")
            sys.exit(1)

        # This method will create the cluster and instance
        snapshotname = get_latest_cluster_snapshot(destination_region,destination_account,pod)
        create_cluster_instance(destination_region=destination_region, destination_account=destination_account,
                                snapshotname=snapshotname, destination_cluster=destination_cluster,
                                destination_instance=destination_instance, db_instance_class=db_instance_class,
                                preferred_mwindow=preferred_mwindow, subnet_group=subnet_group,
                                vpc_sec_groups=vpc_sec_id, kms_key_id=kms_key_id, pgversion=pgversion, tags=tags,
                                pod=pod, stability=stability, dry_run=dry_run,pgfamily=pgfamily)
    if instance_action == 'delete':
        rds, ec2, kms = get_rds_ec2_kms_clients(destination_account, destination_region)
        ret_code = delete_instance(rds, destination_instance, dry_run)
        if ret_code == 0:
            ret_code = delete_cluster(rds, destination_cluster, dry_run)
            if ret_code == 0:
                logger.info("Instance and cluster deletion completed")
                sys.exit(0)
            else:
                logger.error('deletion of cluster failed')
                sys.exit(1)
        else:
            logger.error('deletion of instance failed')
            sys.exit(1)


if __name__ == "__main__":
    main()
