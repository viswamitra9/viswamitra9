#!/usr/bin/env python2

"""
Script to copy a snapshot of golden instance
@author: ranav

"""

import argparse
import pytz
import logging
import os
import subprocess
import sys
import time
import pyodbc
import string
import datetime
import logging
import arcesium.infra.boto as arcboto
import boto3
from botocore.exceptions import ClientError
from logging.handlers import RotatingFileHandler
from datetime import datetime
from botocore.config import Config

config = Config(
    retries=dict(
        max_attempts=20
    )
)

logger = logging.getLogger('mssql-dbs')


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
    """
    take input arguments and parse
    """

    parser = argparse.ArgumentParser(add_help=True, description='example : \
    sudo -u sqlexec mssql-configure-sqlserver --create --mssql-host-shortnames terradb3a.win.ia55.net --stability uat --pod gicuat --customer gic  \
    --region-name us-east-1 --cost gicuat  --customer gic --account-name dev-hyd ')

    parser = argparse.ArgumentParser(add_help=True)
    # Mutually exclusive arguments
    createordelete = parser.add_mutually_exclusive_group(required=True)
    createordelete.add_argument("--create", action='store_true', help="To create snapshot")
    createordelete.add_argument("--delete", action='store_true', help="To delete snapshot")

    # Required Arguments

    parser.add_argument('--account-name', dest='dest_account', help='Give destination region account name',
                        required=True)
    parser.add_argument('--region', dest='region', help='Give destination region name, example : us-east-1',
                        required=True)
    parser.add_argument('--stability', dest='stability', help='Give stability information example : dev, uat, prod',
                        required=True)
    parser.add_argument('--pod', dest='pod', help='Give pod information example : gicuat', required=True)
    parser.add_argument('--cost', dest='cost', help='Customer Cost Tag', required=True)
    parser.add_argument('--customer', dest='customer', help='Give customer name, example paloma', required=True)
    parser.add_argument('--mssql-host-shortnames', action='store', dest='host_name',
                        help='Provide SQL SERVER host name', required=True)

    # Optional arguments

    parser.add_argument("--dry-run", action='store_true', required=False, help="dry run the snapshot creation")
    parser.add_argument('--source-account', dest='src_account', default='prod', required=False)
    parser.add_argument('--source-region', dest='src_region', default='us-east-1', required=False)

    parser.add_argument('--log-level', default='INFO', help="Loglevel Default: %(default)r")
    parser.add_argument('--log-file', default='STDERR', help="Logfile location Default: STDERR")

    return parser.parse_args()


def get_ec2_kms_clients(account, region):
    try:
        arcboto.install()
        session = boto3.session.Session(profile_name='{}/dba'.format(account))
        ec2 = session.client('ec2', region_name='{}'.format(region))
        ec2_resource = session.resource('ec2', region_name='{}'.format(region))
        kms = session.client('kms', region_name='{}'.format(region))
        return kms, ec2, ec2_resource,
    except ClientError as e:
        logger.error('exception while fetching boto3 connection', e.response['Error']['Code'])
        sys.exit(1)


def get_id_of_account(account):
    dev = boto3.session.Session(profile_name='{}/dba'.format(account))
    return dev.client('sts').get_caller_identity().get('Account')


def sql_query(querystring, host_name):
    connectionstring = 'DRIVER={Easysoft ODBC-SQL Server};Server=' + host_name + ';UID=;PWD=;ServerSPN=MSSQLSvc/' + host_name + ';APP=NewPodCreation;'
    print(connectionstring)
    con = pyodbc.connect(connectionstring)
    cur = con.cursor()
    result = cur.execute(querystring)

    for r in result:
        print(r)


def get_ebs_volume_id(host_name, drive_letter):
    get_volume_id = "xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command  \"\\\\win.ia55.net\\windows\\scripts\\dba\\Monitoring\\hammer\\python\\get-ebs-volume-id.ps1 -Computername %s -Drive %s ; \"'" % (
    host_name, drive_letter)
    dbh = pyodbc.connect(
        'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=NewPodSetup;')
    dbh.autocommit = True
    result = dbh.execute(get_volume_id)
    ebs_vol_row = result.fetchone()
    golden_volume_id = str(ebs_vol_row[0])
    if golden_volume_id.find('vol') != -1:
        return golden_volume_id


def get_instance_id(host_name, dest_profile_name, dest_region):
    try:
        kms, destination_region_ec2_client, destination_region_ec2_resource = get_ec2_kms_clients(
            account=dest_profile_name, region=dest_region)

        instance_info_response = destination_region_ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:hostname',
                    'Values': ['{}'.format(host_name)]
                }
            ])

        if instance_info_response is None:
            host_name_no_win = host_name.replace(".win.ia55.net", "")
            instance_info_response = destination_region_ec2_client.describe_instances(
                Filters=[
                    {
                        'Name': 'tag:hostname',
                        'Values': ['{}'.format(host_name_no_win)]
                    }
                ]
            )

        instance_id = instance_info_response["Reservations"][0]["Instances"][0]["InstanceId"]
        availabilityzone = instance_info_response["Reservations"][0]["Instances"][0]["Placement"]["AvailabilityZone"]

        if instance_id is not None:
            return instance_id, availabilityzone
        else:
            logger.error("Unable to find instance_id")
            raise Exception("Unable to find instance_id")
    except:
        raise


def configure_sql_server(dest_region, availability_zone, host_name, pod, stability, dbrole, customer, cost):
    #       Configure SQL SERVER

    try:

        #            Move Master Database running from dbmonitor so we do not loose control or exit once we restart the SQL Service

        print('Moving Master Database')

        movemaster = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"\\\\win.ia55.net\\windows\\scripts\\dba\\Monitoring\\hammer\\python\\move_master_task.ps1 -ComputerName %s; \"'" % (
            host_name)
        sql_query(movemaster, 'dbmonitor1b.win.ia55.net')

        #           Configure SQL SERVER

        print('Configuring SQL SERVER')

        configuresql = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"\\\\win.ia55.net\\windows\\scripts\\dba\\Monitoring\\hammer\\python\\configure_sql_server.ps1 -ComputerName %s -AvailabilityZone %s -Stability %s -Pod %s -Region %s -dbrole %s -EnterpriseEdition %s; \"'" % (
        host_name, availability_zone, stability, pod, dest_region, dbrole, 'no')
        sql_query(configuresql, host_name)

        #           Apply Permission (Invoke-permission is failing when running remotely or when it's part of powershell script hence executing)

        print('Apply Permission')

        applypermission = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"\\\\win.ia55.net\\windows\\scripts\\dba\\Other\\Golden-ApplyPrivileges.ps1 -TargetSQLServer %s -Stability %s -PodName %s; \"'" % (
        host_name, stability, pod)
        sql_query(applypermission, 'dbmonitor1b.win.ia55.net')

        print('Running POS-REFRESH')

        #           Post Refresh Script (Invoke-permission is failing when running remotely or when it's part of powershell script hence executing)

        postrefreshscript = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"\\\\win.ia55.net\\windows\\scripts\\dba\\Other\\Run-PostRefresh.ps1 -TargetSQLServer %s -Client %s -Stability %s -Pod %s; \"'" % (
        host_name, customer, stability, pod)
        sql_query(postrefreshscript, 'dbmonitor1b.win.ia55.net')

        print('Restart SQL SERVER Service')

        restartsqlservice = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"\\\\win.ia55.net\\windows\\scripts\\dba\\Monitoring\\hammer\\python\\restart_sql_service.ps1 -ComputerName %s; \"'" % (
            host_name)
        sql_query(restartsqlservice, 'dbmonitor1b.win.ia55.net')


    except:
        print('PowerShell Command Executed using xp_cmdshell, track progress using local\new_pod* file on Server')


def test_sql_connectvitiy(host_name):
    try:
        CheckServer = "select @@servername"
        sql_query(CheckServer, host_name)

    except Exception as e:
        logger.error("error while connecting to SQL Server {}".format(e))
        sys.exit(1)

    try:
        sql_xp_cmdshell = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"Get-Disk;\"'"
        sql_query(sql_xp_cmdshell, host_name)

    except Exception as e:
        logger.error("error while connecting to SQL Server {}".format(e))
        sys.exit(1)

    try:
        CheckServer = "select @@servername"
        sql_query(CheckServer, 'dbmonitor1b.win.ia55.net')

    except Exception as e:
        logger.error("error while connecting to SQL Server {}".format(e))
        sys.exit(1)

    try:
        sql_xp_cmdshell = "EXEC xp_cmdshell 'powershell.exe -ExecutionPolicy bypass -command \"Get-Disk;\"'"
        sql_query(sql_xp_cmdshell, 'dbmonitor1b.win.ia55.net')

    except Exception as e:
        logger.error("error while connecting to SQL Server {}".format(e))
        sys.exit(1)


def main():
    print('Configuring SQL SERVER')
    args = parse_arguments()
    dryrun = args.dry_run
    # Enabling logger
    setup_logging(args.log_level, args.log_file)
    print(args)

    # Source Region, AZ, account and Profile  Info

    src_region = args.src_region
    src_account = args.src_account
    source_profile_name = src_account

    # Destination Region, AZ, account and Profile  Info

    dest_region = args.region
    dest_account = args.dest_account
    dest_profile_name = dest_account

    # Other Info

    pod = args.pod
    stability = args.stability
    customer = args.customer
    cost = args.cost

    if args.create:
        instance_action = 'create'

    if args.delete:
        instance_action = 'delete'

    if dryrun:
        dry_run = 'dry run: '

    else:
        dry_run = ''

    host_name_string = args.host_name
    host_name_list = list(host_name_string.split(","))
    for host_name_info in host_name_list:
        host_name = host_name_info
        print('Currently working on:' + host_name)

        host_name = host_name.replace(".win.ia55.net", "") + '.win.ia55.net'
        test_sql_connectvitiy(host_name)
        instance_id, availabilityzone = get_instance_id(host_name, dest_profile_name, dest_region)
        availability_zone = availabilityzone
        host_name_no_win = host_name.replace(".win.ia55.net", "")

        # If the stability is prod and host name ending with 1b in that case set the dbrole to dr else set same as stability

        if stability == 'prod':

            if availabilityzone[-2:] != '1a':
                dbrole = 'dr'
            else:
                dbrole = stability
        else:

            dbrole = stability

        if instance_action == 'create':
            print('Configuration of SQL SERVER has been started')
            configure_sql_server(dest_region, availability_zone, host_name, pod, stability, dbrole, customer, cost)

        if instance_action == 'delete':
            logger.info('No Action Required')


if __name__ == "__main__":
    main()
