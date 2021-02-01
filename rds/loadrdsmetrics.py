import boto3
import pyodbc
import psycopg2
from multiprocessing import Process
import argparse
import datetime
import time
import json
import os
import sys
from botocore.config import Config
config = Config(
    retries=dict(
        max_attempts=20)
)
client = boto3.client('logs', config=config)
sys.path.append('/g/dba/python_modules/')
import get_aws_client

sys.path.append('/g/dba/')
import radarutil

os.environ['TZ'] = 'UTC'
time.tzset()


def get_rds_resourceid(dbinstance):
    rdsclient = get_aws_client.get_rds_client()
    instance = rdsclient.describe_db_instances(DBInstanceIdentifier=dbinstance)
    resourceid = instance['DBInstances'][0]['DbiResourceId']
    if not resourceid:
        return None
    else:
        return resourceid


def check_last_load_time(dbinstance):
    lastloadcmd = "if(select count(1) from dbainfra.dbo.rds_os_metrics   WHERE server_name = '" + dbinstance + "' and date_time_utc > getdate()-1)>0  SELECT MAX(date_time_utc) as datetime FROM dbainfra.dbo.rds_os_metrics WHERE server_name = '" + dbinstance + "'  else   SELECT DATEADD(minute,-10,GETUTCDATE()) as Datetime;"
    # lastloadcmd = "select dateadd(minute,-1,getutcdate()) as Datetime;"
    dbh = pyodbc.connect(
        'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
    dbh.autocommit = True
    result = dbh.execute(lastloadcmd)
    lastload = result.fetchone()
    return lastload[0]


def get_rds_metrics(dbinstance, starttime, endtime):
    format = "%d/%m/%Y  %H:%M:%S"
    # start_seconds = time.mktime(datetime.datetime.strptime(starttime, format).timetuple())
    start_seconds = time.mktime(starttime.timetuple())
    # end_seconds = time.mktime(datetime.datetime.strptime(endtime, format).timetuple())
    end_seconds = time.mktime(endtime.timetuple())
    resourceid = get_rds_resourceid(dbinstance=dbinstance)
    insert = ''
    print("Loading started on instance %s with resource id %s for the time range between %s and %s" % (dbinstance, resourceid, starttime, endtime))
    while start_seconds <= end_seconds:
        response = client.filter_log_events(logGroupName='RDSOSMetrics', logStreamNames=[resourceid],startTime=(long(start_seconds)) * 1000,endTime=long(start_seconds + 30) * 1000)
        if len(response['events']) != 0:
            processlist = json.loads(response['events'][0]['message'])['processList']
            for i in processlist:
                if i['cpuUsedPc'] > 0.0:
                    vss = i['vss']
                    name = i['name']
                    memoryused = i['memoryUsedPc']
                    cpuused = i['cpuUsedPc']
                    pid = i['id']
                    rss = i['rss']
                    parentid = i['parentID']
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start_seconds))
                    insertcmd = "INSERT into dbainfra.dbo.rds_os_metrics(server_name, pid, vss, process_name, memory_used_pct, cpu_used_pct, date_time_utc) values ('" + dbinstance + "'," + str(
                        pid) + "," + str(vss) + ",'" + str(name) + "'," + str(memoryused) + "," + str(
                        cpuused) + ",'" + str(timestamp) + "');"
                    insert += insertcmd
        start_seconds = start_seconds + 30
    return insert


def check_enhancedmonitoring_enabled(dbinstance):
    try:
        eclient = boto3.client('rds')
        rds_instances = eclient.describe_db_instances(DBInstanceIdentifier=dbinstance)
        if rds_instances['DBInstances'][0]['MonitoringInterval'] == 0:
            print(rds_instances['DBInstances'][0]['MonitoringInterval'])
            return False
        else:
            return True
    except Exception as e:
        print('Error: ' + str(e))
        print('The instance you selected doesn''t have Enhanced Monitoring activated.')


def write_rds_metrics_postgres(dbinstance):
    try:
        # check if enhancedmonitoring is enabled
        monitoringstatus = check_enhancedmonitoring_enabled(dbinstance=dbinstance)
        if monitoringstatus:
            print("process of RDS OS metrics starting now at %s on instance %s " % (
            str(datetime.datetime.now()), dbinstance))
            lastload = check_last_load_time(dbinstance)
            endtime = datetime.datetime.now()
            starttime = lastload + datetime.timedelta(seconds=1)
            format = "%d/%m/%Y  %H:%M:%S"
            startload = starttime
            endload = endtime
            print("RDS OS Metrics are loading for the instance %s and time window %s and %s " % (dbinstance, starttime, endtime))
            response = get_rds_metrics(dbinstance=dbinstance, starttime=starttime, endtime=endtime)
            dbh = pyodbc.connect('DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
            dbh.autocommit = True
            result = dbh.execute(response)
            print("process of RDS OS metrics ended at %s on instance %s " % (str(datetime.datetime.now()), dbinstance))
        else:
            print("The instance %s is not enabled for enhanced monitoring. Please enable in aws.ia55.net" % (dbinstance))
    except Exception as e:
        sys.exit()


def load_pg_stats_to_file(dbinstance, table, sa_pass):
    endpoint = get_cluster_endpoint(dbinstance)
    # sa_pass = get_sa_password()
    sqlcmd = "(SELECT '{}'as servername, to_char(now(),'YYYY-MM-DD HH24:MI:ss') as timestamp, * FROM {})".format(
        str(dbinstance), str(table))
    targetfile = '/tmp/' + table + '_' + dbinstance + ".txt"
    if os.path.exists(targetfile):
        os.remove(targetfile)
    target = open(targetfile, 'w')
    DSN = 'host={} port = {} dbname={} user={} password={} sslmode = {} '.format(endpoint, '5432', 'postgres', 'sa',
                                                                                 sa_pass, 'require')
    conn = psycopg2.connect(DSN)
    cursor = conn.cursor()
    cursor.copy_to(target, sqlcmd, sep=',', null='')
    cursor.close()
    return targetfile


def load_pg_stats_to_dbmonitor(dbinstance, sa_pass):
    # arctechops#16894#13
    # tables = ['pg_stat_database','pg_stat_bgwriter','pg_stat_all_tables','pg_stat_activity','pg_statio_all_tables','pg_statio_all_indexes']
    tables = ['pg_stat_activity']

    try:
        for table in tables:
            targetfile = load_pg_stats_to_file(dbinstance, table, sa_pass)
            bcpcmd = "sudo -u sqlexec bcp dbainfra.dbo." + table + "_history in '" + targetfile + "'  -S DBMONITOR -c -K -t','"
            output = os.system(bcpcmd)
            print(bcpcmd)
    except Exception as e:
        alert_source = 'dba'
        alert_severity = 'MEDIUM'
        alert_class = 'Ticket'
        alert_key = 'Load-PGAuroraRDSMetrics'
        alert_summary = 'Load-PGAuroraRDSMetrics script failed located in /g/dba/rds/loadpgaurorardsmetrics.py.Script runs through jobexec http://jobexec.ia55.net/ui/pods/shared/jobs/Load_PGAURORA_RDS_OS_MERTRICS'
        alert_description = "Script failed with below error for load pg stats load_pg_stats_to_dbmonitor \n" + ' with err r' + str(
            e) + dbinstance
        request = radarutil.RadarUtil()
        request.raise_radar_alert(alert_source, alert_severity, alert_class, alert_key, alert_summary,
                                  alert_description)
        sys.exit()


def create_parser(program):
    tasks = ['LoadRDSMetrics', 'LoadPGStats']
    parser = argparse.ArgumentParser(prog=program, usage='%(prog)s [options]')
    parser.add_argument('--task', dest="task", required=True, type=str, choices=tasks,
                        help='The task to be performed. Allowed values are LoadRDSMetrics,LoadPGStats', metavar='')
    parser.add_argument('--dbinstance', dest='dbinstance', required=False, type=str, metavar='')
    return parser


def process_options(program=__file__):
    # Get the parser
    parser = create_parser(program=program)

    # Check input options and print message in case of errors
    try:
        options = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)

    return options


if __name__ == '__main__':
    try:
        options = process_options()
        procs = []
        if options.task == "LoadRDSMetrics":
            if not options.dbinstance:
                servers = get_pg_prod_server()
                for server in servers:
                    print(server[0])
                    p1 = Process(target=write_rds_metrics_postgres, args=(server[0],))
                    procs.append(p1)
                    p1.start()
            else:
                p1 = Process(target=write_rds_metrics_postgres, args=(options.dbinstance,))
                procs.append(p1)
                p1.start()
        options = process_options()
        if options.task == "LoadPGStats":
            sa_pass = get_sa_password()
            if not options.dbinstance:
                servers = get_pg_prod_server()
                for server in servers:
                    print(server[0])
                    p1 = Process(target=load_pg_stats_to_dbmonitor, args=(server[0], sa_pass,))
                    procs.append(p1)
                    p1.start()
            else:
                target = load_pg_stats_to_dbmonitor(dbinstance=options.dbinstance, sa_pass=sa_pass)
    except Exception as e:
        sys.exit()
