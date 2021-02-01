import sys
import os
import argparse
import datetime
import time
import boto3
import pyodbc
from multiprocessing import Process
from time import sleep

sys.path.append('/g/dba/pythonutilities/')
from pythonutils import PythonUtils

sys.path.append('/g/dba/rds/')
from rdsutil import RDSUtil
from rds_failover_failback import RDSROReplicaUtil


def get_directory_for_log():
    LOG_DIR = "/g/dba/logs/postgresql"
    return LOG_DIR


def setup_logging(options):
    # Get log directory
    current_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    log_directory = get_directory_for_log()
    # Create log file to which messages will be logged
    current_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    logfile_name = 'aurora_read_replica_%s_%s.log' % (options.task, current_time)
    options.logger = PythonUtils().setup_logging(logging_directory=log_directory, logging_file_name=logfile_name)


def create_parser(program):
    tasks = ['CREATE_READ_ONLY', 'DESTROY_READ_ONLY', 'FAILOVER', 'FAILBACK', 'VALIDATE_FAILOVER', 'VALIDATE_FAILBACK']
    parser = argparse.ArgumentParser(prog=program, usage='%(prog)s [options]')
    parser.add_argument('--task', dest="task", required=True, type=str, choices=tasks,
                        help='The task to be performed. Allowed values are ' + ', '.join(tasks), metavar='')
    parser.add_argument('--dbinstances', dest="dbinstance", required=False, type=str, nargs='+',
                        help='space separated list of PostgreSQL WRITER instance name', metavar='')
    parser.add_argument('--roinstances', dest="roinstance", required=False, type=str, nargs='+',
                        help='space separated list of PostgreSQL READONLY instance name', metavar='')
    parser.add_argument('--validation', dest="validation", required=False, type=str,
                        help='Specify the type of validation allowed values FAILOVER or FAILBACK', metavar='')

    return parser


def process_options(program=__file__):
    parser = create_parser(program=program)

    # Check input options and print message in case of errors
    try:
        options = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)

    def _validate_options(options):
        if (options.task in ['CREATE_READ_ONLY', 'FAILOVER', 'VALIDATE_FAILOVER']) and (not options.dbinstance):
            parser.error("The --dbinstance parameter is mandatory ")
        if (options.task in ['FAILBACK', 'DESTROY_READ_ONLY', 'VALIDATE_FAILBACK']) and (not options.roinstance):
            parser.error("The --ronstance parameter is mandatory for fallback")

    _validate_options(options)

    return options


if __name__ == '__main__':

    # Process input options
    options = process_options()

    procs = []

    # Set up logging
    setup_logging(options)
    rdsroreplica = RDSROReplicaUtil(logger=options.logger)

    if options.task == 'CREATE_READ_ONLY':
        for dbinstanceidentifier in options.dbinstance:
            p1 = Process(target=rdsroreplica.create_read_replica_for_instance, args=(dbinstanceidentifier,))
            procs.append(p1)
            p1.start()
            # executor.submit(rdsroreplica.create_read_replica_for_instance(dbinstance=dbinstanceidentifier))
        for proc in procs:
            proc.join()

    if options.task == 'FAILOVER':
        for dbinstanceidentifier in options.dbinstance:
            p1 = Process(target=rdsroreplica.failover_ro_instance, args=(dbinstanceidentifier,))
            procs.append(p1)
            p1.start()

        for proc in procs:
            proc.join()
    if options.task == 'FAILBACK':
        for roinstanceidentifier in options.roinstance:
            p1 = Process(target=rdsroreplica.fallback_ro_instance, args=(roinstanceidentifier,))
            procs.append(p1)
            p1.start()

        for proc in procs:
            proc.join()

    if options.task == 'DESTROY_READ_ONLY':
        for roinstanceidentifier in options.roinstance:
            p1 = Process(target=rdsroreplica.destroy_ro_replica, args=(roinstanceidentifier,))
            procs.append(p1)
            p1.start()

        for proc in procs:
            proc.join()

    if options.task == 'VALIDATE_FAILOVER':
        for dbinstanceidentifier in options.dbinstance:
            validationtype = 'FAILOVER'
            p1 = Process(target=rdsroreplica.validate_failover_failback, args=(dbinstanceidentifier, validationtype,))
            procs.append(p1)
            p1.start()

        for proc in procs:
            proc.join()

    if options.task == 'VALIDATE_FAILBACK':
        for roinstanceidentifier in options.roinstance:
            validationtype = 'FAILBACK'
            p1 = Process(target=rdsroreplica.validate_failover_failback, args=(roinstanceidentifier, validationtype,))
            procs.append(p1)
            p1.start()

        for proc in procs:
            proc.join()
