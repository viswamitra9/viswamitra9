# Owner : Srinivasarao Oguri
# Description : This automation is to automate the user creation/deletion/reset passwords for Snowflake database users

import textwrap
import argparse
import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import random
import logging
import json
import sys
import pyodbc
from datetime import datetime
sys.path.append('/g/dba/oguri/dba/snowflake/')
import vaultutil

logger  = logging.getLogger()
logfile = '/g/dba/logs/snowflake/snowflake_user_management_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))


def set_logging():
    print("Please check the logfile {} for details".format(logfile))
    # default log level for root handler
    logger.setLevel(logging.INFO)
    # creating file handler
    ch = logging.FileHandler()
    ch.setLevel(logging.INFO)
    # creating stream handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.ERROR)
    # set formatter for handlers with secretdetector
    ch.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    sh.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)


def sql_connect():
    """
    PURPOSE:
        Create connection to DBMONITOR
    RETURNS:
        Returns connection and cursor
    """
    try:
        conn_sql_dest = pyodbc.connect(
            'DRIVER={Easysoft ODBC-SQL Server};Server=DBMONITOR.ia55.net;UID=;PWD=;ServerSPN=MSSQLSvc/dbmonitor1b.win.ia55.net;APP=DBRefreshUtil;')
        cur_sql_dest = conn_sql_dest.cursor()
        conn_sql_dest.autocommit = True
        return cur_sql_dest, conn_sql_dest
    except Exception as e:
        logger.error("Error while creating database connection to DBMONITOR server {}".format(str(e)))
        raise Exception("Error while creating database connection to DBMONITOR server {}".format(str(e)))


def get_admin_connection(account, pod):
    """
    PURPOSE:
        Create connection to account with sa user.
        Create database audit_archive , small warehouse
    INPUTS:
        account(<account>.<region>.privatelink) , username , password
    RETURNS:
        returns connection, cursor
    """
    username = 'sa'
    password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
    connection, cursor = get_snowflake_connection(account, username, password)
    try:
        cursor.execute("create database if not exists audit_archive")
        cursor.execute("use database audit_archive")
        cursor.execute("use schema public")
        logger.info("Checking for dba warehouse and create it if not exists")
        cursor.execute("create warehouse if not exists DBA_WH with WAREHOUSE_SIZE=small")
        cursor.execute("use role accountadmin")
        cursor.execute("use warehouse DBA_WH")
        return connection, cursor
    except Exception as e:
        logger.error("error while creating admin connection to account : {}".format(account))
        raise Exception("error while creating admin connection to account : {}".format(account))


