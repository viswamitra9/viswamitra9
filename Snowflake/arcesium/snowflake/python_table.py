import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from smtpd import COMMASPACE
from email.mime.base import MIMEBase
import os
import email.encoders as Encoders
import smtplib
import json

import pandas as pd
import numpy as np
import logging
import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import time
import sys
sys.path.append('/g/dba/snowflake')
import vaultutil

sys.path.append('/g/dba/rds/')

STYLING = """
<style>
    table, th, td {
        padding-left: 10px;
        padding-right: 10px;
        padding-top: 3px;
        padding-bottom: 3px;
        text-align: center;
        border-collapse: collapse;
        font-size: 14px;
    }
    th{
        color : darkblue;               
    }

    table.center{
        margin-left: auto;
        margin-right: auto;
    }
    table.table-width{
        width: 100%
    }
</style>
"""

logger = logging.getLogger()
DB_WAIT_TIME   = 10
DB_RETRY_COUNT = 5


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
    ch.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    sh.setFormatter(SecretDetector('%(asctime)s %(module)s %(lineno)d %(levelname)-8s %(message)s'))
    # add the handlers to the logger object
    logger.addHandler(ch)
    logger.addHandler(sh)
    return logger


def send_mail(send_from, send_to, subject, text, files=None, server="relay.ia55.net"):
    """
    Function to send email with given details. We use SMTP library for sending email

    Arguments:
            send_from (string): from mailing address
            send_to (list): list of mailing addresses to whom this mail should be sent
            subject (string): subject of mail
            text (string): contents of body of mail
            files (list): lsit of file names which should be attached to the mail
            server (string): the server which should be used for sending mail
                             Defaults to 'realay.ia55.net'

    Examples:
            self.send_email(send_from='kokkanti@arcesium.com', send_to=['kokkanti@arcesium.com'],
            subject='Test mail', text='this is test mail', files=['abc.txt','123.sql'])
    Raises:
            Any exception while sending email
    """
    if files is None:
        files = []
    assert type(send_to) == list
    assert type(files) == list

    message            = MIMEMultipart()
    message['From']    = send_from
    message['To']      = COMMASPACE.join(send_to)
    message['Date']    = formatdate(localtime=True)
    message['Subject'] = subject

    message.attach(MIMEText(text,'html'))

    for f in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(f, "rb").read())
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        message.attach(part)

    try:
        smtpObj = smtplib.SMTP('relay.ia55.net', 25)
        smtpObj.sendmail(message['From'], message['To'], message.as_string())
        smtpObj.close()

    except Exception as e:
        logger.error("Unable to send email with error : str(e)")
        raise Exception("Unable to send email")


def get_snowflake_connection(account, username, password):
    """
    PURPOSE:
        Create Snowflake connection for account
    INPUTS:
        account(<account>.<region>.privatelink) , username , password
    RETURNS:
        returns connection, cursor
    """
    retry_count = 0
    while retry_count < DB_RETRY_COUNT:
        try:
            connection = snowflake.connector.connect(
                account=account,
                user=username,
                password=password,
                insecure_mode=True
            )
            cursor = connection.cursor()
            cursor.execute("use role accountadmin")
            cursor.execute("use warehouse DBA_WH")
            cursor.execute("use database SNOWFLAKE")
            connection.autocommit(True)
            return connection, cursor
        except Exception as e:
            logger.error("Failed to create connection to account : {} with error {}".format(account, e))
            retry_count += 1
            time.sleep(DB_WAIT_TIME)
            logger.info("trying again to connect to the account {}, re-try count : {}".format(account, retry_count))
            raise Exception("Failed to create connection to account : {} with error {}".format(account, e))


def parse_arguments():
    parser = argparse.ArgumentParser(add_help=True, description='example : sudo -u sqlexec /g/dba/virtualenv/python3/bin/python snowflake_cost_report.py --From 03-01-2021 -To 03-31-2021')
    parser.add_argument("-F", "--From",dest="from", default='', help="source pod to copy database",required=True)
    parser.add_argument('-T', '--To',dest='to', default='none',help='destination pod to restore database', required=True)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    return parser.parse_args()


def main():
    # get connection to DBA account
    password = vaultutil.get_user_password('/secret/v2/snowflake/dba/db/admin')
    password = json.loads(password)['password']
    conn , cur = get_snowflake_connection('ARC5008.us-east-1','admin',password)
    query1 = """
    WITH T as (select us.ACCOUNT_NAME,upper(acc.pod) as POD,MONTHNAME(DATE_TRUNC('MONTH',USAGE_DATE))||'_'||YEAR(DATE_TRUNC('MONTH',USAGE_DATE)) as MONTH,round(sum(USAGE_IN_CURRENCY)) as COST
    from SNOWFLAKE.ORGANIZATION_USAGE.USAGE_IN_CURRENCY_DAILY as us LEFT JOIN audit_archive.public.ACCOUNT_POD_MAPPING acc on (upper(acc.ACCOUNT_NAME)=upper(us.account_name))
    WHERE usage_date between date_trunc('MONTH', dateadd(month,-7,current_date)) and date_trunc('MONTH', dateadd(month,-1,current_date))
    group by us.ACCOUNT_NAME,DATE_TRUNC('MONTH',USAGE_DATE),upper(acc.pod)
    order by DATE_TRUNC('MONTH',USAGE_DATE) desc)
    """
    result= cur.execute("select 'select * from T pivot (sum(cost) for month in"
                " ('||LISTAGG(''''||MONTHNAME(date_trunc('MONTH',dateadd(month, '-' || seq4()+-1, current_date())))||'_'YEAR(date_trunc('MONTH',dateadd(month, '-' || seq4()+-1, current_date())))||'''',',')||') "
                "order by POD;' as month from table(generator(rowcount => 6))").fetchone()[0]
    query1 = query1 + str(result)
    df = pd.read_sql_query(query1, conn)
    df = df.replace(np.nan, 0)
    html1 = df.to_html(classes='table-width center table-striped table-bordered table-hover table-condensed',index=False)
    query2 = """
    select us.ACCOUNT_NAME,upper(acc.pod) as POD,DATE_TRUNC('MONTH',END_TIME) as USAGE_MONTH,WAREHOUSE_NAME,round(sum(CREDITS_USED),2) as CREDITS_USED
    from SNOWFLAKE.ORGANIZATION_USAGE.PREVIEW_WAREHOUSE_METERING_HISTORY as us LEFT JOIN audit_archive.public.ACCOUNT_POD_MAPPING acc on (upper(acc.ACCOUNT_NAME)=upper(us.account_name))
    where DATE_TRUNC('MONTH',END_TIME)='2021-03-01'
    group by us.ACCOUNT_NAME,upper(acc.pod),DATE_TRUNC('MONTH',END_TIME),WAREHOUSE_NAME
    order by pod
    """
    df = pd.read_sql_query(query2, conn)
    df = df.replace(np.nan, 0)
    html2 = df.to_html(classes='table-width center table-striped table-bordered table-hover table-condensed',index=False)

    header = """<h1 style="color:darkblue;text-align:center">Snowflake Cost utilization report</h1>"""
    first_table_header = """<h3 style="color:darkblue;">Account level utilization</h3>"""
    second_table_header = """<h3 style="color:darkblue;">Warehouse level utilization</h3>"""
    html = STYLING + header + "<br><br>" + first_table_header + "<br>" + html1 + "<br><br>" + second_table_header + "<br>" + html2
    print(html)
    send_mail(
        send_from='sqlexec@deshaw.com',
        send_to=['oguri@arcesium.com'],
        subject='Snowflake cost utilization report',
        text=html
    )


if __name__ == "__main__":
    main()
