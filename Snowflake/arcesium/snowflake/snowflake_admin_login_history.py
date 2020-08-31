import argparse
import snowflake.connector
from snowflake.connector.secret_detector import SecretDetector
import logging
from datetime import datetime
import pyodbc
from tabulate import tabulate
# packages to send email

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from smtpd import COMMASPACE
from email.mime.base import MIMEBase
import os
import email.encoders as Encoders
import smtplib
#from arcesium.radar.client import SendAlertRequest
#from arcesium.radar.client import RadarService
import sys
sys.path.append('/g/dba/oguri/dba/snowflake/')
import vaultutil

logger = logging.getLogger()
logfile = '/g/dba/logs/snowflake/snowflake_login_history_{}.log'.format(datetime.now().strftime("%d-%b-%Y-%H-%M-%S"))


def set_logging():
    print("Check logfile {} for any errors".format(logfile))
    # default log level for root handler
    logger.setLevel(logging.INFO)
    # creating file handler
    ch = logging.FileHandler(logfile)
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


def raise_radar_alert(alert_description):
    request = SendAlertRequest()
    request.alert_source      = 'dba'
    request.alert_key         = 'PostgreSQL-Generate-Snapshot-Failure'
    request.alert_summary     = 'PostgreSQL snapshot generation failure for production instances'
    request.alert_class       = 'PAGE'
    request.alert_description = alert_description + " Please check the {} file " \
            "for details and reference the {} documentation " \
            "for more information.".format(logfile,'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots')
    request.alert_severity    = 'CRITICAL'
    request.alertKB           = 'http://wiki.ia55.net/display/TECHDOCS/PostgreSQL+RDS+Snapshots'
    service = RadarService()
    try:
        logger.error(request.alert_description)
        print(service.publish_alert(request, radar_domain='prod'))
    except Exception as err:
        logger.error("Error occurred while raising radar alert {}".format(str(err)))

def send_mail(send_from, send_to, subject, text, files=[], server="relay.ia55.net"):
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
            >>> self.send_email(send_from='kokkanti@arcesium.com', send_to=['kokkanti@arcesium.com'], subject='Test mail', text='this is test mail', files=['abc.txt','123.sql'])
    Raises:
            Any excpetion while sending email
    """
    assert type(send_to) == list
    assert type(files) == list

    message = MIMEMultipart()
    message['From'] = send_from
    message['To'] = COMMASPACE.join(send_to)
    message['Date'] = formatdate(localtime=True)
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


def get_snowflake_connection(account, username, password):
    """
    PURPOSE:
        Create Snowflake connection for account
    INPUTS:
        account(<account>.<region>.privatelink) , username , password
    RETURNS:
        returns connection, cursor
    """
    connection = ''
    try:
        connection = snowflake.connector.connect(
            account=account,
            user=username,
            password=password,
            insecure_mode=True,
            autocommit=True
        )
    except Exception as e:
        logger.error("Failed to create connection to account : {} with error {}".format(account, e))
        raise Exception("Failed to create connection to account : {} with error {}".format(account, e))

    cursor = connection.cursor()
    return connection, cursor


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
    try:
        username = 'sa'
        password = vaultutil.get_user_password('/secret/v2/snowflake/{}/db/sa'.format(pod))
        connection, cursor = get_snowflake_connection(account, username, password)
        cursor.execute("create database if not exists audit_archive")
        cursor.execute("use database audit_archive")
        cursor.execute("use schema public")
        logger.info("Checking for dba warehouse and create it if not exists")
        cursor.execute("create warehouse if not exists DBA_WH with WAREHOUSE_SIZE=small")
        cursor.execute("use role accountadmin")
        cursor.execute("use warehouse DBA_WH")
        return connection, cursor
    except Exception as e:
        logger.error("error while creating super user connection to account : {}".format(account))
        exit(1)


def get_login_history(account, pod):
    """
    PURPOSE:
        Create connection to account with admin user.
        Check last 24 hours login history for admin logins
    INPUTS:
        account(<account>.<region>.privatelink) , pod
    RETURNS:
        returns html table of login history
    """
    try:
        html = """
        <html>
        <head>
        <style>
        table, th, td {{ border: 1px solid black; border-collapse: collapse; }}
        th, td {{ padding: 5px; }}
        </style>
        </head>
        <body>
        </br>
        </br>
        {table}
        </br>
        </br>
        </body></html>
        """
        logger.info("collecting data for pod {} account {}".format(pod,account))
        query = "select CURRENT_ACCOUNT()||'.'||current_region()||'.PRIVATELINK' as ACCOUNT,EVENT_TIMESTAMP,USER_NAME,CLIENT_IP,REPORTED_CLIENT_TYPE,FIRST_AUTHENTICATION_FACTOR " \
                "from table(information_schema.login_history(dateadd('day',-1,current_timestamp())," \
                "current_timestamp())) where user_name in ('SA','ADMIN') and REPORTED_CLIENT_TYPE not like '%PYTHON%' " \
                "order by event_timestamp"
        connection, cursor = get_admin_connection(account,pod)
        cursor.execute(query)
        result = cursor.fetchall()
        header = ["ACCOUNT","LOGIN_TIMESTAMP","USER_NAME","CLIENT_IP","CLIENT_APPLICATION","AUTHENTICATION_TYPE"]
        mail_body = ''
        if cursor.rowcount > 0:
            #df = DataFrame(result)
            #df.columns = header
            logger.warning("Found SA/ADMIN logins in {} pod \n".format(pod))
            mail_body += "Found SA/ADMIN logins in {} pod".format(pod)
            # mail_body += str(df)
            # tabulate(tabular_data=result,headers=header,tablefmt='html',missingval='?', stralign='center').encode('utf-8')
            mail_body += html.format(table=tabulate(tabular_data=result,headers=header,tablefmt='html'))
            logger.info(mail_body)
        return str(mail_body)
    except Exception as e:
        raise Exception("Exception while getting login history for account {}".format(account))


def parse_arguments():
    """
    PURPOSE:
        parse input arguments and store the values in variables
    """
    parser = argparse.ArgumentParser(add_help=True)
    # Instances on which task need to be performed
    inst = parser.add_mutually_exclusive_group(required=True)
    inst.add_argument('--pod', dest='pod', help='Provide the pod in which we need gather login history ,'
                                                ' example: balyuat')
    inst.add_argument('--env', dest='env', help='Provide the environment, example: dev/qa/uat/prod/all')
    return parser.parse_args()


def main():
    try:
        args = parse_arguments()
        set_logging()

        instances = {}
        cur_sql_dest, conn_sql_dest = sql_connect()
        if args.pod:
            query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and pod='{}' and IsActive=1".format(args.pod)
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]

        if args.env:
            query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                    "where lower(ServerType)='snowflake' and IsActive=1"
            if args.env != 'all':
                query = "select lower(FriendlyName) as account,lower(pod) from dbainfra.dbo.database_server_inventory " \
                        "where lower(ServerType)='snowflake' and lower(Env)='{}' " \
                        "and IsActive=1".format(str(args.env).lower())
            cur_sql_dest.execute(query)
            result = cur_sql_dest.fetchall()
            for instance in result:
                instances[instance[0]] = instance[1]
        conn_sql_dest.close()

        mail_body = ''
        for account, pod in instances.items():
            mail_body += get_login_history(account, pod)
        sub = "Snowflake sa/admin login report"
        send_mail(send_from="dba-ops@arcesium.com", send_to=["dba-ops-team@arcesium.com"], subject=sub, text=mail_body)
        logger.info("mail sent to team, mail body is : {}".format(mail_body))
    except Exception as ex:
        logger.error("error encountered while getting login history")
        exit(1)
        # raise_radar_alert("Error encountered while getting login history")


if __name__ == "__main__":
    main()
