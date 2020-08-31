# import boto3
import csv
import json

# import boto3 as boto3
import requests
import time
from datetime import datetime, timedelta

current_year_full = datetime.now().strftime('%Y')
current_month = datetime.now().strftime('%m')
current_day = datetime.now().strftime('%d')

csvmx = open("C:\\m_temp\\marchex.csv", 'w')
csvmx.write('Call_Start|Call_Status|Campaign|Call_Result|Duration|Ring_Duration|Account_ID|Account_Name|caller_id|call_url|caller_number' + '\n')
csvmx.close()
time.sleep(4)


def main():
    user = "Joel.furfari@cmg.com"
    password = "welcome8827"
    acct_ids = []
    acct_names = []
    request_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "acct.list",
        "params": [
        ]
    }

    # Make a request to acct.list
    response = send_request(user, password, request_body)
    # Get account id and names
    acct_ids, acct_names = process_acct_list_response(response, acct_ids, acct_names)

    call_ids = []

    for account_id in acct_ids:
        # We might use this parameters if we want to make the dates as dynamic values in request body
        startDate = datetime.now() - timedelta(days=3)
        sd = startDate.strftime('%Y-%m-%d')
        request_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call.search",
            "params": [
                account_id,
                # y,
                {
                    # "start": sd + "T00:00:00-07:00",  # 7DLS/8STD
                    # "end": datetime.now().strftime('%Y-%m-%d') + "T23:59:59-07:00",  # 7DLS/8STD
                    "start": "2020-02-01T00:00:00-07:00",#FullYear-Month-Date
                    "end": "2020-02-15T23:59:59-07:00",#FullYear-Month-Date
                    "include_dna": True,
                    "include_dni_vars": True, "include_high intent": True, "include_department": True,
                    "include_sentiment": True
                }]
        }
        response = send_request_acct(user, password, request_body)
        if response.status_code == 200:
            call_ids = process_call_search_response(response, call_ids, y, row)
        else:
            continue

    # client = boto3.client(
    #     's3'
    # )

    # s3 = boto3.resource('s3')
    # s3.meta.client.upload_file('marchex.csv', 'cmg-datalake-ingest-marchex-dev', current_year_full + '/' +
    # current_month + '/' + current_day + '/' + 'marchex_' + current_year_full + current_month + current_day + '.csv')


def send_request_acct(user, password, request_body):
    endpoint = 'https://api.marchex.io/api/jsonrpc/1'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    ####print (request_body)
    resp = requests.post(endpoint, data=json.dumps(request_body), headers=headers, auth=(user, password))
    return resp


def send_request(user, password, request_body):
    """
    Send the request to Call Analytics JSON-RPC.
    """
    endpoint = endpoint = 'https://api.marchex.io/api/jsonrpc/1'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json', 'Accept-Encoding': '*',
               'Connection': 'keep-alive'}
    resp = requests.post(endpoint, data=json.dumps(request_body), headers=headers, auth=(user, password))
    return resp


def get_callerid_url(user, password, call_id):
   endpoint = endpoint = 'https://api.marchex.io/api/jsonrpc/1'
   headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
   request_body = {
       "jsonrpc": "2.0",
       "id": 1,
       "method": "call.audio.url",
       "params": [
           [call_id],"mp3"
       ]
   }
   resp = requests.post(endpoint, data=json.dumps(request_body), headers=headers, auth=(user, password))
   return resp


def get_caller_number(user, password, call_id):
   endpoint = 'https://api.marchex.io/api/jsonrpc/1'
   headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
   request_body = {
       "jsonrpc": "2.0",
       "id": 1,
       "method": "call.get",
       "params": [
           call_id
       ]
   }
   resp = requests.post(endpoint, data=json.dumps(request_body), headers=headers, auth=(user, password))
   return resp


def process_call_search_response(response, call_ids, y, row):
    call_list = response.json()['result']
    # Format the results for printing
    header_row = '{0:^25}  {1:^18}  {2:^12}  {3:^30}  {4:^24}  {5:^12}  {6:^14}  {7:^18} {8:^30}'
    table_row = '{0:^25}  {1:^18}  {2:^12}  {3:<30}  {4:<24}  {5:>12}  {6:>14}  {7:>18} {8:>30}'
    # print(header_row.format('Call ID', 'Call Status', 'Campaign', 'Call DNA Result', 'Duration', 'Ring Duration', 'Account ID', 'Row'))
    file = open('C:\\m_temp\\marchex.csv', 'a+')
    # std_out = sys.stdout
    # sys.stdout = file
    for call in call_list:
        user = "Joel.furfari@cmg.com"
        password = "welcome8827"
        call_id = call['call_id']
        call_url_response = get_callerid_url(user, password, call_id)
        call_url_result = call_url_response.json()['result']

        try:
            call_url = call_url_result[0]["url"]
        except:
            print("call_id : {} does not have recording".format(call_id))
            call_url = 'none'

        # get caller number
        caller_number_response = get_caller_number(user, password, call_id)
        caller_number_result = caller_number_response.json()['result']["caller_number"]

        # Get a list of call ids to pass to call.audio.url
        call_ids.append(call['call_id'])
        # x = ''.join(row)[-30:]
        # print (call_list)
        x = '|'.join(row)
        # print(row)
        # print(y)
        # print(x)
        z = x.split("|", 1)[1]
        # z = zz.decode().strip()
        # print(table_row.format(str(call['call_start'].encode('utf-8').strip()), str(call['call_status'].encode('utf-8').strip()), str(call['c_name'].encode('utf-8').strip()),
        #                       str(call['dna_class'].encode('utf-8').strip()), call['duration'], call['ring_duration'], str(y), str(z)))
        file.write(str(call['call_start'].encode('utf-8').strip()) + '|' + str(
            call['call_status'].encode('utf-8').strip()) + '|' + str(call['c_name'].encode('utf-8').strip())
                   + '|' + str(call['dna_class'].encode('utf-8').strip()) + '|' + str(call['duration']) + '|' + str(
            call['ring_duration']) + '|' + str(y) + '|' + str(z) + '|' + str(call['call_id']) + '|' + str(call_url) +'|'
                   + str(caller_number_result) + '\n')
    file.close()
    return call_ids


# s3 = boto3.resource('s3')
# s3.meta.client.upload_file('marchex.csv', 'cmg-datalake-ingest-marchex-dev',
#                            current_year_full + '/' + current_month + '/' + current_day + '/' + 'marchex.csv')
#
# the above s3 code is used to land files in s3.

# return call_ids

def process_acct_list_response(response, acct_ids, acct_names):
    """
    Get list of account id and names , write them to account_ids.csv file
    """
    acct_list = response.json()['result']

    header_row = '{0:^18} {1:^12}'
    table_row = '{0:^18} {1:^12}'
    print(header_row.format('Account ID', 'Account Name'))
    # print (acct_list)
    csv = open("account_ids.csv", 'w')
    for acct in acct_list:
        # Get a list of acct ids to pass to call.search
        acct_ids.append(acct['acct'])
        acct_names.append(acct['name'])
        print(table_row.format(str(acct['acct'].split()), str(acct['name'].split())))
        csv.write(str(acct['acct'].encode('utf-8').strip()) + '|' + str(acct['name'].encode('utf-8').strip()) + '\n')
    csv.close()
    return acct_ids, acct_names


def left(y, amount):
    return y[:amount]


if __name__ == '__main__':
    main()