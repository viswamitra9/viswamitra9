import json
import logging
import requests
from requests_kerberos import HTTPKerberosAuth
from retrying import retry

logger = logging.getLogger('__name__')


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_user_password(vaultpath):
    """
    PURPOSE:
        Read secret from vault. Secret format is {'account':account,'password':password,'database':dbname}
        account format is : 'account.<region>.privatelink'
        It is expected that vault read may fail, so retry for 10 times with delay of 10 sec in each run.
    INPUTS:
        vaultpath
    RETURNS:
        returns secret
    """
    try:
        vaultpath_req = "http://vault.ia55.net/v1{}".format(vaultpath)
        response = requests.get(vaultpath_req,auth=HTTPKerberosAuth())
        if response:
            passwd = response.json()['data']['secret']
            return passwd
        else:
            logging.error("Failed to retrieve credentials from {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to retrieve credentials from {} with error {}".format(vaultpath,response.content))
    except Exception as e:
        logging.error("Failed to retrieve credentials from {} with error {}, trying again".format(vaultpath,str(e)))
        raise Exception("Failed to retrieve credentials from {} with error {}".format(vaultpath, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def write_secret_to_vault(vaultpath,secret):
    try:
        vaultpath_req = "http://vault.ia55.net/v1"+vaultpath
        response = requests.post(vaultpath_req, auth=HTTPKerberosAuth(), json={'secret': secret})
        if response:
            logging.info("Credentials written successfully to {}".format(vaultpath))
        else:
            logging.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath,response.content))
    except Exception as e:
        logging.error("Failed to write credentials to {} with error {}, trying again".format(vaultpath, str(e)))
        raise Exception("Failed to write credentials to {} with error {}, trying again".format(vaultpath, str(e)))


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def delete_secret_from_vault(vaultpath):
    try:
        vaultpath_req = "http://vault.ia55.net/v1"+vaultpath
        response = requests.delete(vaultpath_req, auth=HTTPKerberosAuth())
        if response:
            logger.info("Credentials deleted successfully from {}".format(vaultpath))
        else:
            logger.error("Failed to delete credentials from {} with error {}, trying again".format(vaultpath,response.content))
            raise Exception("Failed to delete credentials from {} with error {}, trying again".format(vaultpath,response.content))
    except Exception as e:
        logger.error("Failed to delete credentials from {} with error {}, trying again".format(vaultpath, str(e)))
        raise Exception("Failed to delete credentials from {} with error {}, trying again".format(vaultpath, str(e)))
