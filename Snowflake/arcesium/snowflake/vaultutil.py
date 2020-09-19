import subprocess
import logging
import time

logger = logging.getLogger('__name__')

sleep_time = 10

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
    retry_count = 0
    try:
        while retry_count <= 10:
            command = "vault read -field=secret {}".format(vaultpath)
            pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            # initial password string i_pass
            i_pass, error = pipes.communicate()
            if pipes.returncode == 0:
                password = i_pass.decode('utf-8')
                command = "echo '{}' | grep -v 'Could not get working directory' | tr -d '\\n'".format(str(password))
                pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                password, err = pipes.communicate()
                return str(password.decode('utf-8'))
            elif pipes.returncode == 2:
                password = i_pass.decode('utf-8')
                command = "echo '{}' | grep -v 'Could not get working directory' | tr -d '\\n'".format(str(password))
                pipes = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                password, error = pipes.communicate()
                return str(password.decode('utf-8'))
            else:
                logger.warning(
                    "Error while reading vault path {},reading again : {} attempt".format(vaultpath, retry_count))
                time.sleep(sleep_time)
                retry_count = retry_count + 1
                continue
        return 1
    except Exception as e:
        logger.exception("Exception while reading from vault {}".format(str(e)))
        logger.error("Failed to read secret from vault : {} with error : {}".format(vaultpath, e))
        raise Exception("Failed to read secret from vault : {} with error : {}".format(vaultpath, e))


def write_secret_to_vault(vaultpath,secret):
    """
    PURPOSE:
        Write secret to vault. Secret format is {'account':account,'password':password,'database':dbname}
        account format is : 'account.<region>.privatelink'
        It is expected that vault read may fail, so retry for 10 times with delay of 10 sec in each run.
    INPUTS:
        vaultpath, secret
    """
    try:
        # Retry count variable
        retry_count = 0
        # error variable to store error message
        error = ''
        while retry_count <= 10:
            command = "vault write {} secret=\'{}\'".format(vaultpath, secret)
            writetovault = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            (output, error) = writetovault.communicate()
            if writetovault.returncode == 0:
                logger.info("Password written successfully to vault path {}".format(vaultpath))
                return
            else:
                retry_count = retry_count + 1
                logger.warning(
                    "Error while writing password to vault path {}, retrying : {} attempt".format(vaultpath, retry_count))
                time.sleep(sleep_time)
        logger.error("Error occurred while writing to vault {}, error : {}".format(vaultpath, str(error)))
        exit(1)
    except Exception as e:
        logger.error("Failed to write secret to vault : {} with error : {}".format(vaultpath, e))
        logger.exception("Exception while writing to vault {}".format(str(e)))
        raise Exception("Failed to write secret to vault : {} with error : {}".format(vaultpath, e))


def delete_secret_from_vault(vaultpath):
    """
    PURPOSE:
        delete vault entry for given user
    INPUTS:
        vaultpath, secret
    """
    try:
        # Retry count variable
        retry_count = 0
        # error variable to store error message
        error = ''
        while retry_count <= 10:
            command = "vault delete {}".format(vaultpath)
            writetovault = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            (output, error) = writetovault.communicate()
            if writetovault.returncode == 0:
                logger.info("secret deleted successfully to vault path {}".format(vaultpath))
                return
            else:
                retry_count = retry_count + 1
                logger.warning(
                    "Error while deleting secret from vault path {}, "
                    "retrying : {} attempt".format(vaultpath, retry_count))
                time.sleep(sleep_time)
        logger.error("Error occurred while deleting secret from vault {}, error : {}".format(vaultpath, str(error)))
        exit(1)
    except Exception as e:
        logger.error("Failed to delete secret from vault : {} with error : {}".format(vaultpath, e))
        logger.exception("Exception while deleting secret from vault {}".format(str(e)))
        raise Exception("Failed to delete secret from vault : {} with error : {}".format(vaultpath, e))