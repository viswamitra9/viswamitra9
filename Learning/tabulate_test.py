import sys
from cryptography.fernet import Fernet

try:
    # encrypting
    password = 'Tejpass'
    key = Fernet.generate_key()
    print("key is ",key)
    f = Fernet(key)
    token = f.encrypt(password.encode('utf-8'))
    print ("ENC("+token.decode(encoding='UTF-8')+")")
    print('encrypted: {0}'.format(token))
    # decrypting
    f = Fernet(key)
    output = f.decrypt(token)
    output_decoded = output.decode('utf-8')
    print('decrypted: {0}'.format(output_decoded))
except Exception as e:
    print("test failed : ", str(e))