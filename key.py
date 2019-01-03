import ethereum.utils as eth
import ethereum.tools.keys as ethkeys
import os
import sys
import logging
import json
import getpass
import secrets


def create_private_key(output_file):
    password = ''
    password2 = ' '
    while password != password2:
        password = getpass.getpass('Type the password: ')
        password2 = getpass.getpass('Retype the password: ')
    priv = secrets.randbits(256)
    logging.debug('Private key generated: {}'.format(priv))
    logging.info('Private key succesfully generated.')
    addr = eth.privtoaddr(priv)
    logging.info("The generated address is '{}'".format('0x' + eth.encode_hex(
        addr)))
    store_private_key(priv, password, output_file)


def store_private_key(key, password, output_file):
    bkey = eth.normalize_key(key)

    keystore_json = ethkeys.make_keystore_json(bkey, password, kdf='pbkdf2',
                                               cipher='aes-128-ctr')
    keystore_json['id'] = keystore_json['id'].decode('utf8')
    logging.debug(keystore_json)
    if not os.path.isfile(output_file):
        with open(output_file, 'w') as f:
            json.dump(keystore_json, f)
            logging.info("Private key succesfully stored on file '{}'.".format(
                output_file))
    else:
        logging.error('Keystore file already present! Aborting')


def retrieve_private_key(password, key_file):
    if os.path.isfile(key_file):
        with open(key_file) as f:
            try:
                keystore_json = json.load(f)
                keystore_json['id'] = keystore_json['id']
                key = ethkeys.decode_keystore_json(keystore_json, password)
                if not key:
                    raise Exception
                return key
            except Exception:
                logging.error('Error retrieving private key.')
                sys.exit()
    else:
        logging.error("Keystore file '{}' inexistent.".format(key_file))
        sys.exit()


def get_private_key(key_file):
    password = getpass.getpass('Please enter the private key password: ')
    return retrieve_private_key(password, key_file)
