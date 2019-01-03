import tx
import key
import blockchain

import ethereum
import json
from datetime import datetime
from pycoin.serialize import b2h

import logging

date_format = '%Y-%m-%d %H:%M:%S'


class Cert:

    def __init__(self, data):
        self.status = 'valid'
        self.data = data


def issue_cert(address, data, key_file, config):  # TODO -- use safer method, dont send key
    if not data:
        data = create_cert_data(config)

    str_data = json.dumps(data, indent=4)
    priv_key = key.get_private_key(key_file)
    if priv_key is None:
        return
    logging.debug("Priv key: '{}'".format(priv_key))
    ca_addr = b2h(ethereum.utils.privtoaddr(priv_key))  # TODO -- use from config
    logging.debug("Address: '{}'".format(ca_addr))
    nonce = blockchain.get_address_nonce(ca_addr)
    logging.debug("Nonce: '{}'".format(nonce))
    if nonce is None:
        logging.error("Unable to get nonce. Aborting")
        return None
    gasprice = blockchain.GASPRICE
    gaslimit = blockchain.GASLIMIT
    bdata = str.encode(str_data)
    value = 0 # TODO -- use a const
    t = tx.create_transaction(nonce, gasprice, gaslimit, address, value, bdata)
    signed_tx = tx.sign_transaction(t, priv_key)
    tx_hash = tx.send_transaction(signed_tx)
    if tx_hash:
        logging.info("On-block cert created succesfully on the transaction with hash '{0}' with the following data '{1}'".format(tx_hash, data))
    else:
        logging.error('On-block cert could not be created.')

    return tx_hash


def create_cert_data(config):
    ans = input("Enter the 'Not Before' date in the format 'YYYY-MM-DD hh:mm:ss' (blank for current time): ")
    if ans:
        before_date = datetime.strptime(ans, date_format)
    else:
        before_date = datetime.now()
    ans = input("Enter the 'Not After' date in the format 'YYYY-MM-DD hh:mm:ss': ")
    after_date = datetime.strptime(ans, date_format)

    print("Now enter the following info for the user: ")
    #cert_fields = config['Certificate']['UserInfoFields'].split(';')
    #fields = []
    #for field in cert_fields:

    country = input("Enter the 'Country' for the user: ")
    state = input("Enter the 'State' for the user: ")
    location = input("Enter the 'Location' for the user: ")
    organization = input("Enter the 'Organization' for the user: ")
    organization_unit = input("Enter the 'Organization Unit' for the user: ")
    common_name = input("Enter the 'Common Name' for the user: ")
    email_address = input("Enter the 'Email address' for the user: ")

    if config['CA']:
        ca_config = config['CA']

    cert_data = {
            'Issuer':   {'C': ca_config['Country'], 'ST': ca_config['State'],
                         'O': ca_config['Organization'], 'OU':
                         ca_config['OrganizationUnit'], 'CN':
                         ca_config['CommonName']},
            'Validity': {'Not Before': before_date.strftime(date_format),
                         'Not After': after_date.strftime(date_format)},
            'Subject':  {'C': country, 'ST': state, 'L': location,
                         'O': organization, 'OU': organization_unit,
                         'CN': common_name, 'emailAddress': email_address}
            }
    return cert_data


def revoke_cert(address, key):
    ca_addr = b2h(ethereum.utils.privtoaddr(key))  # @TODO -- change to use from
    # a secret manager
    nonce = blockchain.get_address_nonce(ca_addr)
    logging.debug('Nonce is {0}'.format(nonce))
    if not nonce:
        logging.error("Unable to get nonce. Aborting")
        return None
    gasprice = blockchain.GASPRICE
    gaslimit = blockchain.GASLIMIT
    bdata = str.encode('')
    value = 1
    t = tx.create_transaction(nonce, gasprice, gaslimit, address, value, bdata)
    signed_tx = tx.sign_transaction(t, key)
    tx_hash = tx.send_transaction(signed_tx)
    if tx_hash:
        logging.info("On-block cert succesfully revoked on the transaction "
                     "with hash '{0}'".format(tx_hash))
    else:
        logging.error('Revocation unsuccesful.')

    return tx_hash
