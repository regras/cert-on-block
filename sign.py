import os
import logging
import json

import tx

import ethereum.utils as eth


def sign_data(data, key):
    data_hash = eth.sha3(data)
    key_bytes = eth.normalize_key(key)
    sig = eth.ecsign(data_hash, key_bytes)
    logging.debug('Signature created: {0}'.format(sig))

    return sig


def verify_sig(data, sig, trusted_addrs):
    data_hash = eth.sha3(data)
    sig_pubkey = eth.ecrecover_to_pub(data_hash, sig[0], sig[1], sig[2])
    addr = '0x' + eth.encode_hex(eth.sha3(sig_pubkey)[12:])

    cert = tx.get_cert_from_address(addr, trusted_addrs)
    if cert is None:
        logging.info('No certificate found on address {0}. Invalid '
                     'signature'.format(addr))
    else:
        if cert.status == 'valid':
            logging.info('The signature is valid.')
        else:
            logging.info('The signature is invalid.')

        logging.info('Certificate status: {}'.format(cert.status))
        logging.info('Certificate data: {}'.format(cert.data))


def sign_file(file_name, key):
    sig = ''
    if not os.path.isfile(file_name):
        logging.error("File {0} does not exist".format(file_name))
        return False

    with open(file_name, 'rb') as f:
        text = f.read()
        sig = sign_data(text, key)

    dirname, basename = os.path.split(file_name)
    name = os.path.splitext(basename)[0]

    sig_file_name = dirname + os.path.sep + name + '.sig'
    if os.path.isfile(sig_file_name):
        logging.error("File {0} already exists.".format(sig_file_name))
        return False

    with open(sig_file_name, 'w') as f:
        f.write(json.dumps(sig))
        logging.info("Signature file '{0}' created.".format(sig_file_name))

    return True


def verify_file_sig(file_name, sig_file_name, address):
    data = ''
    if not os.path.isfile(file_name):
        logging.error("File {0} does not exist".format(file_name))
        return False

    with open(file_name, 'rb') as f:
        data = f.read()

    logging.debug('Read data as: {0}'.format(data))

    sig = ''
    if not os.path.isfile(sig_file_name):
        logging.error("File {0} does not exist".format(sig_file_name))
        return False

    with open(sig_file_name) as f:
        sig = json.loads(f.read())

    logging.debug('Read signature as: v:{0}, r:{1}, s:{2}'.format(sig[0],
                  sig[1], sig[2]))

    return verify_sig(data, sig, address)
