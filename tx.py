from ethereum.transactions import Transaction
from ethereum.utils import encode_hex, decode_hex, normalize_address
import requests
import rlp
import json
import logging
from datetime import datetime

import cert
import blockchain

def create_transaction(nonce, gasprice, gaslimit, to, value, data):
    tx = Transaction(nonce, gasprice, gaslimit, to, value, data)
    logging.debug("Created transaction: {0}".format(tx.to_dict()))
    return tx


def sign_transaction(tx, key):
    signed_tx = tx.sign(key)
    logging.debug("Signed transaction: {0}".format(signed_tx.to_dict()))
    return signed_tx


def send_transaction(tx):
    tx_hex = encode_hex(rlp.encode(tx))
    broadcast_url = "https://rinkeby.etherscan.io/api?module=proxy&action=eth_sendRawTransaction"

    response = requests.post(broadcast_url, data={'hex': tx_hex})
    response_json = json.loads(response.text)
    logging.debug("Got the following response from POST: {0}".format(response.text))

    if response.status_code == requests.codes.ok:
        tx_id = response.json().get('result', None)
        if tx_id:
            logging.info("Transaction accepted by blockchain with hash: '{0}'".format(tx_id))
        else:
            error_message = response_json['error']['message']
            logging.error("Transaction rejected. Got the error '{0}'".format(error_message))
        return tx_id
    return None


def get_trusted_transactions(addr, trusted_addresses):
    txs = blockchain.get_transactions_on_address(addr)
    trusted_txs = []
    norm_trusted_addresses = []
    for address in trusted_addresses:
        norm_trusted_addresses.append(normalize_address(address))

    for tx in txs:
        if normalize_address(tx['from']) in norm_trusted_addresses:
            trusted_txs.append(tx)

    return trusted_txs


def get_cert_from_address(addr, trusted_addresses):
    trusted_txs = get_trusted_transactions(addr, trusted_addresses)
    for tx in trusted_txs:
        op_code = int(tx['value'])
        if op_code == cert.OPCODE_ISSUE:
            hex_data = tx['input'][2:]
            bdata = decode_hex(hex_data)
            data = bdata.decode()
            try:
                data_dict = json.loads(data)
            except Exception:
                logging.warning("Transaction of hash '{0}' has invalid data. "
                                "Skipping.".format(tx['hash']))
                continue
            certificate = cert.Cert(data_dict)
            logging.debug("Data dictionary is: '{0}'".format(data_dict))

            not_before = datetime.strptime(data_dict['Validity']['Not Before'],
                                           cert.date_format)
            not_after = datetime.strptime(data_dict['Validity']['Not After'],
                                          cert.date_format)
            now = datetime.now()
            if now < not_before or now > not_after:
                certificate.status = 'expired'
        elif op_code == cert.OPCODE_REVOKE:
            certificate.status = 'revoken'
    return certificate
