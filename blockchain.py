import requests
import logging
import json

GASPRICE = 32000000000
GASLIMIT = 500000

def get_address_nonce(address):
    query_url = 'https://rinkeby.etherscan.io/api?module=proxy&action=eth_getTransactionCount'
    query_url += '&address={0}&tag=latest'.format(address)
    response = requests.post(query_url)
    logging.debug('Got response from address nonce query: {0}'.format(response.text))

    if response.status_code == requests.codes.ok:
        nonce_hex = response.json().get('result', None)
        return int(nonce_hex, 16)
    return None


def get_transactions_on_address(address):
    query_url = 'http://rinkeby.etherscan.io/api?module=account&action=txlist'
    query_url += '&address={0}&startblock=0&endblock=99999999&sort=asc'.format(address)

    response = requests.post(query_url)
    logging.debug('Got response from address nonce query: {0}'.format(response.text))

    if response.status_code == requests.codes.ok:
        txs = response.json().get('result', None)
        return txs
