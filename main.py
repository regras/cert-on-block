#!/usr/bin/env python3

import argparse
import os
import logging
import configparser

import cert
import sign
import tx
import key

# @TODO -- have 'parser' module for parsing the args, and that calls
# 'functions' # module, which executes the possible functions of the program
# @TODO -- show when cert is included in blockchain

# @TODO -- see about parameter used by on-block cert for tx creation that
# impedes replay attacks

# @TODO use decent values for gas constants
# @TODO check config/parameters for all subcommands


def getConfig(config_file):
    if config_file:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config


def get_key_file(config):
    if args.key_file:
        return args.key_file
    else:
        if config:
            try:
                return config['ETC']['KeystoreFile']
            except Exception:
                return None


def func_issue(config):
    if args.key_file:
        key_file = args.key_file
    elif config and config['ETC'] and config['ETC']['KeystoreFile']:
        key_file = config['ETC']['KeystoreFile']
    else:
        logging.error('No keystore file definition found as parameter or on '
                      'config file!')
        return

    if args.address:
        #if args.x509_file:  # @TODO really implement x509 import or remove it
            #if os.path.isfile(args.x509_file):
                #with open(args.x509_file) as f:
                    #cert.issue_cert(args.address, f.read(), key_file, config)
            #else:
                #logging.error("File '{0}' not found")
        #else:
            cert.issue_cert(args.address, None, key_file, config)
    else:
        logging.error('Address is missing')


def func_sign(config):
    key_file = get_key_file(config)
    if key_file is None:
        logging.error('No keystore file definition found as parameter or on '
                      'config file!')
    else:
        priv_key = key.get_private_key(key_file)
        sign.sign_file(args.data_file, priv_key)


def func_check_signature(config):
    if config and config['ETC'] and config['ETC']['caAddresses']:
        ca_addresses = config['ETC']['caAddresses'].split(';')
    else:
        logging.error('No CA addresses definition found as parameter or on '
                      'config file!')
        return
    sign.verify_file_sig(args.data_file, args.sig_file, ca_addresses)
    return None


def func_get_cert(config):
    if config and config['ETC'] and config['ETC']['caAddresses']:
        ca_addresses = config['ETC']['caAddresses'].split(';')
    else:
        logging.error('No CA addresses definition found as parameter or on '
                      'config file!')
        return
    certificate = tx.get_cert_from_address(args.address, ca_addresses)
    if certificate:
        logging.info('Certificate status: {0}'.format(certificate.status))
        logging.info('Certificate data: {0}'.format(certificate.data))
    else:
        logging.warning("The given address doesn't contain a valid "
                        "certificate")


def func_revoke_cert(config):
    key_file = get_key_file(config)
    if key_file is None:
        logging.error('No keystore file definition found as parameter or on '
                      'config file!')
    else:
        priv_key = key.get_private_key(key_file)
        cert.revoke_cert(args.address, priv_key)


def func_gen_keys(config):
    key.create_private_key(args.priv_file)


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help='sub-command help')

# issue subcommand
parser_issue = subparsers.add_parser('issue',
                                     help='issues a new certificate on the '
                                          'blockchain')
parser_issue.add_argument('--address', dest='address', action='store',
                          required=True,
                          help='the address on the blockchain that is used as '
                               'the target for the commands')
parser_issue.add_argument('--key-file', dest='key_file', action='store')
#parser_issue.add_argument('--import-x509', dest='x509_file', action='store')
parser_issue.add_argument('--config', dest='config_file', action='store',
                          help='')
parser_issue.set_defaults(func=func_issue)

# sign subcommand
parser_sign = subparsers.add_parser('sign',
                                    help='signs a message with ECDSA using '
                                         'the private key')
parser_sign.add_argument('--file', dest='data_file', action='store',
                         required=True)
parser_sign.add_argument('--key-file', dest='key_file', action='store')
parser_sign.add_argument('--config', dest='config_file', action='store',
                          help='')
parser_sign.set_defaults(func=func_sign)

# check-sig subcommand
parser_checksig = subparsers.add_parser('check-sig',
                                        help='checks if a given signature is '
                                             'valid')
parser_checksig.add_argument('--file', dest='data_file', action='store',
                             required=True)
parser_checksig.add_argument('--sig-file', dest='sig_file', action='store',
                             required=True)
parser_checksig.add_argument('--config', dest='config_file', action='store',
                          help='')
parser_checksig.set_defaults(func=func_check_signature)

# get-cert subcommand
parser_getcert = subparsers.add_parser('get-cert',
                                       help='retrieves a certificate from '
                                            'the given address from the '
                                            'blockchain along with its status'
                                       )
parser_getcert.add_argument('--address', dest='address', action='store',
                            required=True,
                            help='the address on the blockchain that is used '
                                 'as the target for the commands')
parser_getcert.add_argument('--config', dest='config_file', action='store',
                          help='')
parser_getcert.set_defaults(func=func_get_cert)

# revoke-cert subcommand
parser_revokecert = subparsers.add_parser('revoke-cert',
                                          help='updates the certificate of a '
                                               'given address to be revoken '
                                               'and no longer valid')
parser_revokecert.add_argument('--address', dest='address', action='store',
                               required=True,
                               help='the address on the blockchain that is '
                                    'used as the target for the commands')
parser_revokecert.add_argument('--key-file', dest='key_file', action='store')
parser_revokecert.add_argument('--config', dest='config_file', action='store',
                          help='')
parser_revokecert.set_defaults(func=func_revoke_cert)

# gen-keys subcommand
parser_genkeys = subparsers.add_parser('gen-keys',
                                       help='')
parser_genkeys.add_argument('--output-file', dest='priv_file', action='store',
                            required=True,
                            help='')
parser_genkeys.set_defaults(func=func_gen_keys)


# @TODO -- maybe add suport for pubkey??
# p.add_argument('--pubkey', dest='pubkey', action='store')

logging.basicConfig(level=logging.INFO,
                    format=' %(asctime)s - %(levelname)s - %(message)s')

args = parser.parse_args()

if not any(vars(args).values()):
    parser.error('No sub-command provided.')

config = getConfig(args.config_file)
args.func(config)
