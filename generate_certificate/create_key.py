#!/usr/bin/env python

"""
Create configuration and keys for Let's Encrypt certificate generator

Usage:
  create_key.py [--email=<email>] --google-credentials=<google_credentials> <domain>...

where <domain> is one or more domains to create the certificate for.

Options:
  -h, --help                                this help
  --email=<email>                           email-address to register with at
                                            Let's Encrypt
  --google-credentials=<google_credentials> file with credentials of a service-
                                            account allowed to access Cloud
                                            Datastore for the project
"""

from docopt import docopt
import json
import OpenSSL


__version__ = '1.0'


def generate_configuration(email, google_credentials, domains):
    acme_key = OpenSSL.crypto.PKey()
    acme_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    acme_key = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, acme_key).decode('utf-8')

    with open(google_credentials) as file_:
        google_credentials = json.load(file_)

    return {
        'email': email,
        'acme_account_key': acme_key,
        'google_credentials': google_credentials,
        'domains': domains
    }

if __name__ == '__main__':
    arguments = docopt(__doc__, version=__version__)
    configuration = generate_configuration(
        arguments['--email'], arguments['--google-credentials'], arguments['<domain>'])
    print(json.dumps(configuration, indent=2))
