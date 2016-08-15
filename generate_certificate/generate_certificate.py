#!/usr/bin/env python

"""
Create a Let's Encrypt Certificate

Usage:
  generate_certificate.py <configuration>

where configuration is a configuration-file created with create_key.py.

Options:
  -h, --help    this help
"""

from contextlib import contextmanager
from functools import partial
import json
import logging

import OpenSSL

from acme import challenges
from acme import client
from acme import messages
from acme import jose
from docopt import docopt
from gcloud import datastore
from oauth2client.service_account import ServiceAccountCredentials


__version__ = '1.0'


logging.basicConfig(level=logging.INFO)

DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
# DIRECTORY_URL = 'https://acme-v01.api.letsencrypt.org/directory'


class ACMEClient(object):
    def __init__(self, directory, account_key):
        self.client = client.Client(directory, jose.JWKRSA.load(account_key))

    def check_registration(self, email=None):
        try:
            regr = self.client.register(messages.NewRegistration.from_data(email=email))
            logging.info('Registered new account')
            logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
            self.client.agree_to_tos(regr)
        except messages.Error as e:
            if 'already in use' not in e.detail:
                raise
            logging.info('Using existing account')

    def generate_certificate(self, domains, solver):
        if not domains:
            raise ValueError('no domains to verify')

        authzrs = [self.client.request_challenges(
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain),
            new_authzr_uri=self.client.directory.new_authz) for domain in domains]

        for authzr in authzrs:
            supported_challenges = [
                authzr.body.challenges[c[0]]
                for c in authzr.body.combinations
                if len(c) == 1 and
                isinstance(authzr.body.challenges[c[0]].chall, challenges.HTTP01)]

            if not supported_challenges:
                raise TypeError('No supported challenge returned from directory '
                                'for `{}`'.format(authzr.body.identifier.value))

            challenge = supported_challenges[0]
            key = challenge.path.replace('/{}/'.format(challenge.URI_ROOT_PATH), '')
            response, validation = challenge.response_and_validation(self.client.key)

            with solver(key, validation):
                verified = response.simple_verify(
                    challenge.chall, authzr.body.identifier.value, self.client.key.public_key())

                if not verified:
                    raise ValueError('Failed to test validation of '
                                     '`{}`'.format(authzr.body.identifier.value))

                self.client.answer_challenge(challenge, response)

        certificate_key = OpenSSL.crypto.PKey()
        certificate_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        certificate_request = OpenSSL.crypto.X509Req()
        certificate_request.get_subject().CN = domains[0]

        certificate_request.add_extensions([
            OpenSSL.crypto.X509Extension(
                b'subjectAltName',
                critical=False,
                value=b', '.join('DNS: {}'.format(d).encode('utf-8') for d in domains)
            )
        ])
        certificate_request.set_pubkey(certificate_key)
        certificate_request.set_version(2)
        certificate_request.sign(certificate_key, 'sha256')

        certificate, _ = self.client.poll_and_request_issuance(
            jose.ComparableX509(certificate_request), authzrs,
            max_attempts=(10 * len(authzrs)))

        certificate_chain = self.client.fetch_chain(certificate)
        return certificate.body.wrapped, certificate_chain, certificate_key


class Datastore(object):
    def __init__(self, credentials):
        self.client = datastore.client.Client(
            project=credentials['project_id'],
            credentials=ServiceAccountCredentials.from_json_keyfile_dict(credentials))

    def put(self, challenge, response):
        entity = datastore.Entity(self.client.key('ACMEChallengeResponse'))
        entity['challenge'] = challenge
        entity['response'] = response
        self.client.put(entity)

    def delete(self, challenge):
        result = list(self.client.query(
            kind='ACMEChallengeResponse', filters=[('challenge', '=', challenge)]).fetch(1))
        if result:
            self.client.delete(result[0].key)
        else:
            logging.warn("tried to delete challenge `{}`, but couldn't find it")


@contextmanager
def solve_challenge(datastore, key, validation):
    datastore.put(key, validation)
    try:
        yield
    finally:
        datastore.delete(key)


if __name__ == '__main__':
    arguments = docopt(__doc__, version=__version__)

    with open(arguments['<configuration>']) as file_:
        configuration = json.load(file_)

    acme = ACMEClient(DIRECTORY_URL, configuration['acme_account_key'].encode('utf-8'))
    acme.check_registration(configuration['email'])

    storage = Datastore(configuration['google_credentials'])

    certificate, certificate_chain, certificate_key = acme.generate_certificate(
        configuration['domains'], partial(solve_challenge, storage))

    print(OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, certificate).decode('utf-8'))

    for certificate in certificate_chain:
        print(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, certificate).decode('utf-8'))

    print(OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, certificate_key).decode('utf-8'))
