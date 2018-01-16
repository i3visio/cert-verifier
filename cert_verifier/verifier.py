"""
Verify blockchain certificates (http://www.blockcerts.org/)

Overview of verification steps
- Check integrity: TODO: json-ld normalizatio
- Check signature (pre-v2)
- Check whether revoked
- Check whether expired
- Check authenticity

"""

import argparse
import json
import pkg_resources

from cert_core import to_certificate_model
from cert_verifier import connectors
from cert_verifier.checks import create_verification_steps
import sys


def verify_certificate(certificate_model, options={}):
    # lookup issuer-hosted information
    issuer_info = connectors.get_issuer_info(certificate_model)

    # lookup transaction information
    connector = connectors.createTransactionLookupConnector(certificate_model.chain, options)
    transaction_info = connector.lookup_tx(certificate_model.txid)

    # create verification plan
    verification_steps = create_verification_steps(
        certificate_model,
        transaction_info,
        issuer_info,
        certificate_model.chain
    )

    verification_steps.execute()
    messages = []
    verification_steps.add_detailed_status(messages)
    print("[*] Verification steps:")
    for i, message in enumerate(messages):
        print("\tStep #" + str(i+1) + ". "+ message['name'] + ' --> ' + str(message['status']))

    return messages


def verify_certificate_file(certificate_file_name, transaction_id=None, options={}, hideInfo=False):
    with open(certificate_file_name, 'rb') as cert_fp:
        certificate_bytes = cert_fp.read()
        certificate_json = json.loads(certificate_bytes.decode('utf-8'))

        if not hideInfo:
            print("[*] Issuer data:")
            print("\tName:\t\t" + certificate_json["badge"]["issuer"]["name"])
            print("\tEmail:\t\t" + certificate_json["badge"]["issuer"]["email"])
            print("\tPublic key:\t" + certificate_json["verification"]["publicKey"])

            print("[*] Recipient data:")
            print("\tName:\t\t" + certificate_json["recipientProfile"]["name"])
            print("\tEmail:\t\t" + certificate_json["recipient"]["identity"])
            print("\tPublic key:\t" + certificate_json["recipientProfile"]["publicKey"])

            print("[*] Certificate data:")
            print("\tName:\t\t" + certificate_json["badge"]["name"])
            print("\tDescription:\t" + certificate_json["badge"]["description"])
            print("\tCriteria:\t" + certificate_json["badge"]["criteria"]["narrative"])
            print("\tIssued on:\t" + certificate_json["issuedOn"])

        certificate_model = to_certificate_model(
            certificate_json=certificate_json,
            txid=transaction_id,
            certificate_bytes=certificate_bytes
        )
        result = verify_certificate(certificate_model, options)
    return result


def main(params=None):
    parser = argparse.ArgumentParser(description='verify-certificate is a tool that will verify if the information stored in a Blockcerts certificate is valid.', prog='verify-certificate', epilog="The source code is free software and can be found at <https://github.com/blockchain-certificates/cert-verifier>.", add_help=False)

    # Adding the main options
    parser.add_argument('-c', '--certificates', metavar='<PATH>', default=None,  nargs='+', action='store', help='list of paths to the files containing the certificates in Json format. A sample certificate files can be found either in the official repository or by creating them using cert-tools and issueing them with cert-issuer.', required=True)
    parser.add_argument('--hide_info', default=False, action='store_true', help='to hide the information of the loaded certificate. By default, the application will show the details of each certificate before verifying.', required=False)

    groupAbout = parser.add_argument_group('About arguments')
    groupAbout.add_argument('-h', '--help', action='help', help='shows this help and exists.')
    groupAbout.add_argument('--version', action='version', version='%(prog)s '+ pkg_resources.get_distribution("cert_verifier").version, help='shows the version of the program and exists.')

    if params != None:
        args = parser.parse_args(params)
    else:
        args = parser.parse_args()

    results = {}
    for i, cert_file in enumerate(args.certificates):
        print("[*] Certificate #" + str(i+1) + " | Verifying '" + cert_file + "'.")
        result = verify_certificate_file(cert_file, hideInfo=args.hide_info)
        results[cert_file] = result
        print()

    print("[*] Verification summary:")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
