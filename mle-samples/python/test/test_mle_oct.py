#  *(c) Copyright 2018 - 2020 Visa. All Rights Reserved.**
#
#  *NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
#
#  * By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
#
#  *This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
#

import datetime
import json
import logging
import sys
import unittest
from utils.proxy_helper import ProxyHelper
from utils.config_util import ConfigUtil
from apiclient.visa_api_client import VisaAPIClient
from utils.jwe_encryption_util import JWEEncryptionUtil


class TestMLEOCT(unittest.TestCase):
    def setUp(self):
        ProxyHelper().set_up_proxy()
        date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.visa_api_client = VisaAPIClient()
        self.push_funds_request = json.loads('''{
                        "acquirerCountryCode": "840",
                        "acquiringBin": "408999",
                        "amount": "124.05",
                        "businessApplicationId": "AA",
                        "cardAcceptor": {
                        "address": {
                        "country": "USA",
                        "county": "San Mateo",
                        "state": "CA",
                        "zipCode": "94404"
                        },
                        "idCode": "CA-IDCode-77765",
                        "name": "Visa Inc. USA-Foster City",
                        "terminalId": "TID-9999"
                        },
                        "localTransactionDateTime": "''' + date + '''",
                        "merchantCategoryCode": "6012",
                        "pointOfServiceData": {
                        "motoECIIndicator": "0",
                        "panEntryMode": "90",
                        "posConditionCode": "00"
                        },
                        "recipientName": "rohan",
                        "recipientPrimaryAccountNumber": "4957030420210462",
                        "retrievalReferenceNumber": "412770451018",
                        "senderAccountNumber": "4957030420210454",
                        "senderAddress": "901 Metro Center Blvd",
                        "senderCity": "Foster City",
                        "senderCountryCode": "124",
                        "senderName": "Mohammed Qasim",
                        "senderReference": "",
                        "senderStateCode": "CA",
                        "sourceOfFundsCode": "05",
                        "systemsTraceAuditNumber": "451018",
                        "transactionCurrencyCode": "USD",
                        "transactionIdentifier": "381228649430015"
                    }''')

    def test_push_funds_transactions_mle(self):
        log = logging.getLogger('TestMLEOCT')
        log.addHandler(logging.StreamHandler())
        end_point = 'https://sandbox.api.visa.com/'
        base_uri = 'visadirect/'
        resource_path = 'fundstransfer/v1/pushfundstransactions'
        config_util = ConfigUtil()
        jwe_encryption_util = JWEEncryptionUtil()

        # For MLE keyId needs to be added as a HTTP header
        mle_encryption_keyId = config_util.get_config('MLE', 'keyId')
        input_headers = {'keyId': mle_encryption_keyId}

        encryption_key = config_util.get_safe_filepath('MLE', 'serverCertificatePath')
        decryption_key = config_util.get_safe_filepath('MLE', 'privateKeyPath')

        encrypted_request_body = jwe_encryption_util.encrypt_jwe(self.push_funds_request,
                                                               mle_encryption_keyId,
                                                               jwe_encryption_util.import_key(encryption_key))


        response = self.visa_api_client.perform_mutual_auth_request_post(end_point + base_uri + resource_path,
                                                                         encrypted_request_body,
                                                               'Push Funds Transaction Test', input_headers)

        self.assertEqual(str(response.status_code), "200", "Push Funds Transaction test failed")
        decrypted_json_response = json.loads(jwe_encryption_util.decrypt_jwe_token(json.loads(response.content)['encData'], jwe_encryption_util.import_key(decryption_key)))
        log.info('Decrypted Response : ')
        log.info(decrypted_json_response)
        query_api_resource_path = 'v1/transactionquery?acquiringBIN={}&transactionIdentifier={}'.format(
                    '408999', decrypted_json_response['transactionIdentifier']
                    )
        query_response = self.visa_api_client.perfom_mutual_auth_request_get(end_point + base_uri + query_api_resource_path,
                                                                                        'Query API Test', input_headers)

        self.assertEqual(str(query_response.status_code), "200", "Query API with MLE failed")
        pass

