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
import requests
import string
import sys
import random
import os
from utils.config_util import ConfigUtil

class VisaAPIClient:
    logging.getLogger('').addHandler(logging.StreamHandler())
    log = logging.getLogger('VisaAPIClient')
    log.propagate = True
    timeout = 10
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPSConnection.debuglevel = 0
    config_util = ConfigUtil();
    user_id = config_util.get_config('VDP', 'userId')
    password = config_util.get_config('VDP', 'password')
    cert = config_util.get_safe_filepath('VDP', 'cert')
    key = config_util.get_safe_filepath('VDP', 'key')


    def perfom_mutual_auth_request_get(self, request_uri, test_info, input_headers={}):
        try:
            self.log.info(test_info)
            response = requests.get(request_uri,
                                    # verify = ('put the CA certificate pem file path here'),
                                    cert=(self.cert, self.key),
                                    headers = input_headers,
                                    auth=(self.user_id, self.password),
                                    # json = payload,
                                    timeout=self.timeout
                                    )
            return response

        except Exception as e:
            print(e)
        pass

    def perform_mutual_auth_request_post(self, request_uri, body, test_info, input_headers={}):
        try:

            self.log.info(test_info)
            input_headers.update(self.get_default_headers())
            self.log.info("Request URL:" + request_uri)
            self.log.info(body)
            response = requests.post(request_uri,
                                # verify = ('put the CA certificate pem file path here'),
                                cert=(self.cert, self.key),
                                headers=input_headers,
                                auth=(self.user_id, self.password),
                                json = body,
                                timeout=self.timeout
                                     )
            self.log.info(json.loads(response.content))
            return response
        except Exception as e:
            print(e)

    def get_default_headers(self):
        return {'content-type': 'application/json',
         'accept': 'application/json',
         'x-correlation-id': self._get_correlation_id()}

    """
       Correlation Id ( ex-correlation-id ) is an optional header while making an API call. You can skip passing the header while calling the API's.
    """

    def _get_correlation_id(self):
        size = 12
        chars = string.digits
        correlationId = ''.join(random.choice(chars) for _ in range(size)) + '_SC'
        return correlationId


