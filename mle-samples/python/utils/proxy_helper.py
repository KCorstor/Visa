# -*- coding: utf-8 -*-

#  **© Copyright 2018 - 2020 Visa. All Rights Reserved.**
#
#  *NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
#
#  * By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
#
#  *This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
#

# !/usr/bin/python

import os
import sys
if sys.version_info < (3, 0):
    import ConfigParser as parser
else:
    import configparser as parser
class ProxyHelper:
    def set_up_proxy(self):
        DEBUG = False
        config = parser.ConfigParser()
        config_path = os.path.abspath(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), os.getenv("CONFIG_FILE", "configuration.ini")))
        config.read(config_path)

        if config.get('VDP', 'proxyHostName', fallback=None) != None:
            os.environ["HTTP_PROXY"] = "http://{username}:{password}@{host}:{port}".format(username=config.get('VDP', 'proxyUserName'), password=config.get('VDP', 'proxyPassword'),
                                                                                host=config.get('VDP', 'proxyHostName'), port=config.get('VDP', 'proxyPortNumber'))
            os.environ["HTTPS_PROXY"] =  "https://{username}:{password}@{host}:{port}".format(username=config.get('VDP', 'proxyUserName'), password=config.get('VDP', 'proxyPassword'),
                                                                                host=config.get('VDP', 'proxyHostName'), port=config.get('VDP', 'proxyPortNumber'))
            if DEBUG: print (os.environ["HTTP_PROXY"])
            if DEBUG: print (os.environ["HTTPS_PROXY"])