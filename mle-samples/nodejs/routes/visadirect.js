/*
 * (c) Copyright 2018 - 2020 Visa. All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
 *
 */

var express = require('express');
var router = express.Router();
const request = require('request');
const connection = require('../config/connection');
const jose = require('node-jose');
const fs =  require('fs');
const base64url = require('base64url');
const config = require('../config/config');


router.get('/oct', (req, res) => {
    var options = connection.getOptions();
    options.headers.keyId = config.mleKeyId;
    options.uri = 'https://sandbox.api.visa.com/visadirect/fundstransfer/v1/pushfundstransactions';
    options.method = 'POST';
    parameters = getParameters();
    jose.JWK.asKey(fs.readFileSync(config.mlePublicKeyPath), 'PEM', {"kty": "RSA", "alg": "RSA-OAEP-256", enc: "A128GCM", key_opts: ["wrapKey","enc"]}).then(function(result) {
        console.log(parameters.payload);
        encryptionResult = jose.JWE.createEncrypt({format : 'compact', contentAlg: 'A128GCM', fields: {iat: Date.now()}},result).update(JSON.stringify(parameters.payload)).final()
            .then(function(data) {
                options.body = {"encData": data.toString()};
                request.post(options, (err, response, body) => {
                    if (err) {
                        return console.log(err);
                    }
                    console.log(`Status: ${response.statusCode}`);
                    console.log(`Encrypted Response: ${JSON.stringify(response.body)}`);

                    jose.JWK.asKey(fs.readFileSync(config.mlePrivateKeyPath), 'PEM').then(function(result){
                       jose.JWE.createDecrypt(result).decrypt(response.body.encData, {contentAlg: 'A128GCM', alg: 'RSA-OAEP-256'}).then(function(decryptedResult){
                           console.log(String(decryptedResult.plaintext));
                           options.uri = 'https://sandbox.api.visa.com/visadirect/v1/transactionquery?acquiringBIN=408999&transactionIdentifier='+ JSON.parse(decryptedResult.plaintext).transactionIdentifier;
                           request.get(options, (err, response, body) => {
                               if(err) {
                                   console.log(`Errored due to ${err}`);
                               }
                               console.log(`Status: ${response.statusCode}`);
                               console.log(`Encrypted Response: ${JSON.stringify(response.body)}`);
                           });
                           res.send(String(decryptedResult.plaintext));
                        });
                    });
                });
            }).catch(function(reason) {
                console.log('Encryption failed due to ');
                console.log(reason);
            });
    });
});


function getParameters() {
    var parameters = {
        "x-client-transaction-id": "1612321873781263",
        "Accept": "application/json",
        "Content-Type": "application/json"
    };
    parameters.payload = {
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
        "localTransactionDateTime": Date.now(),
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
    };

    return parameters;
}



module.exports = router;