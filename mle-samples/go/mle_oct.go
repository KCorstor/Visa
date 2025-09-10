/**
 * (c) Copyright 2018 - 2020 Visa. All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
 *
 */

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var (
	baseUrl = "https://sandbox.api.visa.com"

	// THIS IS EXAMPLE ONLY how will user_id and password look like
	// userId = "1WM2TT4IHPXC8DQ5I3CH21n1rEBGK-Eyv_oLdzE2VZpDqRn_U";
	// password = "19JRVdej9";
	username = "BEMZ5X1LZTEHVAGUX6SA21eVnm8-NobWjvJyykqKJNEYRogZ4"
	password = "AFS9iEtA1DiFWFzCDYueA5ANr9UfOiX3Fyg"

	// THIS IS EXAMPLE ONLY how will cert and key look like
	// clientCertificateFile = 'cert.pem'
	// clientCertificateKeyFile = 'key_83d11ea6-a22d-4e52-b310-e0558816727d.pem'
	// caCertificateFile = 'ca_bundle.pem'

	clientCertificateFile    = "cert.pem"
	clientCertificateKeyFile = "private_key.pem"
	caCertificateFile        = "<YOUR MUTUAL SSL CA PATH>"

	// MLE KEY
	//#########
	//# THIS IS EXAMPLE ONLY how will myKey_ID, server_cert and private_key look like
	//# mleClientPrivateKeyPath = 'key_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
	//# mleServerPublicCertificatePath = 'server_cert_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
	//# keyId = '7f591161-6b5f-4136-80b8-2ae8a44ad9eb'

	mleClientPrivateKeyPath        = "key_3a4dbd00-483d-4958-84bf-e0518d0412c4.pem"
	mleServerPublicCertificatePath = "server_cert_3a4dbd00-483d-4958-84bf-e0518d0412c4.pem"
	keyId                          = "3a4dbd00-483d-4958-84bf-e0518d0412c4"
)

func main() {

	log.Println("####################################################################################")
	log.Println("######################## START PUSH (OCT)  Transaction #############################")
	log.Println("####################################################################################")

	pushFundEndPoint := "/visadirect/fundstransfer/v1/pushfundstransactions"
	acquiringBin := "408999"

	t := time.Now()
	localTransactionDateTime := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())

	octPayload := `{
  	  "acquirerCountryCode": "840",
      "acquiringBin": "` + acquiringBin + `",
	  "amount": "124.05",
	  "businessApplicationId": "AA",
	  "cardAcceptor": {
		"address": {
		  "country": "USA",
		  "county": "SanMateo",
		  "state": "CA",
		  "zipCode": "94404"
		},
		"idCode": "CA-IDCode-77765",
		"name": "VisaInc.USA-FosterCity",
		"terminalId": "TID-9999"
	  },
	  "localTransactionDateTime": "` + localTransactionDateTime + `",
	  "merchantCategoryCode": "6012",
	  "pointOfServiceData": {
		"motoECIIndicator": "0",
		"panEntryMode": "90",
		"posConditionCode": "00"
	  },
	  "recipientName": "rohan",
	  "recipientPrimaryAccountNumber": "4957030420210496",
	  "retrievalReferenceNumber": "412770451018",
	  "senderAccountNumber": "4653459515756154",
	  "senderAddress": "901MetroCenterBlvd",
	  "senderCity": "FosterCity",
	  "senderCountryCode": "124",
	  "senderName": "MohammedQasim",
	  "senderReference": "",
	  "senderStateCode": "CA",
	  "sourceOfFundsCode": "05",
	  "systemsTraceAuditNumber": "451018",
	  "transactionCurrencyCode": "USD",
	  "settlementServiceIndicator": "9",
	  "colombiaNationalServiceData": {
		"countryCodeNationalService": "170",
		"nationalReimbursementFee": "20.00",
		"nationalNetMiscAmountType": "A",
		"nationalNetReimbursementFeeBaseAmount": "20.00",
		"nationalNetMiscAmount": "10.00",
		"addValueTaxReturn": "10.00",
		"taxAmountConsumption": "10.00",
		"addValueTaxAmount": "10.00",
		"costTransactionIndicator": "0",
		"emvTransactionIndicator": "1",
		"nationalChargebackReason": "11"
	  }
	}`

	encData := map[string]string{"encData": createJWE(octPayload, keyId, mleServerPublicCertificatePath)}
	encryptedPayload, _ := json.Marshal(encData)
	responsePayload := invokeAPI(pushFundEndPoint, http.MethodPost, string(encryptedPayload))
	log.Println("OCT Response Data: ", responsePayload)

	log.Println("####################################################################################")
	log.Println("######################## END PUSH (OCT)  Transaction ###############################")
	log.Println("####################################################################################")

	log.Println("####################################################################################")
	log.Println("######################## START QUERY API ###########################################")
	log.Println("####################################################################################")

	var responseMap map[string]json.RawMessage
	_ = json.Unmarshal([]byte(responsePayload), &responseMap)

	queryString := "?acquiringBIN=" + acquiringBin + "&transactionIdentifier=" + string(responseMap["transactionIdentifier"])
	transactionQueryEndPoint := "/visadirect/v1/transactionquery" + queryString

	responsePayload = invokeAPI(transactionQueryEndPoint, http.MethodGet, "")
	log.Println("Query Response Data: ", responsePayload)

	log.Println("####################################################################################")
	log.Println("######################## END QUERY API #############################################")
	log.Println("####################################################################################")

}

func invokeAPI(resourcePath string, httpMethod string, payload string) string {
	//Load CA Cert
	clientCACert, err := ioutil.ReadFile(caCertificateFile)
	if err != nil {
		panic(err)
	}

	//Load Client Key Pair
	clientKeyPair, err := tls.LoadX509KeyPair(clientCertificateFile, clientCertificateKeyFile)

	clientCertPool, _ := x509.SystemCertPool()
	if clientCertPool == nil {
		clientCertPool = x509.NewCertPool()
	}

	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      clientCertPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	apiUrl := baseUrl + resourcePath
	var request *http.Request = nil
	if payload != "" {
		log.Println("Request Payload: ", payload)
		request, err = http.NewRequest(httpMethod, apiUrl, bytes.NewBuffer([]byte(payload)))
	} else {
		request, err = http.NewRequest(httpMethod, apiUrl, nil)
	}

	if err != nil {
		panic(err)
	}
	request.SetBasicAuth(username, password)
	request.Header.Set("keyId", keyId)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	log.Println("Invoking API:", httpMethod, resourcePath)
	resp, err := client.Do(request)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	log.Println("Http Status :", resp.Status)
	log.Println("Response Headers:", resp.Header)

	encryptedResponsePayload := string(body)
	log.Println("Response Payload: ", encryptedResponsePayload)

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
		panic(errors.New("error when invoking visa api. " + decryptedData))
	}

	log.Println("Response Body:", encryptedResponsePayload)
	decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
	return decryptedData
}

func createJWE(payload string, keyId string, mleServerPublicCertificatePath string) string {
	// Instantiate an encrypter using RSA-OAEP-256 with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := loadPublicKey(mleServerPublicCertificatePath)
	opts := new(jose.EncrypterOptions)

	iat := currentMillis()

	opts.WithHeader("kid", keyId)
	opts.WithHeader("iat", iat)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: publicKey}, opts)
	if err != nil {
		panic(err)
	}

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	object, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the compact serialization format.
	serialized, err := object.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return serialized
}

func currentMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func loadPublicKey(certFilePath string) *rsa.PublicKey {
	certificate, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certificate)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)
}

func parseEncryptedResponse(encryptedPayload string) EncryptedResponse {
	var encryptedResponse EncryptedResponse
	err := json.Unmarshal([]byte(encryptedPayload), &encryptedResponse)

	if err != nil {
		panic(err)
	}
	return encryptedResponse
}

func decryptJWE(encryptedPayload string, mleClientPrivateKeyPath string) string {

	encryptedData := parseEncryptedResponse(encryptedPayload)

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseEncrypted(encryptedData.EncData)
	if err != nil {
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate the the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	privateKey := loadPrivateKey(mleClientPrivateKeyPath)
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}

	return string(decrypted)
}

//Load Private Key from file
func loadPrivateKey(keyFilePath string) *rsa.PrivateKey {
	keyPem, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyPem)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return priv
}

type EncryptedResponse struct {
	EncData string
}
