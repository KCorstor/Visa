/*
 * (c) Copyright 2018 - 2020 Visa.All Rights Reserved.**
*
* NOTICE: The software and accompanying information and documentation(together, the "Software") remain the property of and are proprietary to Visa and its suppliers and affiliates.The Software remains protected by intellectual property rights and may be covered by U.S.and foreign patents or patent applications.The Software is licensed and not sold.*
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN "AS IS," "AS AVAILABLE," "WITH ALL FAULTS" BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa's terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features, functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa"s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa's control, including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
*
*/
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Jose;
using Org.BouncyCastle.OpenSsl;

using Newtonsoft.Json;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.Crypto.Parameters;

using Newtonsoft.Json.Linq;

namespace Vdp
{
    class Program
    {
        public static string visaUrl = "https://sandbox.api.visa.com/";
        public static string userId = "<YOUR USER ID HERE>";
        public static string password = "<YOUR PASSWORD HERE>";
        public static string cert = "<ABSOLUTE PATH TO .P12 CERTIFICATE HERE>";
        public static string certPassword = "<PASSPHRASE FOR P12 CERTIFICATE HERE>";
        
        //For MLE
        public static string keyId = "<YOUR MLE KID HERE>";
        public static string mleClientPrivateKey = "<YOUR MLE PRIVATE KEY PATH>";
        public static string mleServerPublicCertificate = "<YOUR MLE SERVER CERTIFICATE HERE>"; 

        
        static void Main(string[] args)
        {
            Program p = new Program();
            Console.WriteLine("MLE OCT Test");
            string decryptedPayload = p.PushFundsTransactions();
            Console.WriteLine("Decrypted OCT Response\n" + decryptedPayload);

            var responseObj = JObject.Parse(decryptedPayload) as JToken;
            var aquiringBin = "408999";
            var transactionIdentifier = responseObj["transactionIdentifier"].ToString();

            var queryResponse= p.Query(aquiringBin, transactionIdentifier);
            Console.WriteLine("Transaction Query Response:\n" + queryResponse);
        }

        private void LogRequest(string url, string requestBody)
        {
            Console.WriteLine(url);
            Console.WriteLine(requestBody);
        }

        private void LogResponse(string info, HttpWebResponse response)
        {

            Debug.WriteLine(info);
            Console.WriteLine("Response Status: \n" + response.StatusCode);
            Console.WriteLine("Response Headers: \n" + response.Headers.ToString());

            Console.WriteLine("Response Body: \n" + GetResponseBody(response));
        }

        private string GetResponseBody(HttpWebResponse response)
        {
            string responseBody = "";
            using (var reader = new StreamReader(response.GetResponseStream(), ASCIIEncoding.ASCII))
            {
                responseBody = reader.ReadToEnd();
            }
            return responseBody;
        }

        //Correlation Id ( ex-correlation-id ) is an optional header while making an API call. You can skip passing the header while calling the API's.
        private string GetCorrelationId()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 12).Select(s => s[random.Next(s.Length)]).ToArray()) + "_SC";

        }

        private string GetBasicAuthHeader(string userId, string password)
        {
            string authString = userId + ":" + password;
            var authStringBytes = Encoding.UTF8.GetBytes(authString);
            string authHeaderString = Convert.ToBase64String(authStringBytes);
            return "Basic " + authHeaderString;
        }

        public string DoMutualAuthCall(string path, string method, string testInfo, string requestBodyString, Dictionary<string, string> headers = null)
        {
            string requestURL = visaUrl + path;
            string certificatePath = cert;
            string certificatePassword = certPassword;
            string statusCode = "";
            string responseBody = "";
            LogRequest(requestURL, requestBodyString);
            // Create the POST request object 
            HttpWebRequest request = WebRequest.Create(requestURL) as HttpWebRequest;

            request.Method = method;
            if (method.Equals("POST") || method.Equals("PUT"))
            {
                request.ContentType = "application/json";
                request.Accept = "application/json";
                // Load the body for the post request
                var requestStringBytes = Encoding.UTF8.GetBytes(requestBodyString);
                request.GetRequestStream().Write(requestStringBytes, 0, requestStringBytes.Length);
            }

            if (headers != null)
            {
                foreach (KeyValuePair<string, string> header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            // Add headers
            request.Headers["Authorization"] = GetBasicAuthHeader(userId, password);
            request.Headers["ex-correlation-id"] = GetCorrelationId();
            request.Headers["keyId"] = keyId;

            // Add certificate
            var certificate = new X509Certificate2(certificatePath, certificatePassword);
            request.ClientCertificates.Add(certificate);
            try
            {
                // Make the call
                using (HttpWebResponse response = request.GetResponse() as HttpWebResponse)
                {
                    responseBody = GetResponseBody(response);
                    LogResponse(testInfo, response);
                    statusCode = response.StatusCode.ToString();

                }
            }
            catch (WebException e)
            {
                Console.WriteLine(e.ToString());
                if (e.Response is HttpWebResponse)
                {
                    HttpWebResponse response = (HttpWebResponse)e.Response;
                    responseBody = GetResponseBody(response);
                    LogResponse(testInfo, response);
                    statusCode = response.StatusCode.ToString();
                }
            }
            return responseBody;
        }
        public string PushFundsTransactions()
        {
            string localTransactionDateTime = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
            string requestBody = "{ \"acquirerCountryCode\": \"840\", \"acquiringBin\": \"408999\", \"amount\": \"124.05\", \"businessApplicationId\": \"AA\", \"cardAcceptor\": {   \"address\": {   \"country\": \"USA\",   \"county\": \"San Mateo\",   \"state\": \"CA\",   \"zipCode\": \"94404\"   },   \"idCode\": \"CA-IDCode-77765\",   \"name\": \"Visa Inc. USA-Foster City\",   \"terminalId\": \"TID-9999\" }, \"localTransactionDateTime\": \"" + localTransactionDateTime + "\", \"merchantCategoryCode\": \"6012\", \"pointOfServiceData\": {   \"motoECIIndicator\": \"0\",   \"panEntryMode\": \"90\",   \"posConditionCode\": \"00\" }, \"recipientName\": \"rohan\", \"recipientPrimaryAccountNumber\": \"4957030420210462\", \"retrievalReferenceNumber\": \"412770451018\", \"senderAccountNumber\": \"4957030420210454\", \"senderAddress\": \"901 Metro Center Blvd\", \"senderCity\": \"Foster City\", \"senderCountryCode\": \"124\", \"senderName\": \"Mohammed Qasim\", \"senderReference\": \"\", \"senderStateCode\": \"CA\", \"sourceOfFundsCode\": \"05\", \"systemsTraceAuditNumber\": \"451018\", \"transactionCurrencyCode\": \"USD\", \"transactionIdentifier\": \"381228649430015\" }";

            string requestURL = "visadirect/fundstransfer/v1/pushfundstransactions";

            return GetDecryptedPayload(DoMutualAuthCall(requestURL, "POST", "OCT With MLE", getEncryptedPayload(requestBody), null));
        }

        public string Query(string acquiringBin, string transactionIdentifier)
        {
            var queryString = "?acquiringBIN=" + acquiringBin + "&transactionIdentifier=" + transactionIdentifier;

            var requestUrl = "visadirect/v1/transactionquery" + queryString;

            return GetDecryptedPayload(DoMutualAuthCall(requestUrl, "GET", "Transaction Query With MLE", null, null));
        }

        private static string GetTimestamp()
        {
            long timeStamp = ((long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds) / 1000;
            return timeStamp.ToString();
        }

        private String getEncryptedPayload(String requestBody)
        {
            RSA clientCertificate = new X509Certificate2(mleServerPublicCertificate).GetRSAPublicKey();
            DateTime now = DateTime.UtcNow;
            long unixTimeMilliseconds = new DateTimeOffset(now).ToUnixTimeMilliseconds();
            IDictionary<string, object> extraHeaders = new Dictionary<string, object>{
                {"kid", keyId},{"iat",unixTimeMilliseconds}
            };
            string token = JWT.Encode(requestBody, clientCertificate, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, null, extraHeaders);
            return "{\"encData\":\"" + token + "\"}";
        }

        private static String GetDecryptedPayload(String encryptedPayload)
        {
            var jsonPayload = JsonConvert.DeserializeObject<EncryptedPayload>(encryptedPayload);
            return JWT.Decode(jsonPayload.encData, ImportPrivateKey(mleClientPrivateKey));
        }

        private static RSA ImportPrivateKey(string privateKeyFile)
        {
            var pemValue = System.Text.Encoding.Default.GetString(File.ReadAllBytes(privateKeyFile));
            var pr = new PemReader(new StringReader(pemValue));
            var keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);

            return rsa;
        }

    }

    public class EncryptedPayload
    {
        public string encData { get; set; }
    }

} 