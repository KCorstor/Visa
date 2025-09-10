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
package com.visa;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.IOUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

public class PushFundsAndQueryAPIWithMLE {
    public static final String VISA_BASE_URL = "https://sandbox.api.visa.com";

    // THIS IS EXAMPLE ONLY how will cert and key look like
    // keystorePath = "visa.jks"
    // keystorePassword = "password"
    private static final String KEYSTORE_PATH = "<YOUR KEYSTORE PATH>";
    private static final String KEYSTORE_PASSWORD = "<YOUR KEYSTORE PASSWORD>";

    // THIS IS EXAMPLE ONLY how will user_id and password look like
    // userId = "1WM2TT4IHPXC8DQ5I3CH21n1rEBGK-Eyv_oLdzE2VZpDqRn_U";
    // password = "19JRVdej9";
    private static final String USER_ID = "<YOUR USER ID>";
    private static final String PASSWORD = "<YOUR PASSWORD>";

    // MLE KEY
    //# THIS IS EXAMPLE ONLY how will myKey_ID, server_cert and private_key look like
    //# mleClientPrivateKeyPath = 'key_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
    //# mleServerPublicCertificatePath = 'server_cert_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
    //# keyId = '7f591161-6b5f-4136-80b8-2ae8a44ad9eb'
    private static final String MLE_CLIENT_PRIVATE_KEY_PATH = "<YOUR MLE CLIENT PRIVATE KEY PATH>";
    private static final String MLE_SERVER_PUBLIC_CERTIFICATE_PATH = "<YOUR MLE SERVER PUBLIC CERTIFICATE PATH>";
    private static final String KEY_ID = "<YOUR KEY ID>";

    public static void main(String[] args) throws Exception {
        System.out.println("##########################################################");
        String acquiringBin = "408999";
        String pushFundsPayload = "{\n" +
                "  \"amount\": \"124.05\",\n" +
                "  \"senderAddress\": \"901 Metro Center Blvd\",\n" +
                "  \"localTransactionDateTime\": \"" + getLocalTransactionDateTime() + "\",\n" +
                "  \"pointOfServiceData\": {\n" +
                "    \"panEntryMode\": \"90\",\n" +
                "    \"posConditionCode\": \"00\",\n" +
                "    \"motoECIIndicator\": \"0\"\n" +
                "  },\n" +
                "  \"recipientPrimaryAccountNumber\": \"4957030420210496\",\n" +
                "  \"colombiaNationalServiceData\": {\n" +
                "    \"addValueTaxReturn\": \"10.00\",\n" +
                "    \"taxAmountConsumption\": \"10.00\",\n" +
                "    \"nationalNetReimbursementFeeBaseAmount\": \"20.00\",\n" +
                "    \"addValueTaxAmount\": \"10.00\",\n" +
                "    \"nationalNetMiscAmount\": \"10.00\",\n" +
                "    \"countryCodeNationalService\": \"170\",\n" +
                "    \"nationalChargebackReason\": \"11\",\n" +
                "    \"emvTransactionIndicator\": \"1\",\n" +
                "    \"nationalNetMiscAmountType\": \"A\",\n" +
                "    \"costTransactionIndicator\": \"0\",\n" +
                "    \"nationalReimbursementFee\": \"20.00\"\n" +
                "  },\n" +
                "  \"cardAcceptor\": {\n" +
                "    \"address\": {\n" +
                "      \"country\": \"USA\",\n" +
                "      \"zipCode\": \"94404\",\n" +
                "      \"county\": \"San Mateo\",\n" +
                "      \"state\": \"CA\"\n" +
                "    },\n" +
                "    \"idCode\": \"CA-IDCode-77765\",\n" +
                "    \"name\": \"Visa Inc. USA-Foster City\",\n" +
                "    \"terminalId\": \"TID-9999\"\n" +
                "  },\n" +
                "  \"senderReference\": \"\",\n" +
                "  \"transactionIdentifier\": \"381228649430015\",\n" +
                "  \"acquirerCountryCode\": \"840\",\n" +
                "  \"acquiringBin\": \"" + acquiringBin + "\",\n" +
                "  \"retrievalReferenceNumber\": \"412770451018\",\n" +
                "  \"senderCity\": \"Foster City\",\n" +
                "  \"senderStateCode\": \"CA\",\n" +
                "  \"systemsTraceAuditNumber\": \"451018\",\n" +
                "  \"senderName\": \"Mohammed Qasim\",\n" +
                "  \"businessApplicationId\": \"AA\",\n" +
                "  \"settlementServiceIndicator\": \"9\",\n" +
                "  \"merchantCategoryCode\": \"6012\",\n" +
                "  \"transactionCurrencyCode\": \"USD\",\n" +
                "  \"recipientName\": \"rohan\",\n" +
                "  \"senderCountryCode\": \"124\",\n" +
                "  \"sourceOfFundsCode\": \"05\",\n" +
                "  \"senderAccountNumber\": \"4653459515756154\"\n" +
                "}";

        //##########################################################
        // OCT - Push Funds Transaction
        //##########################################################
        String encryptedPayload = getEncryptedPayload(MLE_SERVER_PUBLIC_CERTIFICATE_PATH, pushFundsPayload, KEY_ID);
        System.out.println("START Sample Code for OCT MLE+Two-Way (Mutual) SSL");
        System.out.println("OCT Encrypted Payload \n" + encryptedPayload);
        String encryptedResponseStr = invokeAPI("/visadirect/fundstransfer/v1/pushfundstransactions", "POST", encryptedPayload);
        EncryptedResponse encryptedResponse = new ObjectMapper().readValue(encryptedResponseStr, EncryptedResponse.class);
        System.out.println("##########################################################");
        System.out.println("OCT Encrypted Response \n" + encryptedResponse.getEncData());

        String decryptedResponse = getDecryptedPayload(MLE_CLIENT_PRIVATE_KEY_PATH, encryptedResponse);
        System.out.println("OCT Decrypted Response \n" + decryptedResponse);
        System.out.println("END Sample Code for OCT MLE+Two-Way (Mutual) SSL");
        System.out.println("##########################################################");


        //##########################################################
        // Transaction Query API
        //##########################################################
        System.out.println("##########################################################");
        System.out.println("START Sample Code for Query API MLE+Two-Way (Mutual) SSL");
        String transactionIdentifier = ((Map<String, Object>) new ObjectMapper().readValue(decryptedResponse, new TypeReference<Map<String, Object>>() {
        })).get("transactionIdentifier").toString();

        String queryParams = "acquiringBIN=" + acquiringBin + "&transactionIdentifier=" + transactionIdentifier;
        encryptedResponseStr = invokeAPI("/visadirect/v1/transactionquery?" + queryParams, "GET", null);
        encryptedResponse = new ObjectMapper().readValue(encryptedResponseStr, EncryptedResponse.class);
        System.out.println("##########################################################");
        System.out.println("Query API Encrypted Response: \n" + encryptedResponse.getEncData());
        decryptedResponse = getDecryptedPayload(MLE_CLIENT_PRIVATE_KEY_PATH, encryptedResponse);
        System.out.println("Query API  Decrypted Response: \n" + decryptedResponse);
        System.out.println("END Sample Code for Query API MLE+Two-Way (Mutual) SSL");
        System.out.println("##########################################################");
    }

    /**
     * Invoke API
     *
     * @param resourcePath - Resource Path
     * @param httpMethod   - HTTP Method
     * @param payload      - Request Payload
     * @return String       - Response Payalod
     * @throws Exception - {@link Exception}
     */
    public static String invokeAPI(final String resourcePath, String httpMethod, String payload) throws Exception {
        String url = VISA_BASE_URL + resourcePath;
        System.out.println("Calling API: " + url);

        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream keystoreInputStream = new FileInputStream(KEYSTORE_PATH);
        keystore.load(keystoreInputStream, KEYSTORE_PASSWORD.toCharArray());
        keystoreInputStream.close();
        // Make a KeyStore from the PKCS-12 file
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        // Make a KeyManagerFactory from the KeyStore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

        // Now make an SSL Context with our Key Manager and the default Trust Manager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        if (con instanceof HttpsURLConnection) {
            ((HttpsURLConnection) con).setSSLSocketFactory(sslContext.getSocketFactory());
        }

        con.setRequestMethod(httpMethod);
        con.setRequestProperty("Content-Type", "application/json");
        con.setRequestProperty("Accept", "application/json");
        con.setRequestProperty("keyId", KEY_ID);

        //Set Timeout
        //con.setConnectTimeout(10000);

        byte[] encodedAuth = Base64.getEncoder().encode((USER_ID + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
        String authHeaderValue = "Basic " + new String(encodedAuth);
        con.setRequestProperty("Authorization", authHeaderValue);

        if (payload != null && payload.trim().length() > 0) {
            con.setDoOutput(true);
            con.setDoInput(true);
            try (OutputStream os = con.getOutputStream()) {
                byte[] input = payload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
        }

        int status = con.getResponseCode();
        System.out.println("Http Status: " + status);

        BufferedReader in;
        if (status == 200) {
            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        } else {
            in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
            System.out.println("Two-Way (Mutual) SSL test failed");
        }
        String response;
        StringBuilder content = new StringBuilder();
        while ((response = in.readLine()) != null) {
            content.append(response);
        }
        in.close();
        con.disconnect();

        //Print All Response Headers
        //con.getHeaderFields().forEach((k, v) -> System.out.println(k + " : " + v));
        return content.toString();
    }

    /**
     * @param mleServerPublicCertificatePath - MLE Server Public Certificate Path
     * @param requestPayload                 - Request Payload
     * @param keyId                          - Key ID
     * @return
     * @throws CertificateException - {@link CertificateException}
     * @throws JOSEException        - {@link JOSEException}
     * @throws IOException          - {@link IOException}
     */
    public static String getEncryptedPayload(String mleServerPublicCertificatePath, String requestPayload, String keyId) throws CertificateException, JOSEException, IOException {
        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        headerBuilder.keyID(keyId);
        headerBuilder.customParam("iat", System.currentTimeMillis());
        JWEObject jweObject = new JWEObject(headerBuilder.build(), new Payload(requestPayload));
        jweObject.encrypt(new RSAEncrypter(getRSAPublicKey(mleServerPublicCertificatePath)));
        return "{\"encData\":\"" + jweObject.serialize() + "\"}";
    }

    /**
     * Decrypt response payload
     *
     * @param mleClientPrivateKeyPath - MLE Client Private Key Path
     * @param encryptedPayload        - Encrypted Response Payload
     * @return Decrypted Response
     * @throws ParseException           - {@link ParseException}
     * @throws NoSuchAlgorithmException - {@link NoSuchAlgorithmException}
     * @throws IOException              - {@link IOException}
     * @throws InvalidKeySpecException  - {@link InvalidKeySpecException}
     * @throws JOSEException            - {@link JOSEException}
     */
    public static String getDecryptedPayload(String mleClientPrivateKeyPath, EncryptedResponse encryptedPayload) throws ParseException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, JOSEException {
        String response = encryptedPayload.getEncData();
        JWEObject jweObject = JWEObject.parse(response);
        PrivateKey privateKey = getRSAPrivateKey(mleClientPrivateKeyPath);
        jweObject.decrypt(new RSADecrypter(privateKey));
        response = jweObject.getPayload().toString();
        return response;
    }

    /**
     * Converts PEM file content to RSAPublicKey
     *
     * @param mleServerPublicCertificatePath - MLE Server Public Certificate Path
     * @return RSA Public Key       - {@link PrivateKey}
     * @throws CertificateException - {@link IOException}
     * @throws IOException          - {@link IOException}
     */
    private static RSAPublicKey getRSAPublicKey(final String mleServerPublicCertificatePath) throws CertificateException, IOException {
        final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
        final String END_CERT = "-----END CERTIFICATE-----";
        final String pemEncodedPublicKey = IOUtils.readFileToString(new File(mleServerPublicCertificatePath), StandardCharsets.UTF_8);
        final com.nimbusds.jose.util.Base64 base64 = new com.nimbusds.jose.util.Base64(pemEncodedPublicKey.replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""));
        final Certificate cf = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(base64.decode()));
        return (RSAPublicKey) cf.getPublicKey();
    }

    /**
     * Format Local Date Time to yyyy-MM-dd'T'HH:mm:ss
     *
     * @return String
     */
    private static String getLocalTransactionDateTime() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        return simpleDateFormat.format(new Date());
    }

    /**
     * Converts PEM file content to PrivateKey
     *
     * @param mleClientPrivateKeyPath - MLE Client Private Key Path
     * @return Private Key              - {@link PrivateKey}
     * @throws IOException              - {@link IOException}
     * @throws NoSuchAlgorithmException - {@link NoSuchAlgorithmException}
     * @throws InvalidKeySpecException  - {@link InvalidKeySpecException}
     */
    private static PrivateKey getRSAPrivateKey(String mleClientPrivateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
        final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

        final String pemEncodedKey = IOUtils.readFileToString(new File(mleClientPrivateKeyPath), StandardCharsets.UTF_8);
        final com.nimbusds.jose.util.Base64 base64 = new com.nimbusds.jose.util.Base64(pemEncodedKey.replaceAll(BEGIN_RSA_PRIVATE_KEY, "").replaceAll(END_RSA_PRIVATE_KEY, ""));
        final ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence.fromByteArray(base64.decode());
        final Enumeration<?> e = primitive.getObjects();
        final BigInteger v = ((ASN1Integer) e.nextElement()).getValue();
        int version = v.intValue();
        if (version != 0 && version != 1) {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }
        final BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Encrypted Response Object
     */
    public static class EncryptedResponse {

        String encData;

        public String getEncData() {
            return encData;
        }

    }

}
