<?php
/**
 * *© Copyright 2018 - 2020 Visa. All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
 *
 */

namespace mle;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;

class EncryptionUtils
{
    protected $jweBuilder;

    protected $jweDecrypter;

    public function __construct()
    {
        // The key encryption algorithm manager with the RSA-OAEP-256 algorithm.
        $keyEncryptionAlgorithmManager = new AlgorithmManager([new RSAOAEP256(),]);

        // The content encryption algorithm manager with the A128GCM algorithm.
        $contentEncryptionAlgorithmManager = new AlgorithmManager([new A128GCM(),]);

        // The compression method manager with the DEF (Deflate) method.
        $compressionMethodManager = new CompressionMethodManager([new Deflate(),]);

        // We instantiate our JWE Builder.
        $this->jweBuilder = new JWEBuilder($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);

        // We instantiate our JWE Decrypter.
        $this->jweDecrypter = new JWEDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);
    }

    /**
     * This method will encrypt the payload and create a JWE token
     *
     * @param $payload
     * @param $keyId
     * @param $mleServerPublicCertificatePath
     * @return false|string
     */
    public function encryptPayload($payload, $keyId, $mleServerPublicCertificatePath)
    {
        // Our key.
        $jwk = JWKFactory::createFromCertificateFile($mleServerPublicCertificatePath);

        $milliseconds = round(microtime(true) * 1000);

        $jwe = $this->jweBuilder
            ->create()              // We want to create a new JWE
            ->withPayload($payload) // We set the payload
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',  // Key Encryption Algorithm
                'enc' => 'A128GCM',       // Content Encryption Algorithm
                'iat' => $milliseconds,   // Current Time Stamp in milliseconds
                'kid' => $keyId
            ])
            ->addRecipient($jwk)    // We add a recipient (a shared key or public key).
            ->build();              // We build it

        $serializer = new CompactSerializer();
        $token = $serializer->serialize($jwe, 0);
        return json_encode(['encData' => $token], JSON_PRETTY_PRINT);
    }

    /**
     * This method will decrypt the given JWE token.
     *
     * @param $encryptedPayload - JWE Token
     * @param $mleClientPrivateKeyPath
     * @return string|null
     * @throws \Exception
     */
    public function decryptJwe($encryptedPayload, $mleClientPrivateKeyPath)
    {
        // Our key.
        $jwk = JWKFactory::createFromKeyFile($mleClientPrivateKeyPath);
        $encryptedPayload = json_decode($encryptedPayload, true);

        $token = $encryptedPayload['encData'];

        $serializerManager = new JWESerializerManager([new CompactSerializer(),]);

        $jwe = $serializerManager->unserialize($token);

        $success = $this->jweDecrypter->decryptUsingKey($jwe, $jwk, 0);

        if ($success) {
            $jweLoader = new JWELoader(
                $serializerManager,
                $this->jweDecrypter,
                null
            );
            $jwe = $jweLoader->loadAndDecryptWithKey($token, $jwk, $recipient);
            return $jwe->getPayload();
        } else {
            throw new \Exception('Error Decrypting JWE');
        }
    }
}
