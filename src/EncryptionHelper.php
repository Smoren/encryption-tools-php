<?php

namespace Smoren\EncryptionTools;

use Smoren\EncryptionTools\Exceptions\DecryptionError;

class EncryptionHelper
{
    /**
     * @return string[]
     */
    public static function generateRsaPair(): array
    {
        $keyPair = openssl_pkey_new();
        openssl_pkey_export($keyPair, $privateKey);
        $publicKey = openssl_pkey_get_details($keyPair)["key"];

        return [$privateKey, $publicKey];
    }

    /**
     * @param mixed $data
     * @param string $publicKey
     * @return string
     */
    public static function encryptByPublicKey($data, string $publicKey): string
    {
        openssl_public_encrypt(json_encode($data), $dataEncrypted, $publicKey);
        return base64_encode($dataEncrypted);
    }

    /**
     * @param mixed $data
     * @param string $publicKey
     * @return string
     */
    public static function encryptByPrivateKey($data, string $publicKey): string
    {
        openssl_private_encrypt(json_encode($data), $dataEncrypted, $publicKey);
        return base64_encode($dataEncrypted);
    }

    /**
     * @param string $dataEncrypted
     * @param string $publicKey
     * @return mixed
     * @throws DecryptionError
     */
    public static function decryptByPublicKey(string $dataEncrypted, string $publicKey)
    {
        openssl_public_decrypt(base64_decode($dataEncrypted), $dataDecrypted, $publicKey);

        if($dataDecrypted === null) {
            throw new DecryptionError('cannot decrypt by private key', DecryptionError::INVALID_KEY);
        }

        return json_decode($dataDecrypted, true);
    }

    /**
     * @param string $dataEncrypted
     * @param string $publicKey
     * @return mixed
     * @throws DecryptionError
     */
    public static function decryptByPrivateKey(string $dataEncrypted, string $publicKey)
    {
        openssl_private_decrypt(base64_decode($dataEncrypted), $dataDecrypted, $publicKey);

        if($dataDecrypted === null) {
            throw new DecryptionError('cannot decrypt by private key', DecryptionError::INVALID_KEY);
        }

        return json_decode($dataDecrypted, true);
    }
}
