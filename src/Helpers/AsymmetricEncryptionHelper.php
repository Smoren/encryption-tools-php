<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\AsymmetricEncryptionException;
use Smoren\EncryptionTools\Exceptions\JsonException;

/**
 * Class AsymmetricEncryptionHelper
 * @author Smoren <ofigate@gmail.com>
 */
class AsymmetricEncryptionHelper
{
    /**
     * Generates RSA key pair
     * @return string[] [$privateKey, $publicKey]
     * @throws AsymmetricEncryptionException
     */
    public static function generateKeyPair(): array
    {
        $keyPair = openssl_pkey_new();
        if(!$keyPair) {
            throw new AsymmetricEncryptionException(
                'openssl_pkey_new() returned false',
                AsymmetricEncryptionException::OPENSSL_ERROR
            );
        }

        openssl_pkey_export($keyPair, $privateKey);
        $details = openssl_pkey_get_details($keyPair);
        if(!$details) {
            throw new AsymmetricEncryptionException(
                'openssl_pkey_get_details() returned false',
                AsymmetricEncryptionException::OPENSSL_ERROR
            );
        }

        $publicKey = $details["key"];

        return [$privateKey, $publicKey];
    }

    /**
     * Returns data encrypted by public key
     * @param mixed $data data to encrypt
     * @param string $publicKey public key
     * @return string encrypted data
     * @throws AsymmetricEncryptionException
     * @throws JsonException
     */
    public static function encryptByPublicKey($data, string $publicKey): string
    {
        static::validatePublicKey($publicKey);
        if(!openssl_public_encrypt(JsonHelper::encode($data), $dataEncrypted, $publicKey)) {
            throw new AsymmetricEncryptionException(
                'openssl_public_encrypt() returned false',
                AsymmetricEncryptionException::CANNOT_ENCRYPT
            );
        }
        return base64_encode($dataEncrypted);
    }

    /**
     * Returns data encrypted by private key
     * @param mixed $data data to encrypt
     * @param string $privateKey public key
     * @return string encrypted data
     * @throws AsymmetricEncryptionException
     * @throws JsonException
     */
    public static function encryptByPrivateKey($data, string $privateKey): string
    {
        static::validatePrivateKey($privateKey);
        if(!openssl_private_encrypt(JsonHelper::encode($data), $dataEncrypted, $privateKey)) {
            throw new AsymmetricEncryptionException(
                'openssl_private_encrypt() returned false',
                AsymmetricEncryptionException::CANNOT_ENCRYPT
            );
        }
        return base64_encode($dataEncrypted);
    }

    /**
     * Returns data decrypted by public key
     * @param string $dataEncrypted data to decrypt
     * @param string $publicKey public key
     * @return mixed decrypted data
     * @throws AsymmetricEncryptionException
     */
    public static function decryptByPublicKey(string $dataEncrypted, string $publicKey)
    {
        static::validatePublicKey($publicKey);
        openssl_public_decrypt(base64_decode($dataEncrypted), $dataDecrypted, $publicKey);

        if($dataDecrypted === null) {
            throw new AsymmetricEncryptionException(
                'cannot decrypt by public key',
                AsymmetricEncryptionException::CANNOT_DECRYPT
            );
        }

        return json_decode($dataDecrypted, true);
    }

    /**
     * Returns data decrypted by private key
     * @param string $dataEncrypted data to decrypt
     * @param string $privateKey private key
     * @return mixed decrypted data
     * @throws AsymmetricEncryptionException
     */
    public static function decryptByPrivateKey(string $dataEncrypted, string $privateKey)
    {
        static::validatePrivateKey($privateKey);
        openssl_private_decrypt(base64_decode($dataEncrypted), $dataDecrypted, $privateKey);

        if($dataDecrypted === null) {
            throw new AsymmetricEncryptionException(
                'cannot decrypt by private key',
                AsymmetricEncryptionException::CANNOT_DECRYPT
            );
        }

        return json_decode($dataDecrypted, true);
    }

    /**
     * Returns signature created for data with private key
     * @param mixed $data data to sign
     * @param string $privateKey private key
     * @param int $algorithm openssl algorithm
     * @return string signature
     * @throws AsymmetricEncryptionException
     * @throws JsonException
     */
    public static function sign($data, string $privateKey, int $algorithm = OPENSSL_ALGO_SHA256): string
    {
        static::validatePrivateKey($privateKey);
        openssl_sign(JsonHelper::encode($data), $signature, $privateKey, $algorithm);
        return $signature;
    }

    /**
     * Verifies the signature
     * @param mixed $data data to verify signature for
     * @param string $signature signature to verify
     * @param string $publicKey public key to verfy signature with
     * @param int $algorithm openssl algorithm
     * @throws AsymmetricEncryptionException if verification failure
     * @throws JsonException
     */
    public static function verify(
        $data,
        string $signature,
        string $publicKey,
        int $algorithm = OPENSSL_ALGO_SHA256
    ): void {
        static::validatePublicKey($publicKey);
        if(!openssl_verify(JsonHelper::encode($data), $signature, $publicKey, $algorithm)) {
            throw new AsymmetricEncryptionException('wrong signature', AsymmetricEncryptionException::CANNOT_VERIFY);
        }
    }

    /**
     * Validates public key
     * @param string $publicKey public key to validate
     * @throws AsymmetricEncryptionException if key is invalid
     */
    public static function validatePublicKey(string $publicKey): void
    {
        static::validateKey($publicKey, 'PUBLIC');
    }

    /**
     * Validates private key
     * @param string $privateKey private key to validate
     * @throws AsymmetricEncryptionException if key is invalid
     */
    public static function validatePrivateKey(string $privateKey): void
    {
        static::validateKey($privateKey, 'PRIVATE');
    }

    /**
     * Validates key
     * @param string $key key to validate
     * @param string $keyType key type (PUBLIC or PRIVATE)
     * @throws AsymmetricEncryptionException if key is invalid
     */
    protected static function validateKey(string $key, string $keyType): void
    {
        $arPublicKey = explode("\n", $key);
        $beginString = array_shift($arPublicKey);
        $endLineBreak = array_pop($arPublicKey);
        $endString = array_pop($arPublicKey);
        $lastPart = array_pop($arPublicKey);

        $isCorrect = true;

        if(
            $endLineBreak !== "" ||
            $beginString !== "-----BEGIN {$keyType} KEY-----" ||
            $endString !== "-----END {$keyType} KEY-----" ||
            !preg_match('/^.{1,63}$/', $lastPart ?? '')
        ) {
            $isCorrect = false;
        } else {
            foreach($arPublicKey as $part) {
                if(!preg_match('/^.{64}$/', $part)) {
                    $isCorrect = false;
                    break;
                }
            }
        }

        if(!$isCorrect) {
            throw new AsymmetricEncryptionException(
                'invalid key format',
                AsymmetricEncryptionException::INVALID_KEY_FORMAT
            );
        }
    }
}
