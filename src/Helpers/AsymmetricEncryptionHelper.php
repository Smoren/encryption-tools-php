<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\AsymmetricEncryptionException;

class AsymmetricEncryptionHelper
{
    /**
     * @return string[]
     */
    public static function generateKeyPair(): array
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
     * @throws AsymmetricEncryptionException
     */
    public static function encryptByPublicKey($data, string $publicKey): string
    {
        static::validatePublicKey($publicKey);
        openssl_public_encrypt(json_encode($data), $dataEncrypted, $publicKey);
        return base64_encode($dataEncrypted);
    }

    /**
     * @param mixed $data
     * @param string $privateKey
     * @return string
     * @throws AsymmetricEncryptionException
     */
    public static function encryptByPrivateKey($data, string $privateKey): string
    {
        static::validatePrivateKey($privateKey);
        openssl_private_encrypt(json_encode($data), $dataEncrypted, $privateKey);
        return base64_encode($dataEncrypted);
    }

    /**
     * @param string $dataEncrypted
     * @param string $publicKey
     * @return mixed
     * @throws AsymmetricEncryptionException
     */
    public static function decryptByPublicKey(string $dataEncrypted, string $publicKey)
    {
        static::validatePublicKey($publicKey);
        openssl_public_decrypt(base64_decode($dataEncrypted), $dataDecrypted, $publicKey);

        if($dataDecrypted === null) {
            throw new AsymmetricEncryptionException(
                'cannot decrypt by private key',
                AsymmetricEncryptionException::CANNOT_DECRYPT
            );
        }

        return json_decode($dataDecrypted, true);
    }

    /**
     * @param string $dataEncrypted
     * @param string $privateKey
     * @return mixed
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
     * @param mixed $data
     * @param string $privateKey
     * @param string|int $algorithm
     * @return mixed
     * @throws AsymmetricEncryptionException
     */
    public static function sign($data, string $privateKey, int $algorithm = OPENSSL_ALGO_SHA256): string
    {
        static::validatePrivateKey($privateKey);
        openssl_sign(json_encode($data), $signature, $privateKey, $algorithm);
        return $signature;
    }

    /**
     * @param mixed $data
     * @param string $signature
     * @param string $publicKey
     * @param string|int $algorithm
     * @throws AsymmetricEncryptionException
     */
    public static function verify($data, string $signature, string $publicKey, int $algorithm = OPENSSL_ALGO_SHA256)
    {
        static::validatePublicKey($publicKey);
        if(!openssl_verify(json_encode($data), $signature, $publicKey, $algorithm)) {
            throw new AsymmetricEncryptionException('wrong signature', AsymmetricEncryptionException::CANNOT_VERIFY);
        }
    }

    /**
     * @param string $key
     * @throws AsymmetricEncryptionException
     */
    public static function validatePublicKey(string $key)
    {
        static::validateKey($key, 'PUBLIC');
    }

    /**
     * @param string $key
     * @throws AsymmetricEncryptionException
     */
    public static function validatePrivateKey(string $key)
    {
        static::validateKey($key, 'PRIVATE');
    }

    /**
     * @param string $key
     * @param string $keyType
     * @throws AsymmetricEncryptionException
     */
    protected static function validateKey(string $key, string $keyType)
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
            !preg_match('/^.{1,63}$/', $lastPart)
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
