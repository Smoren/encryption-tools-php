<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\AsymmetricEncryptionException;
use Smoren\EncryptionTools\Exceptions\JsonException;
use Smoren\EncryptionTools\Exceptions\SymmetricEncryptionException;

/**
 * Class AsymmetricLargeDataEncryptionHelper
 * @author Smoren <ofigate@gmail.com>
 */
class AsymmetricLargeDataEncryptionHelper
{
    /**
     * Generates RSA key pair
     * @return string[] [$privateKey, $publicKey]
     * @throws AsymmetricEncryptionException
     */
    public static function generateKeyPair(): array
    {
        return AsymmetricEncryptionHelper::generateKeyPair();
    }

    /**
     * Returns data encrypted by public key
     * @param mixed $data data to encrypt
     * @param string $publicKey public key
     * @return string encrypted data
     * @throws AsymmetricEncryptionException
     * @throws JsonException
     */
    public static function encryptByPublicKey($data, string $publicKey, int $internalKeyLength = 128): string
    {
        $internalKey = static::generateRandomString($internalKeyLength);
        $internalKeyEncrypted = AsymmetricEncryptionHelper::encryptByPublicKey($internalKey, $publicKey);
        try {
            $dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $internalKey);
        } catch(SymmetricEncryptionException $e) {
            throw new AsymmetricEncryptionException(
                'cannot encrypt',
                AsymmetricEncryptionException::CANNOT_ENCRYPT,
                $e
            );
        }

        return strlen($internalKeyEncrypted).'_'.$internalKeyEncrypted.$dataEncrypted;
    }

    /**
     * Returns data encrypted by private key
     * @param mixed $data data to encrypt
     * @param string $privateKey public key
     * @return string encrypted data
     * @throws AsymmetricEncryptionException
     * @throws JsonException
     */
    public static function encryptByPrivateKey($data, string $privateKey, int $internalKeyLength = 128): string
    {
        $internalKey = static::generateRandomString($internalKeyLength);
        $internalKeyEncrypted = AsymmetricEncryptionHelper::encryptByPrivateKey($internalKey, $privateKey);
        try {
            $dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $internalKey);
        } catch(SymmetricEncryptionException $e) {
            throw new AsymmetricEncryptionException(
                'cannot encrypt',
                AsymmetricEncryptionException::CANNOT_ENCRYPT,
                $e
            );
        }

        return strlen($internalKeyEncrypted).'_'.$internalKeyEncrypted.$dataEncrypted;
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
        $matches = static::getPrefixMatches($dataEncrypted);

        $internalKeyEncrypted = substr($dataEncrypted, $matches[0], $matches[1]);
        /** @var string $internalKeyDecrypted */
        $internalKeyDecrypted = AsymmetricEncryptionHelper::decryptByPublicKey($internalKeyEncrypted, $publicKey);
        $dataPartEncrypted = substr($dataEncrypted, $matches[0]+$matches[1]);

        try {
            return SymmetricEncryptionHelper::decrypt($dataPartEncrypted, $internalKeyDecrypted);
        } catch(SymmetricEncryptionException $e) {
            throw new AsymmetricEncryptionException(
                'cannot decrypt',
                AsymmetricEncryptionException::CANNOT_DECRYPT,
                $e
            );
        }
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
        $matches = static::getPrefixMatches($dataEncrypted);

        $internalKeyEncrypted = substr($dataEncrypted, $matches[0], $matches[1]);
        /** @var string $internalKeyDecrypted */
        $internalKeyDecrypted = AsymmetricEncryptionHelper::decryptByPrivateKey($internalKeyEncrypted, $privateKey);
        $dataPartEncrypted = substr($dataEncrypted, $matches[0]+$matches[1]);

        try {
            return SymmetricEncryptionHelper::decrypt($dataPartEncrypted, $internalKeyDecrypted);
        } catch(SymmetricEncryptionException $e) {
            throw new AsymmetricEncryptionException(
                'cannot decrypt',
                AsymmetricEncryptionException::CANNOT_DECRYPT,
                $e
            );
        }
    }

    /**
     * Internal function-helper for decrypting
     * @param string $dataEncrypted encrypted data
     * @return array<int> [int, int]
     * @throws AsymmetricEncryptionException
     */
    protected static function getPrefixMatches(string $dataEncrypted): array
    {
        preg_match('/^([0-9]+)_/', $dataEncrypted, $matches);
        if(!isset($matches[1])) {
            throw new AsymmetricEncryptionException('cannot decrypt', AsymmetricEncryptionException::CANNOT_DECRYPT);
        }
        $matches[0] = strlen($matches[0]);

        return $matches;
    }

    /**
     * Generates random string
     * @param int $length string length
     * @return string random string
     */
    protected static function generateRandomString(int $length): string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';

        for($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }

        return $randomString;
    }
}
