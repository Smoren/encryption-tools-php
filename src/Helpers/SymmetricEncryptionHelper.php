<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\SymmetricEncryptionException;

class SymmetricEncryptionHelper
{
    /**
     * @param mixed $data
     * @param string $secretKey
     * @param string $cipherMethod
     * @return string
     * @throws SymmetricEncryptionException
     */
    public static function encrypt($data, string $secretKey, string $cipherMethod = 'aes-256-cbc'): string
    {
        static::checkCipherMethodAvailable($cipherMethod);
        /** @var string $data */
        $data = json_encode($data); // TODO throw exception if false

        $ivLen = openssl_cipher_iv_length($cipherMethod);
        if($ivLen === false) {
            throw new SymmetricEncryptionException(
                'openssl_cipher_iv_length() returned false',
                SymmetricEncryptionException::OPENSSL_ERROR
            );
        }
        $iv = openssl_random_pseudo_bytes($ivLen);
        if($iv === false) {
            throw new SymmetricEncryptionException(
                'openssl_random_pseudo_bytes() returned false',
                SymmetricEncryptionException::OPENSSL_ERROR
            );
        }
        $cipherText = openssl_encrypt($data, $cipherMethod, $secretKey, OPENSSL_RAW_DATA, $iv);
        if($cipherText === false) {
            throw new SymmetricEncryptionException(
                'openssl_encrypt() returned false',
                SymmetricEncryptionException::OPENSSL_ERROR
            );
        }
        $hmac = hash_hmac('sha256', $cipherText, $secretKey, true);

        return base64_encode($iv.$hmac.$cipherText);
    }

    /**
     * @param string $encryptedData
     * @param string $secretKey
     * @param string $cipherMethod
     * @return mixed
     * @throws SymmetricEncryptionException
     */
    public static function decrypt(string $encryptedData, string $secretKey, string $cipherMethod = 'aes-256-cbc')
    {
        static::checkCipherMethodAvailable($cipherMethod);

        $c = base64_decode($encryptedData);
        $ivLen = openssl_cipher_iv_length($cipherMethod);
        if($ivLen === false) {
            throw new SymmetricEncryptionException(
                'openssl_cipher_iv_length() returned false',
                SymmetricEncryptionException::OPENSSL_ERROR
            );
        }
        $iv = substr($c, 0, $ivLen);
        $hmac = substr($c, $ivLen, $sha2len=32);
        $cipherText = substr($c, $ivLen+$sha2len);

        $data = openssl_decrypt($cipherText, $cipherMethod, $secretKey, OPENSSL_RAW_DATA, $iv);

        if($data === false) {
            throw new SymmetricEncryptionException(
                'incorrect secret key',
                SymmetricEncryptionException::CANNOT_DECRYPT
            );
        }
        return json_decode($data, true);
    }

    /**
     * @return array
     */
    public static function getCipherMethodList(): array
    {
        return openssl_get_cipher_methods();
    }

    /**
     * @param string $cipherMethod
     * @throws SymmetricEncryptionException
     */
    public static function checkCipherMethodAvailable(string $cipherMethod)
    {
        if(!in_array($cipherMethod, static::getCipherMethodList(), true)) {
            throw new SymmetricEncryptionException(
                "unknown cipher method '{$cipherMethod}'",
                SymmetricEncryptionException::UNKNOWN_METHOD
            );
        }
    }
}
