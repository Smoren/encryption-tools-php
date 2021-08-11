<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\SymmetricEncryptionException;

class SymmetricEncryptionHelper
{
    /**
     * @param $data
     * @param string $secretKey
     * @param string $cipherMethod
     * @return string
     * @throws SymmetricEncryptionException
     */
    public static function encrypt($data, string $secretKey, string $cipherMethod = 'aes-256-cbc'): string
    {
        static::checkCipherMethodAvailable($cipherMethod);
        $data = json_encode($data);

        $ivLen = openssl_cipher_iv_length($cipherMethod);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $cipherText = openssl_encrypt($data, $cipherMethod, $secretKey, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $cipherText, $secretKey, true);

        return base64_encode($iv.$hmac.$cipherText);
    }

    public static function decrypt(string $encryptedData, string $secretKey, string $cipherMethod = 'aes-256-cbc')
    {
        static::checkCipherMethodAvailable($cipherMethod);

        $c = base64_decode($encryptedData);
        $ivLen = openssl_cipher_iv_length($cipherMethod);
        $iv = substr($c, 0, $ivLen);
        $hmac = substr($c, $ivLen, $sha2len=32);
        $cipherText = substr($c, $ivLen+$sha2len);

        $data = openssl_decrypt($cipherText, $cipherMethod, $secretKey, OPENSSL_RAW_DATA, $iv);

        if($data === false) {
            throw new SymmetricEncryptionException(
                'incorrect secret key',
                SymmetricEncryptionException::INCORRECT_KEY
            );
        }
        return json_decode($data, true);
    }

    public static function getCipherMethodList(): array
    {
        return openssl_get_cipher_methods();
    }

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