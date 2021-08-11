<?php

namespace app\tests\unit;

use Codeception\Test\Unit;
use Smoren\EncryptionTools\Exceptions\SymmetricEncryptionException;
use Smoren\EncryptionTools\Helpers\AsymmetricEncryptionHelper;
use Smoren\EncryptionTools\Exceptions\AsymmetricEncryptionException;
use Smoren\EncryptionTools\Helpers\SymmetricEncryptionHelper;

class CommonTest extends Unit
{
    /**
     * @throws SymmetricEncryptionException
     */
    public function testSymmetricEncryptionHelper()
    {
        $data = [1, 2, 3, "asd", "test" => "фыв"];
        $secretKey = uniqid();

        $dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $secretKey);
        $dataDecrypted = SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey);
        $this->assertEquals($data, $dataDecrypted);

        $dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $secretKey, 'aes-128-cbc');
        $dataDecrypted = SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey, 'aes-128-cbc');
        $this->assertEquals($data, $dataDecrypted);

        $dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $secretKey, 'camellia-256-ofb');
        $dataDecrypted = SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey, 'camellia-256-ofb');
        $this->assertEquals($data, $dataDecrypted);

        try {
            SymmetricEncryptionHelper::decrypt($dataEncrypted, uniqid());
        } catch(SymmetricEncryptionException $e) {
            $this->assertEquals(SymmetricEncryptionException::INCORRECT_KEY, $e->getCode());
        }

        try {
            SymmetricEncryptionHelper::encrypt($dataEncrypted, $secretKey, 'unknown-method');
        } catch(SymmetricEncryptionException $e) {
            $this->assertEquals(SymmetricEncryptionException::UNKNOWN_METHOD, $e->getCode());
        }

        try {
            SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey, 'unknown-method');
        } catch(SymmetricEncryptionException $e) {
            $this->assertEquals(SymmetricEncryptionException::UNKNOWN_METHOD, $e->getCode());
        }
    }

    /**
     * @throws AsymmetricEncryptionException
     */
    public function testAsymmetricEncryptionHelper()
    {
        $data = [1, 2, 3, "asd", "test" => "фыв"];

        [$privateKey, $publicKey] = AsymmetricEncryptionHelper::generateKeyPair();
        [$anotherPrivateKey, $anotherPublicKey] = AsymmetricEncryptionHelper::generateKeyPair();

        $dataEncrypted = AsymmetricEncryptionHelper::encryptByPrivateKey($data, $privateKey);
        $dataDecrypted = AsymmetricEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            AsymmetricEncryptionHelper::decryptByPublicKey($dataEncrypted, $anotherPublicKey);
            $this->fail();
        } catch(AsymmetricEncryptionException $e) {
            $this->assertEquals(AsymmetricEncryptionException::INCORRECT_KEY, $e->getCode());
        }

        try {
            AsymmetricEncryptionHelper::decryptByPublicKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(AsymmetricEncryptionException $e) {
            $this->assertEquals(AsymmetricEncryptionException::INVALID_KEY_FORMAT, $e->getCode());
        }

        $dataEncrypted = AsymmetricEncryptionHelper::encryptByPublicKey($data, $publicKey);
        $dataDecrypted = AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, $anotherPrivateKey);
            $this->fail();
        } catch(AsymmetricEncryptionException $e) {
            $this->assertEquals(AsymmetricEncryptionException::INCORRECT_KEY, $e->getCode());
        }

        try {
            AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(AsymmetricEncryptionException $e) {
            $this->assertEquals(AsymmetricEncryptionException::INVALID_KEY_FORMAT, $e->getCode());
        }
    }

    /**
     * @throws AsymmetricEncryptionException
     * @throws SymmetricEncryptionException
     */
    public function testTogether()
    {
        $data = "some secret string";
        $passphrase = uniqid();

        [$privateKey, $publicKey] = AsymmetricEncryptionHelper::generateKeyPair();
        $privateKeyEncrypted = SymmetricEncryptionHelper::encrypt($privateKey, $passphrase);
        $dataEncrypted = AsymmetricEncryptionHelper::encryptByPublicKey($data, $publicKey);

        $privateKeyDecrypted = SymmetricEncryptionHelper::decrypt($privateKeyEncrypted, $passphrase);
        $dataDecrypted = AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKeyDecrypted);

        $this->assertEquals($data, $dataDecrypted);
    }
}
