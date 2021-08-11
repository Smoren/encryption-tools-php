<?php

namespace app\tests\unit;

use Codeception\Test\Unit;
use Smoren\EncryptionTools\EncryptionHelper;
use Smoren\EncryptionTools\Exceptions\EncryptionHelperException;

class CommonTest extends Unit
{
    public function testHelper()
    {
        $data = [1, 2, 3, "asd", "test" => "фыв"];

        [$privateKey, $publicKey] = EncryptionHelper::generateRsaPair();
        [$anotherPrivateKey, $anotherPublicKey] = EncryptionHelper::generateRsaPair();

        $dataEncrypted = EncryptionHelper::encryptByPrivateKey($data, $privateKey);
        $dataDecrypted = EncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            EncryptionHelper::decryptByPublicKey($dataEncrypted, $anotherPublicKey);
            $this->fail();
        } catch(EncryptionHelperException $e) {
            $this->assertEquals(EncryptionHelperException::INCORRECT_KEY, $e->getCode());
        }

        try {
            EncryptionHelper::decryptByPublicKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(EncryptionHelperException $e) {
            $this->assertEquals(EncryptionHelperException::INVALID_KEY_FORMAT, $e->getCode());
        }

        $dataEncrypted = EncryptionHelper::encryptByPublicKey($data, $publicKey);
        $dataDecrypted = EncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            EncryptionHelper::decryptByPrivateKey($dataEncrypted, $anotherPrivateKey);
            $this->fail();
        } catch(EncryptionHelperException $e) {
            $this->assertEquals(EncryptionHelperException::INCORRECT_KEY, $e->getCode());
        }

        try {
            EncryptionHelper::decryptByPrivateKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(EncryptionHelperException $e) {
            $this->assertEquals(EncryptionHelperException::INVALID_KEY_FORMAT, $e->getCode());
        }
    }
}
