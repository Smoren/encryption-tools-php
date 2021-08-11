<?php

namespace app\tests\unit;

use Codeception\Test\Unit;
use Smoren\EncryptionTools\RsaEncryptionHelper;
use Smoren\EncryptionTools\Exceptions\RsaEncryptionHelperException;

class CommonTest extends Unit
{
    /**
     * @throws RsaEncryptionHelperException
     */
    public function testHelper()
    {
        $data = [1, 2, 3, "asd", "test" => "фыв"];

        [$privateKey, $publicKey] = RsaEncryptionHelper::generateKeyPair();
        [$anotherPrivateKey, $anotherPublicKey] = RsaEncryptionHelper::generateKeyPair();

        $dataEncrypted = RsaEncryptionHelper::encryptByPrivateKey($data, $privateKey);
        $dataDecrypted = RsaEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            RsaEncryptionHelper::decryptByPublicKey($dataEncrypted, $anotherPublicKey);
            $this->fail();
        } catch(RsaEncryptionHelperException $e) {
            $this->assertEquals(RsaEncryptionHelperException::INCORRECT_KEY, $e->getCode());
        }

        try {
            RsaEncryptionHelper::decryptByPublicKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(RsaEncryptionHelperException $e) {
            $this->assertEquals(RsaEncryptionHelperException::INVALID_KEY_FORMAT, $e->getCode());
        }

        $dataEncrypted = RsaEncryptionHelper::encryptByPublicKey($data, $publicKey);
        $dataDecrypted = RsaEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            RsaEncryptionHelper::decryptByPrivateKey($dataEncrypted, $anotherPrivateKey);
            $this->fail();
        } catch(RsaEncryptionHelperException $e) {
            $this->assertEquals(RsaEncryptionHelperException::INCORRECT_KEY, $e->getCode());
        }

        try {
            RsaEncryptionHelper::decryptByPrivateKey($dataEncrypted, 'invalid_key_format_value');
            $this->fail();
        } catch(RsaEncryptionHelperException $e) {
            $this->assertEquals(RsaEncryptionHelperException::INVALID_KEY_FORMAT, $e->getCode());
        }
    }
}
