<?php

namespace app\tests\unit;

use Codeception\Test\Unit;
use Smoren\EncryptionTools\EncryptionHelper;
use Smoren\EncryptionTools\Exceptions\DecryptionError;

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
        } catch(DecryptionError $e) {
            $this->assertTrue(true);
        }

        $dataEncrypted = EncryptionHelper::encryptByPublicKey($data, $publicKey);
        $dataDecrypted = EncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
        $this->assertEquals($data, $dataDecrypted);

        try {
            EncryptionHelper::decryptByPrivateKey($dataEncrypted, $anotherPrivateKey);
            $this->fail();
        } catch(DecryptionError $e) {
            $this->assertTrue(true);
        }
    }
}
