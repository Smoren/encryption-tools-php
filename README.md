# encryption-tools
Tools for encryption/decryption using RSA key pair

### Install to your project
```shell script
composer require smoren/encryption-tools
``` 

### Unit testing
```shell script
composer install
./vendor/bin/codecept build
./vendor/bin/codecept run unit tests/unit
```

### Demo

```php
use Smoren\EncryptionTools\Helpers\RsaEncryptionHelper;

$data = ["some", "data" => "to", "encrypt"];
[$privateKey, $publicKey] = RsaEncryptionHelper::generateKeyPair();
[$anotherPrivateKey, $anotherPublicKey] = RsaEncryptionHelper::generateKeyPair();

$dataEncrypted = RsaEncryptionHelper::encryptByPrivateKey($data, $privateKey);
$dataDecrypted = RsaEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
print_r($dataDecrypted);

$dataEncrypted = RsaEncryptionHelper::encryptByPublicKey($data, $publicKey);
$dataDecrypted = RsaEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
print_r($dataDecrypted);
```
