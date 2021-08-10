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
use Smoren\EncryptionTools\EncryptionHelper;

$data = ["some", "data" => "to", "encrypt"];
[$privateKey, $publicKey] = EncryptionHelper::generateRsaPair();
[$anotherPrivateKey, $anotherPublicKey] = EncryptionHelper::generateRsaPair();

$dataEncrypted = EncryptionHelper::encryptByPrivateKey($data, $privateKey);
$dataDecrypted = EncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
print_r($dataDecrypted);

$dataEncrypted = EncryptionHelper::encryptByPublicKey($data, $publicKey);
$dataDecrypted = EncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
print_r($dataDecrypted);
```
