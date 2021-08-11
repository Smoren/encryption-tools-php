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

#### Symmetric encryption
```php
use Smoren\EncryptionTools\Helpers\SymmetricEncryptionHelper;

$data = ["some", "data" => "to", "encrypt"];
$secretKey = uniqid();

$dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $secretKey);
$dataDecrypted = SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey);
print_r($dataDecrypted);

$dataEncrypted = SymmetricEncryptionHelper::encrypt($data, $secretKey, 'camellia-256-ofb');
$dataDecrypted = SymmetricEncryptionHelper::decrypt($dataEncrypted, $secretKey, 'camellia-256-ofb');
print_r($dataDecrypted);
```

#### Asymmetric encryption/decryption (RSA-based)
```php
use Smoren\EncryptionTools\Helpers\AsymmetricEncryptionHelper;

$data = ["some", "data" => "to", "encrypt"];
[$privateKey, $publicKey] = AsymmetricEncryptionHelper::generateKeyPair();
[$anotherPrivateKey, $anotherPublicKey] = AsymmetricEncryptionHelper::generateKeyPair();

$dataEncrypted = AsymmetricEncryptionHelper::encryptByPrivateKey($data, $privateKey);
$dataDecrypted = AsymmetricEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
print_r($dataDecrypted);

$dataEncrypted = AsymmetricEncryptionHelper::encryptByPublicKey($data, $publicKey);
$dataDecrypted = AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
print_r($dataDecrypted);
```
