# encryption-tools

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/smoren/encryption-tools)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Smoren/encryption-tools-php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Smoren/encryption-tools-php/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/Smoren/encryption-tools-php/badge.svg?branch=master)](https://coveralls.io/github/Smoren/encryption-tools-php?branch=master)
![Build and test](https://github.com/Smoren/encryption-tools-php/actions/workflows/test_master.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Tools for encryption/decryption and signing/verifying (wraps openssl lib).

* Symmetric
* Asymmetric (RSA-based)

### Install to your project
```shell script
composer require smoren/encryption-tools
``` 

### Unit testing
```shell script
composer install
composer test-init
composer test
```

### Usage

#### Symmetric encryption/decryption
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

$dataEncrypted = AsymmetricEncryptionHelper::encryptByPrivateKey($data, $privateKey);
$dataDecrypted = AsymmetricEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
print_r($dataDecrypted);

$dataEncrypted = AsymmetricEncryptionHelper::encryptByPublicKey($data, $publicKey);
$dataDecrypted = AsymmetricEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
print_r($dataDecrypted);
```

#### Asymmetric signing/verifying (RSA-based)
```php
use Smoren\EncryptionTools\Helpers\AsymmetricEncryptionHelper;
use Smoren\EncryptionTools\Exceptions\AsymmetricEncryptionException;

$data = ["some", "data" => "to", "encrypt"];
[$privateKey, $publicKey] = AsymmetricEncryptionHelper::generateKeyPair();

$signature = AsymmetricEncryptionHelper::sign($data, $privateKey);

try {
    AsymmetricEncryptionHelper::verify($data, $signature, $publicKey);
} catch(AsymmetricEncryptionException $e) {
    // ... handling exception if cannot verify signature
}
```

#### Asymmetric encryption/decryption (RSA-based) for lage data
```php
use Smoren\EncryptionTools\Helpers\AsymmetricLargeDataEncryptionHelper;

$data = file_get_contents('file_with_large_data.txt');
[$privateKey, $publicKey] = AsymmetricLargeDataEncryptionHelper::generateKeyPair();

$dataEncrypted = AsymmetricLargeDataEncryptionHelper::encryptByPrivateKey($data, $privateKey);
$dataDecrypted = AsymmetricLargeDataEncryptionHelper::decryptByPublicKey($dataEncrypted, $publicKey);
print_r($dataDecrypted);

$dataEncrypted = AsymmetricLargeDataEncryptionHelper::encryptByPublicKey($data, $publicKey);
$dataDecrypted = AsymmetricLargeDataEncryptionHelper::decryptByPrivateKey($dataEncrypted, $privateKey);
print_r($dataDecrypted);
```
