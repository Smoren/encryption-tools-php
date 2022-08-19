<?php

namespace Smoren\EncryptionTools\Exceptions;

class AsymmetricEncryptionException extends EncryptionException
{
    public const CANNOT_DECRYPT = 1;
    public const INVALID_KEY_FORMAT = 2;
    public const CANNOT_VERIFY = 3;
    public const CANNOT_ENCRYPT = 4;
    public const OPENSSL_ERROR = 5;
}
