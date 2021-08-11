<?php

namespace Smoren\EncryptionTools\Exceptions;

class AsymmetricEncryptionException extends EncryptionException
{
    const CANNOT_DECRYPT = 1;
    const INVALID_KEY_FORMAT = 2;
    const CANNOT_VERIFY = 3;
}
