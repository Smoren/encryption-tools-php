<?php

namespace Smoren\EncryptionTools\Exceptions;

class SymmetricEncryptionException extends EncryptionException
{
    const CANNOT_DECRYPT = 1;
    const UNKNOWN_METHOD = 2;
}
