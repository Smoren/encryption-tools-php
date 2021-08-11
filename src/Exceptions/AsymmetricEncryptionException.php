<?php

namespace Smoren\EncryptionTools\Exceptions;

class AsymmetricEncryptionException extends EncryptionException
{
    const INCORRECT_KEY = 1;
    const INVALID_KEY_FORMAT = 2;
}
