<?php

namespace Smoren\EncryptionTools\Exceptions;

class SymmetricEncryptionException extends EncryptionException
{
    const INCORRECT_KEY = 1;
    const UNKNOWN_METHOD = 2;
}
