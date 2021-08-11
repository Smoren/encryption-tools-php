<?php

namespace Smoren\EncryptionTools\Exceptions;

use Smoren\ExtendedExceptions\BadDataException;

class EncryptionHelperException extends BadDataException
{
    const INVALID_KEY_FORMAT = 1;
    const INCORRECT_KEY = 2;
}