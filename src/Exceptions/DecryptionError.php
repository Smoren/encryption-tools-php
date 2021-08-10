<?php

namespace Smoren\EncryptionTools\Exceptions;

use Smoren\ExtendedExceptions\BadDataException;

class DecryptionError extends BadDataException
{
    const INVALID_KEY = 1;
}