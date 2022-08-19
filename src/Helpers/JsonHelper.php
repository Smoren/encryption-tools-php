<?php

namespace Smoren\EncryptionTools\Helpers;

use Smoren\EncryptionTools\Exceptions\JsonException;

/**
 * Class JsonHelper
 * @author Smoren <ofigate@gmail.com>
 */
class JsonHelper
{
    /**
     * Converts value to JSON format
     * @param mixed $value
     * @return string
     * @throws JsonException
     */
    public static function encode($value): string
    {
        $result = json_encode($value);
        if($error = json_last_error()) {
            throw new JsonException(json_last_error_msg(), $error);
        }

        /** @var string $result */
        return $result;
    }

    /**
     * Parses JSON to PHP value
     * @param string $json
     * @return mixed
     * @throws JsonException
     */
    public static function decode(string $json)
    {
        $result = json_decode($json, true);
        if($error = json_last_error()) {
            throw new JsonException(json_last_error_msg(), $error);
        }

        return $result;
    }
}
