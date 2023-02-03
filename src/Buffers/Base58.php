<?php
/*
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\Buffers;

use Comely\Buffer\BigInteger\BaseCharset;

/**
 * Class Base58
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class Base58 extends BaseCharset
{
    /** @var static */
    private static self $instance;

    /**
     * @return static
     */
    public static function Charset(): static
    {
        if (!isset(static::$instance)) {
            static::$instance = new static();
        }

        return static::$instance;
    }

    /**
     * Base58 charset constructor
     */
    private function __construct()
    {
        return parent::__construct(
            charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            caseSensitive: true
        );
    }
}
