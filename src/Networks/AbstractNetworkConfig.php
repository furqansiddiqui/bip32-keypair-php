<?php
/*
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/furqansiddiqui/bip32-keypair-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

namespace FurqanSiddiqui\BIP32\Networks;

use FurqanSiddiqui\BIP32\Buffers\Bits32;

/**
 * Class NetworkConfig
 * @package FurqanSiddiqui\BIP32\Networks
 */
abstract class AbstractNetworkConfig
{
    /** @var array */
    protected static array $instances = [];

    /**
     * @return static
     */
    public static function loadConfig(): static
    {
        if (isset(static::$instances[static::class])) {
            return static::$instances[static::class];
        }

        return static::$instances[static::class] = static::createConfigInstance();
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $exportPrivateKeyPrefix
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $exportPublicKeyPrefix
     * @param int $hardenedIndexBeginsFrom
     * @param string $hmacSeed
     * @param string $base58Charset
     * @param bool $base58CaseSensitive
     */
    public function __construct(
        public readonly Bits32 $exportPrivateKeyPrefix,
        public readonly Bits32 $exportPublicKeyPrefix,
        public readonly int    $hardenedIndexBeginsFrom,
        public readonly string $hmacSeed,
        public readonly string $base58Charset,
        public readonly bool   $base58CaseSensitive,
    )
    {
    }

    /**
     * @return static
     */
    abstract public static function createConfigInstance(): static;

    /**
     * @return \GMP
     */
    public function secp256k1_nOrder(): \GMP
    {
        return gmp_init("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    }
}
