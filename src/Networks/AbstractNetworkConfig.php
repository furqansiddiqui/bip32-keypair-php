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
    /** @var static */
    protected static self $instance;

    /**
     * @return static
     */
    public static function loadConfig(): static
    {
        if (isset(static::$instance)) {
            return static::$instance;
        }

        return static::$instance = static::createConfigInstance();
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $exportPrivateKeyPrefix
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $exportPublicKeyPrefix
     * @param int $hardenedIndexBeginsFrom
     * @param string $hmacSeed
     */
    final protected function __construct(
        public readonly Bits32 $exportPrivateKeyPrefix,
        public readonly Bits32 $exportPublicKeyPrefix,
        public readonly int    $hardenedIndexBeginsFrom,
        public readonly string $hmacSeed,
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
