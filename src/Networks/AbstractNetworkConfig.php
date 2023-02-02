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
    abstract public static function loadConfig(): static;
}
