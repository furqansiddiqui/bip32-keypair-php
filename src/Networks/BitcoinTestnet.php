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

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\Networks;

use FurqanSiddiqui\BIP32\Buffers\Bits32;

/**
 * Class BitcoinTestnet
 * @package FurqanSiddiqui\BIP32\Networks
 */
class BitcoinTestnet extends AbstractNetworkConfig
{
    /**
     * @return static
     */
    public static function createConfigInstance(): static
    {
        return new static(
            exportPrivateKeyPrefix: new Bits32(hex2bin("04358394")),
            exportPublicKeyPrefix: new Bits32(hex2bin("043587CF")),
            hardenedIndexBeginsFrom: 0x80000000,
            hmacSeed: "Bitcoin seed",
            base58Charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            base58CaseSensitive: true,
        );
    }
}
