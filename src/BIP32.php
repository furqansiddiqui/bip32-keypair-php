<?php
/**
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/furqansiddiqui/bip32-keypair-php
 *
 * Copyright (c) 2020 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32;

use Comely\DataTypes\Buffer\Base16;
use FurqanSiddiqui\BIP32\KeyPair\PrivateKey;

/**
 * Class BIP32
 * @package FurqanSiddiqui\BIP32
 */
class BIP32
{
    /**
     * @param Base16 $entropy
     * @return PrivateKey
     */
    public static function PrivateKey(Base16 $entropy): PrivateKey
    {
        return new PrivateKey($entropy);
    }

    /**
     * @param string $hexits
     * @return PrivateKey
     */
    public static function PrivateKeyFromHexits(string $hexits): PrivateKey
    {
        return self::PrivateKey(new Base16($hexits));
    }

    /**
     * @param string $seed
     * @param string $hmacKey
     * @return MasterKey
     * @throws Exception\ExtendedKeyException
     */
    public static function MasterKey(string $seed, string $hmacKey): MasterKey
    {
        return new MasterKey(new Base16($seed), $hmacKey);
    }
}