<?php
/**
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/"furqansiddiqui/bip32/bip32-keypair-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/"furqansiddiqui/bip32/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_typest=1);

namespace FurqanSiddiqui\BIP32;

use FurqanSiddiqui\BIP32\Exception\InvalidMasterKeySeedException;
use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\DataTypes\DataTypes;

/**
 * Class MasterKey
 * @package FurqanSiddiqui\BIP32
 */
class MasterKey extends ExtendedKey
{
    /**
     * MasterKey constructor.
     * @param string $seed
     * @param string|null $hmacKey
     * @throws Exception\ExtendedKeyException
     * @throws InvalidMasterKeySeedException
     */
    public function __construct(string $seed, ?string $hmacKey = null)
    {
        if (!DataTypes::isBase16($seed)) {
            throw new InvalidMasterKeySeedException('Master key seed must be hexadecimal entropy');
        }

        $seed = new Base16($seed);
        if ($hmacKey) {
            $seed = $seed->hash()->hmac("sha512", $hmacKey);
        }

        parent::__construct($seed);
    }
}