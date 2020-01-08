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

/**
 * Class MasterKey
 * @package FurqanSiddiqui\BIP32
 */
class MasterKey extends ExtendedKey
{
    /**
     * MasterKey constructor.
     * @param Base16 $seed
     * @param string|null $hmacKey
     * @throws Exception\ExtendedKeyException
     */
    public function __construct(Base16 $seed, ?string $hmacKey = null)
    {
        $binary = $seed->binary();
        if (!in_array($binary->size()->bits(), [128, 256, 512])) {
            throw new \LengthException('Base16 seed must be 128, 256 or 512-bit long');
        }

        if ($hmacKey) {
            $binary = $binary->hash()->hmac("sha512", $hmacKey);
        }

        parent::__construct($binary);
    }
}