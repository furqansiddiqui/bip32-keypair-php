<?php
/**
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/furqansiddiqui/bip32-keypair-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\ECDSA;

use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\ECDSA;
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Class Vectors
 * @package FurqanSiddiqui\BIP32\ECDSA
 */
class Vectors
{
    /**
     * @param int $curve
     * @param Binary $privateKey
     * @return Vector
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function Curve(int $curve, Binary $privateKey): Vector
    {
        switch ($curve) {
            case Curves::SECP256K1:
                return ECDSA::Secp256k1()->vectorFromPrivateKey($privateKey);
            case Curves::SECP256K1_OPENSSL:
                return ECDSA::Secp256k1_OpenSSL()->vectorFromPrivateKey($privateKey);
            default:
                throw new \InvalidArgumentException('Invalid ECDSA curve');
        }
    }
}