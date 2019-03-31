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

namespace FurqanSiddiqui\BIP32\Extend;

use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\DataTypes\Binary;

/**
 * Interface PrivateKeyInterface
 * @package FurqanSiddiqui\BIP32\Extend
 */
interface PrivateKeyInterface
{
    /**
     * @param string $prop
     * @param $value
     * @return PrivateKeyInterface
     */
    public function set(string $prop, $value): self;

    /**
     * @return int|null
     */
    public function getEllipticCurve(): ?int;

    /**
     * @return Curves
     */
    public function curves(): Curves;

    /**
     * @return Binary
     */
    public function raw(): Binary;

    /**
     * @return PublicKeyInterface
     */
    public function publicKey(): PublicKeyInterface;
}