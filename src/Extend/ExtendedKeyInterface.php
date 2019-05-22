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
 * Interface ExtendedKeyInterface
 * @package FurqanSiddiqui\BIP32\Extend
 */
interface ExtendedKeyInterface
{
    /**
     * @return Binary
     */
    public function raw(): Binary;

    /**
     * @return int
     */
    public function depth(): int;

    /**
     * @param string $prop
     * @param $value
     * @return ExtendedKeyInterface
     */
    public function set(string $prop, $value): self;

    /**
     * @return Binary
     */
    public function chainCode(): Binary;

    /**
     * @return PrivateKeyInterface
     */
    public function privateKey(): PrivateKeyInterface;

    /**
     * @return PublicKeyInterface
     */
    public function publicKey(): PublicKeyInterface;

    /**
     * @return Curves
     */
    public function curves(): Curves;

    /**
     * @return int|null
     */
    public function getEllipticCurveId(): ?int;

    /**
     * @param $path
     * @return ExtendedKeyInterface
     */
    public function derivePath($path): self;
}