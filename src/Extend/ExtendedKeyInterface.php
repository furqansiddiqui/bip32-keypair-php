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

namespace FurqanSiddiqui\BIP32\Extend;

use Comely\DataTypes\Buffer\Base16;
use Comely\DataTypes\Buffer\Binary;
use FurqanSiddiqui\BIP32\ECDSA\Curves;

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
     * @return Base16
     */
    public function chainCode(): Base16;

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

    /**
     * @return ExtendedKeyInterface|null
     */
    public function parent(): ?ExtendedKeyInterface;

    /**
     * @return Base16|null
     */
    public function childNumber(): ?Base16;

    /**
     * @param int $versionBytes
     * @return Binary
     */
    public function serializePublicKey(int $versionBytes): Binary;

    /**
     * @param int $versionBytes
     * @return Binary
     */
    public function serializePrivateKey(int $versionBytes): Binary;
}