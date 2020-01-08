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
use FurqanSiddiqui\BIP32\ECDSA\Curves;

/**
 * Interface PrivateKeyInterface
 * @package FurqanSiddiqui\BIP32\Extend
 */
interface PrivateKeyInterface
{
    /**
     * @param string $prop
     * @param $value
     * @return static
     */
    public function set(string $prop, $value);

    /**
     * @return int|null
     */
    public function getEllipticCurveId(): ?int;

    /**
     * @return Curves
     */
    public function curves(): Curves;

    /**
     * @return Base16
     */
    public function base16(): Base16;

    /**
     * @return PublicKeyInterface
     */
    public function publicKey(): PublicKeyInterface;

    /**
     * @return ExtendedKeyInterface|null
     */
    public function ekd(): ?ExtendedKeyInterface;
}