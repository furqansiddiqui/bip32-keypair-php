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

/**
 * Interface PublicKeyInterface
 * @package FurqanSiddiqui\BIP32\Extend
 */
interface PublicKeyInterface
{
    /**
     * @return int|null
     */
    public function getEllipticCurveId(): ?int;

    /**
     * @return Base16
     */
    public function full(): Base16;

    /**
     * @return Base16
     */
    public function compressed(): Base16;

    /**
     * @return bool
     */
    public function hasPrivateKey(): bool;

    /**
     * @return PrivateKeyInterface|null
     */
    public function privateKey(): ?PrivateKeyInterface;

    /**
     * @return Base16
     */
    public function fingerPrint(): Base16;
}