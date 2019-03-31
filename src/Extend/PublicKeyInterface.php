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

use FurqanSiddiqui\BIP32\ECDSA\FailSafeCurveValidate;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Interface PublicKeyInterface
 * @package FurqanSiddiqui\BIP32\Extend
 */
interface PublicKeyInterface
{
    /**
     * PublicKeyInterface constructor.
     * @param PrivateKeyInterface $keyPair
     */
    public function __construct(PrivateKeyInterface $keyPair);

    /**
     * @return Binary
     */
    public function raw(): Binary;

    /**
     * @return Binary
     */
    public function compressed(): Binary;

    /**
     * @return FailSafeCurveValidate
     */
    public function failSafeCurveValidate(): FailSafeCurveValidate;

    /**
     * @return int
     */
    public function curve(): int;

    /**
     * @return Vector
     */
    public function vector(): Vector;

    /**
     * @return PrivateKeyInterface
     */
    public function privateKey(): PrivateKeyInterface;
}