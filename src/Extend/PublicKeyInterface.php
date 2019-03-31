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
    public function __construct(PrivateKeyInterface $keyPair);

    public function raw(): Binary;

    public function compressed(): Binary;

    public function failSafeCurveValidate(): FailSafeCurveValidate;

    public function curve(): int;

    public function vector(): Vector;

    public function privateKey(): PrivateKeyInterface;
}