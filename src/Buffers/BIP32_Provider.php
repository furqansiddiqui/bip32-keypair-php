<?php
/*
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/furqansiddiqui/bip32-keypair-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\Buffers;

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Bytes32;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\KeyPair\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\KeyPair\PublicKeyInterface;

/**
 * Interface BIP32_Provider
 * @package FurqanSiddiqui\BIP32\Buffers
 */
interface BIP32_Provider
{
    /**
     * @param \Comely\Buffer\Bytes32 $entropy
     * @return \FurqanSiddiqui\BIP32\KeyPair\PrivateKeyInterface
     */
    public function privateKeyFromEntropy(Bytes32 $entropy): PrivateKeyInterface;

    /**
     * @param \Comely\Buffer\AbstractByteArray $compressedPubKey
     * @return \FurqanSiddiqui\BIP32\KeyPair\PublicKeyInterface
     */
    public function publicKeyFromIncomplete(AbstractByteArray $compressedPubKey): PublicKeyInterface;

    /**
     * @return \FurqanSiddiqui\BIP32\BIP32
     */
    public function bip32(): BIP32;
}
