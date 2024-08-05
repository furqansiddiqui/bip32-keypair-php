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

namespace FurqanSiddiqui\BIP32\KeyPair;

use Charcoal\Buffers\Frames\Bytes32;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException;

/**
 * Class MasterKeyPair
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class MasterKeyPair extends ExtendedKeyPair
{
    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\BIP32\KeyPair\PublicKey|\FurqanSiddiqui\BIP32\KeyPair\PrivateKey $key
     * @param int $depth
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $childNum
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $parentPubFp
     * @param \Charcoal\Buffers\Frames\Bytes32 $chainCode
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public function __construct(BIP32 $bip32, PublicKey|PrivateKey $key, int $depth, Bits32 $childNum, Bits32 $parentPubFp, Bytes32 $chainCode)
    {
        if (!$childNum->isZeroBytes() || !$parentPubFp->isZeroBytes() || $depth !== 0) {
            throw new UnserializeBIP32KeyException('Cannot unserialize child key as MasterKeyPair', debug: [
                "childNum" => $childNum->toInt(),
                "parentPubFp" => $parentPubFp->toInt(),
                "depth" => $depth,
            ]);
        }

        parent::__construct($bip32, $key, $depth, $childNum, $parentPubFp, $chainCode);
    }
}
