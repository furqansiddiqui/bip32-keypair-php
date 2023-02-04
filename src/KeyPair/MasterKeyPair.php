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

use Comely\Buffer\Bytes32;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Exception\ExtendedKeyException;
use FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException;

/**
 * Class MasterKey
 * @package FurqanSiddiqui\BIP32
 */
class MasterKeyPair extends ExtendedKeyPair
{
    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\BIP32\KeyPair\PublicKey|\FurqanSiddiqui\BIP32\KeyPair\PrivateKey $key
     * @param int $depth
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $childNum
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $parentPubFp
     * @param \Comely\Buffer\Bytes32 $chainCode
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public function __construct(BIP32 $bip32, PublicKey|PrivateKey $key, int $depth, Bits32 $childNum, Bits32 $parentPubFp, Bytes32 $chainCode)
    {
        if (!$childNum->isZeroBytes() || !$parentPubFp->isZeroBytes() || $depth !== 0) {
            throw new UnserializeBIP32KeyException('Cannot unserialize child key as MasterKeyPair');
        }

        parent::__construct($bip32, $key, $depth, $childNum, $parentPubFp, $chainCode);
    }

    /**
     * @param $path
     * @return \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     * @throws \FurqanSiddiqui\BIP32\Exception\ExtendedKeyException
     */
    public function derivePath($path): ExtendedKeyPair
    {
        $parts = explode("/", trim(strtolower($path), "/"));
        if ($parts[0] !== "m") {
            throw new ExtendedKeyException('Derivation path must start with "m"');
        }

        array_shift($parts); // Remove initial "m"
        $derivedKey = $this;
        foreach ($parts as $part) {
            if (!is_string($part) || !preg_match('/^[0-9]+\'?$/', $part)) {
                throw new ExtendedKeyException('Invalid index in derivation path');
            }

            $isHardened = str_ends_with($part, "'");
            $index = $isHardened ? substr($part, 0, -1) : $part;
            $derivedKey = $derivedKey->derive(intval($index), $isHardened);
        }

        return $derivedKey;
    }
}
