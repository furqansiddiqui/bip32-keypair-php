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

use Charcoal\Buffers\AbstractByteArray;
use Charcoal\Buffers\Frames\Bytes32;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Buffers\Signature;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
readonly class PublicKey implements PublicKeyInterface
{
    /** @var \FurqanSiddiqui\BIP32\Buffers\Bits32 */
    public Bits32 $fingerPrint;
    /** @var bool */
    public bool $isComplete;

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \Charcoal\Buffers\AbstractByteArray $publicKey
     * @return static
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public static function fromUncompressed(BIP32 $bip32, AbstractByteArray $publicKey): static
    {
        $pub = \FurqanSiddiqui\ECDSA\ECC\PublicKey::fromDER($publicKey);
        return new static($bip32, $pub);
    }

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\ECDSA\ECC\PublicKey $eccPublicKey
     */
    public function __construct(
        public BIP32                               $bip32,
        public \FurqanSiddiqui\ECDSA\ECC\PublicKey $eccPublicKey
    )
    {
        $this->isComplete = strlen($this->eccPublicKey->y) === 64;
        $this->fingerPrint = new Bits32(
            substr(hash("ripemd160", hash("sha256", $this->compressed()->raw(), true), true), 0, 4)
        );
    }

    /**
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function compressed(): AbstractByteArray
    {
        return $this->eccPublicKey->getCompressed();
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Signature $sig
     * @param \Charcoal\Buffers\Frames\Bytes32 $msgHash
     * @param int|null $recId
     * @return bool
     */
    public function verifyPublicKey(Signature $sig, Bytes32 $msgHash, ?int $recId = null): bool
    {
        if (!$this->isComplete) {
            return false;
        }

        $recPub = $this->bip32->ecc->recoverPublicKeyFromSignature($sig->eccSignature, $msgHash, $recId);
        return $this->eccPublicKey->compare($recPub) === 0;
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Signature $sig
     * @param \Charcoal\Buffers\Frames\Bytes32 $msgHash
     * @return bool
     */
    public function verifySignature(Signature $sig, Bytes32 $msgHash): bool
    {
        if (!$this->isComplete) {
            return false;
        }

        return $this->bip32->ecc->verify($this->eccPublicKey, $sig->eccSignature, $msgHash);
    }

    /**
     * @param \FurqanSiddiqui\BIP32\KeyPair\PublicKey|\FurqanSiddiqui\ECDSA\ECC\PublicKey $pub2
     * @return int
     */
    public function compare(PublicKey|\FurqanSiddiqui\ECDSA\ECC\PublicKey $pub2): int
    {
        if ($pub2 instanceof self) {
            $pub2 = $pub2->eccPublicKey;
        }

        if ($this->isComplete) {
            return $this->eccPublicKey->compare($pub2);
        }

        if (hash_equals($this->eccPublicKey->x, $pub2->x)) {
            if (hash_equals($this->eccPublicKey->prefix, $pub2->prefix)) {
                return 0;
            }

            return -3;
        }

        return -1;
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Signature $sig
     * @param \Charcoal\Buffers\Frames\Bytes32 $msgHash
     * @return int|bool
     */
    public function findRecoveryId(Signature $sig, Bytes32 $msgHash): int|bool
    {
        if ($this->isComplete) {
            for ($i = 0; $i < 4; $i++) {
                try {
                    $recPub = $this->bip32->ecc->recoverPublicKeyFromSignature($sig->eccSignature, $msgHash, $i);
                    if ($this->eccPublicKey->compare($recPub) === 0) {
                        return $i;
                    }
                } catch (\Exception) {
                }
            }
        }

        return false;
    }
}
