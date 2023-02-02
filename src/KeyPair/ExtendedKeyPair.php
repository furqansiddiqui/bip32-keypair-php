<?php
/*
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\KeyPair;

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Buffer;
use Comely\Buffer\Bytes32;
use Comely\Buffer\Exception\ByteReaderUnderflowException;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key;
use FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException;
use FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException;
use FurqanSiddiqui\ECDSA\KeyPair;

/**
 * Class ExtendedKeyPair
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class ExtendedKeyPair extends AbstractKeyPair
{
    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key $ser
     * @return static
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public static function Unserialize(BIP32 $bip32, SerializedBIP32Key $ser): static
    {
        try {
            $parse = $ser->read();
            $version = Bits32::fromInteger($parse->readUInt32BE());
            if (!$version->compare($bip32->config->exportPrivateKeyPrefix, $bip32->config->exportPublicKeyPrefix)) {
                throw new UnserializeBIP32KeyException('Network version byte does not match');
            }

            $depth = $parse->readUInt8();
            $parentPubFp = new Bits32($parse->next(4));
            $childNum = Bits32::fromInteger($parse->readUInt32BE());
            $chainCode = new Bytes32($parse->next(32));
            $keyPrefix = $parse->next(1);
            $keyBytes = new Bytes32($parse->next(32));

            if ($keyPrefix === "\x00") {
                $bip32Key = new PrivateKey($bip32, new KeyPair($bip32->ecc, $keyBytes));
            } elseif ($keyPrefix === "\x02" || $keyPrefix === "\x03") {
                $bip32Key = new PublicKey($bip32, new \FurqanSiddiqui\ECDSA\ECC\PublicKey(
                    $keyBytes->toBase16(),
                    "",
                    bin2hex($keyPrefix)
                ));
            } else {
                throw new UnserializeBIP32KeyException('Invalid prefix for public/private keys');
            }

            if ($childNum->isZeroBytes() && $parentPubFp->isZeroBytes() && $depth === 0) {
                return new MasterKeyPair($bip32, $bip32Key, $depth, $childNum, $parentPubFp, $chainCode);
            }

            return new ExtendedKeyPair($bip32, $bip32Key, $depth, $childNum, $parentPubFp, $chainCode);
        } catch (ByteReaderUnderflowException $e) {
            throw new UnserializeBIP32KeyException(previous: $e);
        }
    }

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\BIP32\KeyPair\PrivateKey|\FurqanSiddiqui\BIP32\KeyPair\PublicKey $key
     * @param int $depth
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $childNum
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $parentPubFp
     * @param \Comely\Buffer\Bytes32 $chainCode
     */
    public function __construct(
        BIP32                   $bip32,
        PrivateKey|PublicKey    $key,
        public readonly int     $depth,
        public readonly Bits32  $childNum,
        public readonly Bits32  $parentPubFp,
        public readonly Bytes32 $chainCode,
    )
    {
        parent::__construct($bip32, $key);
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [sprintf("BIP32 Extended Key (%d)%d", $this->depth, $this->childNum->toInt())];
    }

    /**
     * @param int $index
     * @param bool $isHardened
     * @return \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     * @throws \FurqanSiddiqui\BIP32\Exception\ExtendedKeyException
     */
    public function derive(int $index, bool $isHardened = false): ExtendedKeyPair
    {
        if (!$this->prv) {
            throw new ChildKeyDeriveException('Private key is required for derivation');
        }

        $index = $isHardened ? $index + $this->bip32->config->hardenedIndexBeginsFrom : $index;
        $indexBytes = Bits32::fromInteger($index);
        $data = $isHardened ?
            "00" . $this->prv->eccPrivateKey->private->toBase16() . $indexBytes->toBase16() :
            $this->publicKey()->compressed()->toBase16() . $indexBytes->toBase16();

        $hmac = hash_hmac("sha512", hex2bin($data), $this->chainCode->raw(), true);
        $childPrivateKey = $this->collateChildParentKeys(
            gmp_init(bin2hex(substr($hmac, 0, 32)), 16),
            gmp_init($this->prv->eccPrivateKey->private->toBase16(), 16)
        );

        $childPrivateKey = Bytes32::fromBase16(gmp_strval($childPrivateKey, 16));
        $serialized = new Buffer();
        $serialized->appendUInt32BE($this->bip32->config->exportPrivateKeyPrefix->toInt())
            ->appendUInt8($this->depth + 1)
            ->append($this->publicKey()->fingerPrint)
            ->appendUInt32BE($indexBytes->toInt())
            ->append(new Bytes32(substr($hmac, 32)))
            ->append("\0")
            ->append($childPrivateKey);

        return self::Unserialize($this->bip32, new SerializedBIP32Key($serialized->raw()));
    }

    /**
     * @param \GMP $child
     * @param \GMP $parent
     * @return \GMP
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     */
    private function collateChildParentKeys(\GMP $child, \GMP $parent): \GMP
    {
        $n = $this->bip32->config->secp256k1_nOrder();
        if (gmp_cmp($child, $n) >= 0) {
            throw new ChildKeyDeriveException("Child key exceeds curve order (n)");
        }

        return gmp_mod(gmp_add($child, $parent), $n);
    }

    /**
     * @return \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key
     */
    public function serializePublicKey(): SerializedBIP32Key
    {
        return $this->serializeKey(
            $this->bip32->config->exportPublicKeyPrefix,
            $this->publicKey()->compressed()
        );
    }

    /**
     * @return \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     */
    public function serializePrivateKey(): SerializedBIP32Key
    {
        if (!$this->prv) {
            throw new ChildKeyDeriveException('Private key is not set for serialization');
        }

        return $this->serializeKey(
            $this->bip32->config->exportPrivateKeyPrefix,
            new Buffer("\0" . $this->prv->eccPrivateKey->private)
        );
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $versionBytes
     * @param \Comely\Buffer\AbstractByteArray $key
     * @return \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key
     */
    private function serializeKey(Bits32 $versionBytes, AbstractByteArray $key): SerializedBIP32Key
    {
        return new SerializedBIP32Key((new Buffer())
            ->appendUInt64BE($versionBytes->toInt())
            ->appendUInt8($this->depth)
            ->append($this->parentPubFp)
            ->appendUInt32BE($this->childNum->toInt())
            ->append($this->chainCode)
            ->append($key)
            ->raw());
    }
}
