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

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Buffer;
use Comely\Buffer\Bytes32;
use Comely\Buffer\Exception\ByteReaderUnderflowException;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\BIP32_Provider;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key;
use FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException;
use FurqanSiddiqui\BIP32\Exception\ExtendedKeyException;
use FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException;

/**
 * Class ExtendedKeyPair
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class ExtendedKeyPair extends AbstractKeyPair implements ExtendedKeyInterface
{
    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\BIP32_Provider $bip32
     * @param \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key $ser
     * @return static
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public static function Unserialize(BIP32_Provider $bip32, SerializedBIP32Key $ser): static
    {
        try {
            $parse = $ser->read();
            $version = Bits32::fromInteger($parse->readUInt32BE());
            $depth = $parse->readUInt8();
            $parentPubFp = new Bits32($parse->next(4));
            $childNum = Bits32::fromInteger($parse->readUInt32BE());
            $chainCode = new Bytes32($parse->next(32));
            $keyPrefix = $parse->next(1);
            $keyBytes = new Bytes32($parse->next(32));

            if ($depth === 0 && !$parentPubFp->isZeroBytes()) {
                throw new UnserializeBIP32KeyException('Zero depth with non-zero parent public key');
            }

            if ($depth === 0 && !$childNum->isZeroBytes()) {
                throw new UnserializeBIP32KeyException('Zero depth with non-zero child index');
            }

            try {
                if ($keyPrefix === "\x00" && $version->compare($bip32->bip32()->config->exportPrivateKeyPrefix)) {
                    $bip32Key = $bip32->privateKeyFromEntropy($keyBytes);
                } elseif ($keyPrefix === "\x02" || $keyPrefix === "\x03") {
                    if ($version->compare($bip32->bip32()->config->exportPublicKeyPrefix)) {
                        $bip32Key = $bip32->publicKeyFromIncomplete((new Buffer($keyPrefix))->append($keyBytes));
                    }
                }
            } catch (\Exception $e) {
                throw new UnserializeBIP32KeyException($e->getMessage());
            }

            if (!isset($bip32Key)) {
                throw new UnserializeBIP32KeyException('Invalid prefix for public/private keys');
            }

            return new static($bip32->bip32(), $bip32Key, $depth, $childNum, $parentPubFp, $chainCode);
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
        BIP32                                  $bip32,
        PrivateKeyInterface|PublicKeyInterface $key,
        public readonly int                    $depth,
        public readonly Bits32                 $childNum,
        public readonly Bits32                 $parentPubFp,
        public readonly Bytes32                $chainCode,
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
     * @param $path
     * @return $this
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     * @throws \FurqanSiddiqui\BIP32\Exception\ExtendedKeyException
     */
    public function derivePath($path): ExtendedKeyInterface
    {
        if ($this->depth !== 0) {
            throw new ExtendedKeyException('derivePath method is only available to MasterKeyPair instances');
        }

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

    /**
     * @param int $index
     * @param bool $isHardened
     * @return $this
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public function derive(int $index, bool $isHardened = false): ExtendedKeyInterface
    {
        return ExtendedKeyPair::Unserialize($this->bip32, $this->_derive($index, $isHardened));
    }

    /**
     * @param int $index
     * @param bool $isHardened
     * @return \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key
     * @throws \FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException
     */
    protected function _derive(int $index, bool $isHardened = false): SerializedBIP32Key
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

        return new SerializedBIP32Key($serialized->raw());
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
            ->appendUInt32BE($versionBytes->toInt())
            ->appendUInt8($this->depth)
            ->append($this->parentPubFp)
            ->appendUInt32BE($this->childNum->toInt())
            ->append($this->chainCode)
            ->append($key)
            ->raw());
    }
}
