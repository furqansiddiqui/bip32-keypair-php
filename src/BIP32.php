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

namespace FurqanSiddiqui\BIP32;

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Bytes32;
use FurqanSiddiqui\BIP32\Buffers\Base58;
use FurqanSiddiqui\BIP32\Buffers\BIP32_Provider;
use FurqanSiddiqui\BIP32\Buffers\Bits32;
use FurqanSiddiqui\BIP32\Buffers\Bits512;
use FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key;
use FurqanSiddiqui\BIP32\Exception\KeyPairException;
use FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair;
use FurqanSiddiqui\BIP32\KeyPair\MasterKeyPair;
use FurqanSiddiqui\BIP32\KeyPair\PrivateKey;
use FurqanSiddiqui\BIP32\KeyPair\PublicKey;
use FurqanSiddiqui\BIP32\Networks\AbstractNetworkConfig;
use FurqanSiddiqui\ECDSA\ECC\EllipticCurveInterface;
use FurqanSiddiqui\ECDSA\KeyPair;

/**
 * Class BIP32
 * @package FurqanSiddiqui\BIP32
 */
class BIP32 implements BIP32_Provider
{
    public readonly Base58 $base58;

    /**
     * @param \FurqanSiddiqui\ECDSA\ECC\EllipticCurveInterface $ecc
     * @param \FurqanSiddiqui\BIP32\Networks\AbstractNetworkConfig $config
     * @param \FurqanSiddiqui\BIP32\Buffers\Base58|null $base58
     */
    public function __construct(
        public readonly EllipticCurveInterface $ecc,
        public readonly AbstractNetworkConfig  $config,
        ?Base58                                $base58 = null
    )
    {
        $this->base58 = $base58 ?? new Base58($this->config->base58Charset, $this->config->base58CaseSensitive);
    }

    /**
     * @return $this
     */
    public function bip32(): static
    {
        return $this;
    }

    /**
     * @return \Comely\Buffer\Bytes32
     * @throws \FurqanSiddiqui\BIP32\Exception\KeyPairException
     */
    public function generateSecureEntropy(): Bytes32
    {
        try {
            return new Bytes32(random_bytes(32));
        } catch (\Exception) {
            throw new KeyPairException('Failed to generate PRNG random 32 bytes');
        }
    }

    /**
     * @param \Comely\Buffer\Bytes32 $entropy
     * @return \FurqanSiddiqui\BIP32\KeyPair\PrivateKey
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public function privateKeyFromEntropy(Bytes32 $entropy): PrivateKey
    {
        return new PrivateKey($this, new KeyPair($this->ecc, $entropy));
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $publicKey
     * @return \FurqanSiddiqui\BIP32\KeyPair\PublicKey
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public function publicKeyFromDER(AbstractByteArray $publicKey): PublicKey
    {
        return new PublicKey($this, \FurqanSiddiqui\ECDSA\ECC\PublicKey::fromDER($publicKey));
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $publicKey
     * @return \FurqanSiddiqui\BIP32\KeyPair\PublicKey
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public function publicKeyFromUncompressed(AbstractByteArray $publicKey): PublicKey
    {
        return $this->publicKeyFromDER($publicKey);
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $compressedPubKey
     * @return \FurqanSiddiqui\BIP32\KeyPair\PublicKey
     * @throws \FurqanSiddiqui\BIP32\Exception\KeyPairException
     */
    public function publicKeyFromIncomplete(AbstractByteArray $compressedPubKey): PublicKey
    {
        if ($compressedPubKey->len() !== 33) {
            throw new KeyPairException('Compressed public key must be 33 bytes long');
        }

        $compressedPubKey = $compressedPubKey->raw();
        if (!in_array($compressedPubKey[0], ["\x02", "\x03"])) {
            throw new KeyPairException('Invalid compressed public key prefix');
        }

        return new PublicKey(
            $this,
            new \FurqanSiddiqui\ECDSA\ECC\PublicKey(bin2hex(substr($compressedPubKey, 1)), "", bin2hex($compressedPubKey[0]))
        );
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key|\Comely\Buffer\AbstractByteArray $ser
     * @return \FurqanSiddiqui\BIP32\KeyPair\MasterKeyPair|\FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     */
    public function unserialize(SerializedBIP32Key|AbstractByteArray $ser): MasterKeyPair|ExtendedKeyPair
    {
        if (!$ser instanceof SerializedBIP32Key) {
            $ser = new SerializedBIP32Key($ser->raw());
        }

        return MasterKeyPair::Unserialize($this, $ser);
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $entropy
     * @param string|null $overrideConfigSeed
     * @return \FurqanSiddiqui\BIP32\Buffers\Bits512
     */
    public function hmacEntropy(AbstractByteArray $entropy, ?string $overrideConfigSeed = null): Bits512
    {
        return new Bits512(hash_hmac("sha512", $entropy->raw(), $overrideConfigSeed ?? $this->config->hmacSeed, true));
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $prv
     * @return \FurqanSiddiqui\BIP32\KeyPair\MasterKeyPair
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public function masterKeyFromEntropy(AbstractByteArray $prv): MasterKeyPair
    {
        return $this->masterKeyFromSeed($this->hmacEntropy($prv));
    }

    /**
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits512 $seed
     * @return \FurqanSiddiqui\BIP32\KeyPair\MasterKeyPair
     * @throws \FurqanSiddiqui\BIP32\Exception\UnserializeBIP32KeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public function masterKeyFromSeed(Bits512 $seed): MasterKeyPair
    {
        $seed = $seed->raw();
        return new MasterKeyPair(
            $this,
            new PrivateKey($this, new KeyPair($this->ecc, new Bytes32(substr($seed, 0, 32)))),
            0,
            Bits32::fromInteger(0),
            new Bits32(str_repeat("\0", 4)),
            new Bytes32(substr($seed, 32))
        );
    }

    /**
     * @param \FurqanSiddiqui\BIP32\KeyPair\PrivateKey|\FurqanSiddiqui\BIP32\KeyPair\PublicKey $key
     * @param \Comely\Buffer\Bytes32 $chainCode
     * @param int $depth
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $childNum
     * @param \FurqanSiddiqui\BIP32\Buffers\Bits32 $parentPubFp
     * @return \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair
     */
    public function extendedKey(
        PrivateKey|PublicKey $key,
        Bytes32              $chainCode,
        int                  $depth,
        Bits32               $childNum,
        Bits32               $parentPubFp
    ): ExtendedKeyPair
    {
        return new ExtendedKeyPair($this, $key, $depth, $childNum, $parentPubFp, $chainCode);
    }
}
