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

namespace FurqanSiddiqui\BIP32\KeyPair;

use Comely\DataTypes\Buffer\Base16;
use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\BIP32\Extend\ExtendedKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;

/**
 * Class PrivateKey
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class PrivateKey implements PrivateKeyInterface
{
    /** @var null|ExtendedKeyInterface */
    protected $extendedKey;
    /** @var Base16 */
    protected $privateKey;
    /** @var null|int */
    protected $curve;
    /** @var null|PublicKeyInterface */
    protected $publicKey;

    /**
     * PrivateKey constructor.
     * @param Base16 $entropy
     * @param ExtendedKeyInterface|null $extendedKey
     */
    public function __construct(Base16 $entropy, ?ExtendedKeyInterface $extendedKey = null)
    {
        $this->extendedKey = $extendedKey;
        $this->privateKey = $entropy;
        $this->privateKey->readOnly(true); // Set buffer to read-only state
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [sprintf('%d-bit Private Key', $this->privateKey->binary()->size()->bits())];
    }

    /**
     * @param string $prop
     * @param $value
     * @return static
     */
    public function set(string $prop, $value)
    {
        if ($prop === "curve") {
            if ($this->extendedKey) {
                throw new \DomainException('Cannot change ECDSA curve for Extended private keys');
            }

            if (!is_int($value) || !in_array($value, array_keys(Curves::INDEX))) {
                throw new \InvalidArgumentException('Cannot use an invalid ECDSA curve');
            }

            $this->curve = $value;
            return $this;
        }

        throw new \DomainException('Cannot set value of inaccessible property');
    }

    /**
     * @return int|null
     */
    public function getEllipticCurveId(): ?int
    {
        if ($this->curve) {
            return $this->curve;
        }

        if ($this->extendedKey) {
            return $this->extendedKey->getEllipticCurveId();
        }

        return null;
    }

    /**
     * @return Curves
     */
    public function curves(): Curves
    {
        return new Curves(function (int $curve) {
            $this->set("curve", $curve);
        });
    }

    /**
     * @return Base16
     */
    public function base16(): Base16
    {
        return $this->privateKey;
    }

    /**
     * @return PublicKeyInterface
     * @throws \FurqanSiddiqui\BIP32\Exception\PublicKeyException
     */
    public function publicKey(): PublicKeyInterface
    {
        if (!$this->publicKey) {
            $this->publicKey = new PublicKey($this);
        }

        return $this->publicKey;
    }

    /**
     * @return ExtendedKeyInterface|null
     */
    public function ekd(): ?ExtendedKeyInterface
    {
        return $this->extendedKey;
    }
}