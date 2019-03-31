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

namespace FurqanSiddiqui\BIP32;

use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException;
use FurqanSiddiqui\BIP32\Exception\ExtendedKeyException;
use FurqanSiddiqui\BIP32\Extend\ExtendedKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;
use FurqanSiddiqui\BIP32\KeyPair\PrivateKey;
use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\DataTypes\Binary;

/**
 * Class ExtendedKey
 * @package FurqanSiddiqui\BIP32
 */
class ExtendedKey implements ExtendedKeyInterface
{
    public const HARDENED_INDEX_BEGIN = 0x80000000;
    public const BITWISE_SEED_LENGTH = 512;

    /** @var null|ExtendedKey */
    protected $parent;
    /** @var int */
    protected $depth;
    /** @var Binary */
    protected $privateKey;
    /** @var Binary */
    protected $chainCode;
    /** @var int */
    protected $curve;
    /** @var bool */
    protected $validateChildKeyCurveN;

    /** @var null|PrivateKeyInterface */
    private $privateKeyInstance;

    /**
     * ExtendedKey constructor.
     * @param Binary $seed
     * @param ExtendedKeyInterface|null $parent
     * @throws ExtendedKeyException
     */
    public function __construct(Binary $seed, ?ExtendedKeyInterface $parent = null)
    {
        if ($seed->length()->bits() !== static::BITWISE_SEED_LENGTH) {
            throw new ExtendedKeyException(
                sprintf('Extended key constructor must be passed with %d bit seed', static::BITWISE_SEED_LENGTH)
            );
        }

        $this->parent = $parent;
        $this->depth = $this->parent ? $this->parent->depth() + 1 : 0;
        if ($this->depth > 9) {
            throw new ExtendedKeyException('Cannot extend key to more than 9 depth');
        }

        $this->privateKey = $seed->copy(0, 32)->readOnly(true);
        $this->chainCode = $seed->copy(32)->readOnly(true);
        $this->validateChildKeyCurveN = true;
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return ["BIP32 Extended Key"];
    }

    /**
     * @return int
     */
    public function depth(): int
    {
        return $this->depth;
    }

    /**
     * @param string $prop
     * @param $value
     * @return ExtendedKeyInterface
     */
    public function set(string $prop, $value): ExtendedKeyInterface
    {
        if ($prop === "curve") {
            if (!is_int($value) || !in_array($value, array_keys(Curves::INDEX))) {
                throw new \InvalidArgumentException('Cannot use an invalid ECDSA curve');
            }

            $this->curve = $value;
            return $this;
        }

        throw new \DomainException('Cannot set value of inaccessible property');
    }

    /**
     * @return Binary
     */
    public function chainCode(): Binary
    {
        return $this->chainCode;
    }

    /**
     * @return PrivateKeyInterface
     */
    public function privateKey(): PrivateKeyInterface
    {
        if (!$this->privateKeyInstance) {
            $this->privateKeyInstance = new PrivateKey($this->privateKey, $this);
        }

        return $this->privateKeyInstance;
    }

    /**
     * @return PublicKeyInterface
     */
    public function publicKey(): PublicKeyInterface
    {
        return $this->privateKey()->publicKey();
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
     * @return int|null
     */
    public function getEllipticCurve(): ?int
    {
        if ($this->curve) {
            return $this->curve;
        }

        if ($this->parent) {
            return $this->parent->getEllipticCurve();
        }

        return null;
    }

    /**
     * @param $path
     * @return ExtendedKeyInterface
     * @throws ChildKeyDeriveException
     * @throws ExtendedKeyException
     */
    public function derivePath($path): ExtendedKeyInterface
    {
        $parts = explode("/", trim(strtolower($path), "/"));
        if ($parts[0] !== "m") {
            throw new ExtendedKeyException('Derivation path must start with "m"');
        }

        array_shift($parts); // Remove initial "m"
        $derivedKey = $this;
        foreach ($parts as $part) {
            if (!is_string($part) || !preg_match('/^[0-9]+\'?$/', $part)) {
                throw new ExtendedKeyException(sprintf('Invalid index in derivation path'));
            }

            $isHardened = substr($part, -1) === "'" ? true : false;
            $index = $isHardened ? substr($part, 0, -1) : $part;
            $derivedKey = $derivedKey->derive(intval($index), $isHardened);
        }

        return $derivedKey;
    }

    /**
     * @param int $index
     * @param bool $isHardened
     * @return ExtendedKeyInterface
     * @throws ChildKeyDeriveException
     * @throws ExtendedKeyException
     */
    public function derive(int $index, bool $isHardened = false): ExtendedKeyInterface
    {
        $index = $isHardened ? $index + self::HARDENED_INDEX_BEGIN : $index;
        $indexHex = str_pad(dechex($index), 8, "0", STR_PAD_LEFT);
        $hmacRawData = $isHardened ?
            "00" . $this->privateKey()->raw()->get()->base16() . $indexHex :
            $this->publicKey()->compressed()->get()->base16() . $indexHex;

        $hmac = new Binary(hash_hmac("sha512", hex2bin($hmacRawData), $this->chainCode->raw(), true));
        $childPrivateKey = $hmac->copy(0, 32); // Get first 32 bytes
        $childChainCode = $hmac->copy(-32); // Get last 32 bytes as Chain code


        $childExtendedKey = $this->collateChildParentKeys($childPrivateKey, $this->privateKey()->raw());
        $childExtendedKey->append($childChainCode->raw());
        return new self($childExtendedKey, $this);
    }

    /**
     * @param Binary $child
     * @param Binary $parent
     * @return Binary
     * @throws ChildKeyDeriveException
     */
    private function collateChildParentKeys(Binary $child, Binary $parent): Binary
    {
        $child = $this->key2BcNumber($child, "Child private key");
        $parent = $this->key2BcNumber($parent, "Parent (this) private key");

        $n = $this->publicKey()->vector()->n();
        if (!$n->isPositive()) {
            throw new ChildKeyDeriveException('Curve order (n) is not positive');
        }

        if ($child->greaterThanOrEquals($n)) {
            throw new ChildKeyDeriveException(
                'Child key exceeds curve order (n)',
                ChildKeyDeriveException::HINT_TRY_NEXT_INDEX
            );
        }

        $collate = $child->new()->add($parent);
        $collate->mod($this->publicKey()->vector()->n());
        $collate = new Base16(str_pad($collate->encode(), 64, "0", STR_PAD_LEFT));
        return $collate;
    }

    /**
     * @param Binary $in
     * @param string $which
     * @return BcNumber
     * @throws ChildKeyDeriveException
     */
    private function key2BcNumber(Binary $in, string $which): BcNumber
    {
        try {
            $bcNumber = BcNumber::Decode($in->get()->base16(false));
        } catch (\Error $e) {
            trigger_error(sprintf('[%s][%d] %s', get_class($e), $e->getCode(), $e->getMessage()));
        }

        if (!isset($bcNumber) || !$bcNumber instanceof BcNumber) {
            throw new ChildKeyDeriveException(
                sprintf('Could not convert %s to number', $which),
                ChildKeyDeriveException::HINT_TRY_NEXT_INDEX
            );
        }

        if (!$bcNumber->isPositive()) {
            throw new ChildKeyDeriveException(
                sprintf('Converted BcNumber from %s is not positive', $which),
                ChildKeyDeriveException::HINT_TRY_NEXT_INDEX
            );
        }

        return $bcNumber;
    }
}