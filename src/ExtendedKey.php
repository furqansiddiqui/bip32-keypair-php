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

namespace FurqanSiddiqui\BIP32;

use Comely\DataTypes\BcMath\BcMath;
use Comely\DataTypes\BcNumber;
use Comely\DataTypes\Buffer\Base16;
use Comely\DataTypes\Buffer\Binary;
use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\BIP32\Exception\ChildKeyDeriveException;
use FurqanSiddiqui\BIP32\Exception\ExtendedKeyException;
use FurqanSiddiqui\BIP32\Extend\ExtendedKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;
use FurqanSiddiqui\BIP32\KeyPair\PrivateKey;

/**
 * Class ExtendedKey
 * @package FurqanSiddiqui\BIP32
 */
class ExtendedKey implements ExtendedKeyInterface
{
    public const HARDENED_INDEX_BEGIN = 0x80000000;
    public const BITWISE_SEED_LENGTH = 512;

    /** @var null|ExtendedKeyInterface */
    protected $parent;
    /** @var int */
    protected $depth;
    /** @var Base16 */
    protected $privateKey;
    /** @var Base16 */
    protected $chainCode;
    /** @var int */
    protected $curve;
    /** @var bool */
    protected $validateChildKeyCurveN;

    /** @var null|Base16 */
    protected $childNumber;
    /** @var null|PrivateKeyInterface */
    protected $privateKeyInstance;

    /**
     * ExtendedKey constructor.
     * @param Binary $seed
     * @param ExtendedKeyInterface|null $parent
     * @param Base16|null $childNumber
     * @throws ExtendedKeyException
     */
    public function __construct(Binary $seed, ?ExtendedKeyInterface $parent = null, ?Base16 $childNumber = null)
    {
        if ($seed->size()->bits() !== static::BITWISE_SEED_LENGTH) {
            throw new ExtendedKeyException(
                sprintf('Extended key constructor must be passed with %d bit seed', static::BITWISE_SEED_LENGTH)
            );
        }

        $this->parent = $parent;
        $this->depth = $this->parent ? $this->parent->depth() + 1 : 0;
        if ($this->depth > 9) {
            throw new ExtendedKeyException('Cannot extend key to more than 9 depth');
        }

        $this->privateKey = $seed->copy(0, 32)->base16()->readOnly(true);
        $this->chainCode = $seed->copy(32)->base16()->readOnly(true);
        $this->validateChildKeyCurveN = true;
        $this->childNumber = $childNumber ? $childNumber->readOnly(true) : null;
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
    public function raw(): Binary
    {
        $raw = new Binary();
        $raw->append($this->privateKey->binary());
        $raw->append($this->chainCode->binary());
        return $raw;
    }

    /**
     * @return Base16
     */
    public function chainCode(): Base16
    {
        return $this->chainCode;
    }

    /**
     * @return Base16|null
     */
    public function childNumber(): ?Base16
    {
        return $this->childNumber;
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
    public function getEllipticCurveId(): ?int
    {
        if ($this->curve) {
            return $this->curve;
        }

        if ($this->parent) {
            return $this->parent->getEllipticCurveId();
        }

        return null;
    }

    /**
     * @return ExtendedKeyInterface|null
     */
    public function parent(): ?ExtendedKeyInterface
    {
        return $this->parent;
    }

    /**
     * @param $path
     * @return ExtendedKey
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
     * @return ExtendedKey
     * @throws ChildKeyDeriveException
     * @throws ExtendedKeyException
     */
    public function derive(int $index, bool $isHardened = false): ExtendedKeyInterface
    {
        $index = $isHardened ? $index + self::HARDENED_INDEX_BEGIN : $index;
        $indexHex = str_pad(dechex($index), 8, "0", STR_PAD_LEFT);
        $hmacRawData = $isHardened ?
            "00" . $this->privateKey->hexits(false) . $indexHex :
            $this->publicKey()->compressed()->hexits(false) . $indexHex;
        $hmacRawData = new Base16($hmacRawData);

        $hmac = new Binary(hash_hmac("sha512", $hmacRawData->binary()->raw(), $this->chainCode->binary()->raw(), true));
        $childPrivateKey = $hmac->copy(0, 32); // Get first 32 bytes
        $childChainCode = $hmac->copy(-32); // Get last 32 bytes as Chain code

        $childExtendedKey = $this->collateChildParentKeys($childPrivateKey, $this->privateKey()->base16()->binary());
        $childExtendedKey->append($childChainCode->raw());
        return new self($childExtendedKey, $this, (new Base16($indexHex))->readOnly(true));
    }

    /**
     * @param int $versionBytes
     * @return Binary
     */
    public function serializePublicKey(int $versionBytes): Binary
    {
        return $this->serializeKey($versionBytes, $this->publicKey()->compressed());
    }

    /**
     * @param int $versionBytes
     * @return Binary
     */
    public function serializePrivateKey(int $versionBytes): Binary
    {
        return $this->serializeKey($versionBytes, new Base16("00" . $this->privateKey->hexits(false)));
    }

    /**
     * @param int $versionBytes
     * @param Base16 $key
     * @return Binary
     */
    private function serializeKey(int $versionBytes, Base16 $key): Binary
    {
        $serialized = new Base16();

        // Version Byte
        $serialized->append(BcMath::Encode($versionBytes));

        // Depth
        $serialized->append(BcMath::Encode($this->depth));

        // Fingerprint
        if ($this->parent()) { // Has parent?
            $serialized->append($this->parent()->publicKey()->fingerPrint()->hexits());
        } else { // Master key?
            $serialized->append("00000000");
        }

        // Child number
        if ($this->childNumber) {
            $serialized->append($this->childNumber->hexits(false));
        } else { // Master key?
            $serialized->append("00000000");
        }

        // Chain Code
        $serialized->append($this->chainCode->hexits(false));

        // Key
        $serialized->append($key->hexits(false));

        return $serialized->binary();
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

        $ecCurve = Curves::getInstanceOf($this->getEllipticCurveId());
        $n = new BcNumber(gmp_strval($ecCurve->order(), 10));
        if (!$n->isPositive()) {
            throw new ChildKeyDeriveException('Curve order (n) is not positive');
        }

        if ($child->greaterThanOrEquals($n)) {
            throw new ChildKeyDeriveException(
                'Child key exceeds curve order (n)',
                ChildKeyDeriveException::HINT_TRY_NEXT_INDEX
            );
        }

        $collate = $child->add($parent);
        $collate = $collate->mod($n);
        $collate = new Base16(str_pad($collate->encode()->hexits(), 64, "0", STR_PAD_LEFT));
        return $collate->binary();
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
            $bcNumber = BcNumber::fromBase16($in->base16());
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