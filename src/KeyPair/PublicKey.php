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

namespace FurqanSiddiqui\BIP32\KeyPair;

use FurqanSiddiqui\BcMath\BcBaseConvert;
use FurqanSiddiqui\BcMath\BcMath;
use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\BIP32\ECDSA\FailSafeCurveValidate;
use FurqanSiddiqui\BIP32\ECDSA\Vectors;
use FurqanSiddiqui\BIP32\Exception\FailSafeValidateException;
use FurqanSiddiqui\BIP32\Exception\PublicKeyException;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;
use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\DataTypes\DataTypes;
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class PublicKey implements PublicKeyInterface
{
    /** @var null|PrivateKey */
    protected $privateKey;
    /** @var null|int */
    protected $curve;
    /** @var null|Vector */
    protected $vector;
    /** @var Binary */
    protected $publicKey;
    /** @var Binary */
    protected $compressedPublicKey;

    /**
     * @param PrivateKeyInterface $privateKey
     * @return PublicKey
     * @throws PublicKeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function fromPrivateKey(PrivateKeyInterface $privateKey)
    {
        return new static($privateKey);
    }

    /**
     * @param $x
     * @param $y
     * @return static
     * @throws PublicKeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function fromXAndY($x, $y)
    {
        // Get value of coords as Base16
        $x = self::getCoordsAsBase16($x, "x");
        $y = self::getCoordsAsBase16($y, "y");
        $bitwise = BcBaseConvert::BaseConvert($y->hexits(), 16, 2);
        $sign = substr($bitwise, -1) === "0" ? "02" : "03";

        $fullPublicKey = $x->clone()->append($y)->binary()->readOnly(true);
        $compressedPublicKey = $x->clone()->prepend($sign)->binary()->readOnly(true);
        return new static(null, $fullPublicKey, $compressedPublicKey);
    }

    /**
     * @param $point
     * @param string $which
     * @return Base16
     * @throws PublicKeyException
     */
    private static function getCoordsAsBase16($point, string $which = "?"): Base16
    {
        $argDataType = gettype($point);
        if (is_string($point)) {
            if (DataTypes::isBase16($point)) {
                $point = new Base16($point);
            } else {
                $pointInt = BcMath::isNumeric($point);
                if ($pointInt) {
                    $point = $pointInt;
                }
            }
        }

        if ($point instanceof BcNumber) {
            if ($point->isInteger() && $point->isPositive()) {
                $point = $point->encode(); // Encode BcNumber as Base16
            }
        }

        if (!$point instanceof Base16) {
            throw new PublicKeyException(
                sprintf('Could not convert public key point "%s" to Base16 from given data type "%s"', $which, $argDataType)
            );
        }

        return $point;
    }

    /**
     * PublicKey constructor.
     * @param PrivateKeyInterface|null $privateKey
     * @param Binary|null $publicKey
     * @param Binary|null $compressed
     * @throws PublicKeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public function __construct(?PrivateKeyInterface $privateKey, ?Binary $publicKey = null, ?Binary $compressed = null)
    {
        if ($privateKey) {
            $this->privateKey = $privateKey;
            $this->curve = $this->privateKey->getEllipticCurveId();
            if (!$this->curve) {
                throw new PublicKeyException('Cannot generate public key; ECDSA curve is not defined');
            }

            $this->vector = Vectors::Curve($this->curve, $this->privateKey->raw());
            switch ($this->curve) {
                case Curves::SECP256K1:
                case Curves::SECP256K1_OPENSSL:
                    $coords = $this->vector->coords();
                    if (!$coords->x()) {
                        throw new PublicKeyException('Secp256k1 curve missing "x" point');
                    } elseif (!$coords->y()) {
                        throw new PublicKeyException('Secp256k1 curve missing "y" point');
                    }

                    $base16x = $coords->x()->encode();
                    $base16y = $coords->y()->encode();
                    $bitwise = BcBaseConvert::BaseConvert($base16y->hexits(), 16, 2);
                    $sign = substr($bitwise, -1) === "0" ? "02" : "03";
                    $this->publicKey = $base16x->clone()->append($base16y)->binary()->readOnly(true);
                    $this->compressedPublicKey = $base16x->clone()->prepend($sign)->binary()->readOnly(true);
                    break;
                default:
                    throw new PublicKeyException(
                        sprintf('Not sure how to convert "%s" vector into public key', Curves::INDEX[$this->curve])
                    );

            }

            return;
        }

        // Construct from given Full and compressed public keys
        if ($publicKey) {
            $this->publicKey = $publicKey;
        }

        if ($compressed) {
            $this->compressedPublicKey = $compressed;
        }

        // Check if full and/or compressed key has been set
        if (!$this->publicKey && !$this->compressedPublicKey) {
            throw new PublicKeyException('Could not instantiate PublicKey object without data');
        }
    }

    /**
     * @return Binary
     */
    public function raw(): Binary
    {
        return $this->publicKey;
    }

    /**
     * @return Binary
     * @throws PublicKeyException
     */
    public function compressed(): Binary
    {
        if (!$this->compressedPublicKey) {
            throw new PublicKeyException(
                sprintf('Could not generate a compressed public key using "%s" curve', Curves::INDEX[$this->curve])
            );
        }

        return $this->compressedPublicKey;
    }

    /**
     * @return bool
     */
    public function hasPrivateKey(): bool
    {
        return $this->privateKey ? true : false;
    }

    /**
     * @return FailSafeCurveValidate
     * @throws FailSafeValidateException
     */
    public function failSafeCurveValidate(): FailSafeCurveValidate
    {
        if (!$this->hasPrivateKey()) {
            throw new FailSafeValidateException('Public key instance does not have a private key');
        }

        return new FailSafeCurveValidate($this);
    }

    /**
     * @return int
     */
    public function curve(): ?int
    {
        return $this->curve;
    }

    /**
     * @return Vector
     */
    public function vector(): ?Vector
    {
        return $this->vector;
    }

    /**
     * @return PrivateKeyInterface|null
     */
    public function privateKey(): ?PrivateKeyInterface
    {
        return $this->privateKey;
    }
}