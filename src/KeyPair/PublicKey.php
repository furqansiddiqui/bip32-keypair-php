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
use FurqanSiddiqui\BIP32\ECDSA\Curves;
use FurqanSiddiqui\BIP32\ECDSA\FailSafeCurveValidate;
use FurqanSiddiqui\BIP32\ECDSA\Vectors;
use FurqanSiddiqui\BIP32\Exception\PublicKeyException;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class PublicKey implements PublicKeyInterface
{
    /** @var PrivateKey */
    protected $privateKey;
    /** @var int */
    protected $curve;
    /** @var Vector */
    protected $vector;
    /** @var Binary */
    protected $publicKey;
    /** @var Binary */
    protected $compressedPublicKey;

    /**
     * PublicKey constructor.
     * @param PrivateKeyInterface $keyPair
     * @throws PublicKeyException
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public function __construct(PrivateKeyInterface $keyPair)
    {
        $this->privateKey = $keyPair;
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
                $this->publicKey    =   $base16x->clone()->append($base16y)->binary()->readOnly(true);
                $this->compressedPublicKey  =   $base16x->clone()->prepend($sign)->binary()->readOnly(true);
                break;
            default:
                throw new PublicKeyException(
                    sprintf('Not sure how to convert "%s" vector into public key', Curves::INDEX[$this->curve])
                );

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
     * @return FailSafeCurveValidate
     */
    public function failSafeCurveValidate(): FailSafeCurveValidate
    {
        return new FailSafeCurveValidate($this);
    }

    /**
     * @return int
     */
    public function curve(): int
    {
        return $this->curve;
    }

    /**
     * @return Vector
     */
    public function vector(): Vector
    {
        return $this->vector;
    }

    /**
     * @return PrivateKeyInterface
     */
    public function privateKey(): PrivateKeyInterface
    {
        return $this->privateKey;
    }
}