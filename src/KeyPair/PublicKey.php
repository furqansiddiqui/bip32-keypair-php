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
use FurqanSiddiqui\BIP32\Exception\PublicKeyException;
use FurqanSiddiqui\BIP32\Extend\PrivateKeyInterface;
use FurqanSiddiqui\BIP32\Extend\PublicKeyInterface;
use FurqanSiddiqui\ECDSA\ECC\EllipticCurveInterface;

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
    /** @var \FurqanSiddiqui\ECDSA\ECC\PublicKey */
    protected $eccPublicKeyObj;
    /** @var null|Base16 */
    private $fingerPrint;

    /**
     * PublicKey constructor.
     * @param PrivateKeyInterface|null $privateKey
     * @param EllipticCurveInterface|null $curve
     * @param Base16|null $publicKey
     * @param bool|null $pubKeyArgIsCompressed
     * @throws PublicKeyException
     */
    public function __construct(?PrivateKeyInterface $privateKey, ?EllipticCurveInterface $curve = null, ?Base16 $publicKey = null, ?bool $pubKeyArgIsCompressed = null)
    {
        $eccCurve = null; // ECDSA curve instance

        // Generating from Private key?
        if ($privateKey) {
            $this->privateKey = $privateKey;
            $this->curve = null;
            $privateKeyCurveId = $this->privateKey->getEllipticCurveId();
            if (!$privateKeyCurveId) {
                throw new PublicKeyException('Cannot generate Public key; No ECDSA curve defined for private key');
            }

            $eccCurve = Curves::getInstanceOf($privateKeyCurveId);
        } else {
            $eccCurve = $curve;
            $this->curve = Curves::getCurveId($eccCurve);
        }

        if (!$eccCurve instanceof EllipticCurveInterface) {
            throw new PublicKeyException('No ECDSA curve has been set to generate Public Key obj');
        }

        // Generate Public Key
        if ($this->privateKey) {
            // Derive public key from private key
            $eccPublicKey = $eccCurve->getPublicKey($this->privateKey->base16());
        } elseif ($publicKey) {
            if ($pubKeyArgIsCompressed === true) {
                // Argument is a compressed public key
                $eccPublicKey = $eccCurve->getPublicKeyFromCompressed($publicKey);
            } elseif ($pubKeyArgIsCompressed === false) {
                // Argument is a full (uncompressed) public key
                $eccPublicKey = $eccCurve->usePublicKey($publicKey);
            } else {
                // Attempt 1, assume its full (uncompressed public key)
                try {
                    $eccPublicKey = $eccCurve->usePublicKey($publicKey);
                } catch (\Exception $e) {
                }

                // Attempt 2, has to be a compressed public key
                if (!isset($eccPublicKey)) {
                    try {
                        $eccPublicKey = $eccCurve->getPublicKeyFromCompressed($publicKey);
                    } catch (\Exception $e) {
                    }
                }
            }
        }

        if (!isset($eccPublicKey)) {
            throw new PublicKeyException('Could not generate Public key from given argument(s)');
        }

        $this->eccPublicKeyObj = $eccPublicKey;
    }

    /**
     * @return int|null
     */
    public function getEllipticCurveId(): ?int
    {
        if ($this->privateKey) {
            return $this->privateKey->getEllipticCurveId();
        }

        if ($this->curve) {
            return $this->curve;
        }

        return null;
    }

    /**
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function getEllipticCurvePubKeyObj(): \FurqanSiddiqui\ECDSA\ECC\PublicKey
    {
        return $this->eccPublicKeyObj;
    }

    /**
     * @return Base16
     */
    public function full(): Base16
    {
        return $this->eccPublicKeyObj->getUnCompressed();
    }

    /**
     * @return Base16
     */
    public function compressed(): Base16
    {
        return $this->eccPublicKeyObj->getCompressed();
    }

    /**
     * @return Base16
     */
    public function fingerPrint(): Base16
    {
        if ($this->fingerPrint) {
            return $this->fingerPrint;

        }

        $fingerPrint = $this->compressed()->binary()
            ->hash()->sha256()
            ->hash()->ripeMd160(4);

        $this->fingerPrint = $fingerPrint->base16();
        return $this->fingerPrint;
    }

    /**
     * @return bool
     */
    public function hasPrivateKey(): bool
    {
        return $this->privateKey ? true : false;
    }

    /**
     * @return PrivateKeyInterface|null
     */
    public function privateKey(): ?PrivateKeyInterface
    {
        return $this->privateKey;
    }
}