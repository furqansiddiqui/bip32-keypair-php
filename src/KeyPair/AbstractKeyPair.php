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

use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Exception\KeyPairException;

/**
 * Class KeyPair
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
abstract class AbstractKeyPair
{
    /** @var \FurqanSiddiqui\BIP32\KeyPair\PrivateKeyInterface|null */
    protected readonly null|PrivateKeyInterface $prv;
    /** @var \FurqanSiddiqui\BIP32\KeyPair\PublicKey|null */
    protected null|PublicKeyInterface $pub;

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\BIP32\KeyPair\PrivateKeyInterface|\FurqanSiddiqui\BIP32\KeyPair\PublicKeyInterface $key
     */
    public function __construct(public readonly BIP32 $bip32, PrivateKeyInterface|PublicKeyInterface $key)
    {
        if ($key instanceof PrivateKeyInterface) {
            $this->prv = $key;
            $this->pub = null;
        } else {
            $this->prv = null;
            $this->pub = $key;
        }
    }

    /**
     * @return \FurqanSiddiqui\BIP32\KeyPair\PublicKey
     */
    public function publicKey(): PublicKeyInterface
    {
        if (!$this->pub) {
            $this->pub = new PublicKey($this->bip32, $this->prv->eccPrivateKey->public());
        }

        return $this->pub;
    }

    /**
     * @return bool
     */
    public function hasPrivateKey(): bool
    {
        return isset($this->prv);
    }

    /**
     * @return \FurqanSiddiqui\BIP32\KeyPair\PrivateKey
     * @throws \FurqanSiddiqui\BIP32\Exception\KeyPairException
     */
    public function privateKey(): PrivateKeyInterface
    {
        if (!$this->prv) {
            throw new KeyPairException('Key pair does not have a private key set');
        }

        return $this->prv;
    }
}
