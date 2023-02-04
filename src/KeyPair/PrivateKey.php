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

use Comely\Buffer\Bytes32;
use FurqanSiddiqui\BIP32\BIP32;
use FurqanSiddiqui\BIP32\Buffers\Signature;
use FurqanSiddiqui\ECDSA\KeyPair;

/**
 * Class PrivateKey
 * @package FurqanSiddiqui\BIP32\KeyPair
 */
class PrivateKey implements PrivateKeyInterface
{
    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\ECDSA\KeyPair $eccPrivateKey
     */
    public function __construct(
        public readonly BIP32   $bip32,
        public readonly KeyPair $eccPrivateKey,
    )
    {
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [sprintf('%d-bit Private Key', $this->eccPrivateKey->private->len() * 8)];
    }

    /**
     * @param \Comely\Buffer\Bytes32 $msgHash
     * @param \Comely\Buffer\Bytes32|null $nonceK
     * @return \FurqanSiddiqui\BIP32\Buffers\Signature
     */
    public function sign(Bytes32 $msgHash, ?Bytes32 $nonceK = null): Signature
    {
        return new Signature($this->bip32, $this->eccPrivateKey->sign($msgHash, $nonceK));
    }

    /**
     * @param \Comely\Buffer\Bytes32 $msgHash
     * @param \Comely\Buffer\Bytes32|null $nonceK
     * @return \FurqanSiddiqui\BIP32\Buffers\Signature
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public function signRecoverable(Bytes32 $msgHash, ?Bytes32 $nonceK = null): Signature
    {
        return new Signature($this->bip32, $this->eccPrivateKey->signRecoverable($msgHash, $nonceK));
    }
}
