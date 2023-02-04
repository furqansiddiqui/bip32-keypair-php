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

namespace FurqanSiddiqui\BIP32\Buffers;

use Comely\Buffer\AbstractByteArray;
use FurqanSiddiqui\BIP32\BIP32;

/**
 * Class Signature
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class Signature
{
    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $eccSignature
     */
    public function __construct(
        public readonly BIP32                                     $bip32,
        public readonly \FurqanSiddiqui\ECDSA\Signature\Signature $eccSignature
    )
    {
    }

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \Comely\Buffer\AbstractByteArray $signature
     * @return static
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public static function fromDER(BIP32 $bip32, AbstractByteArray $signature): static
    {
        return new static($bip32, \FurqanSiddiqui\ECDSA\Signature\Signature::fromDER($signature));
    }

    /**
     * @param \FurqanSiddiqui\BIP32\BIP32 $bip32
     * @param \Comely\Buffer\AbstractByteArray $signature
     * @return static
     * @throws \Comely\Buffer\Exception\ByteReaderUnderflowException
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public static function fromCompact(BIP32 $bip32, AbstractByteArray $signature): static
    {
        return new static($bip32, \FurqanSiddiqui\ECDSA\Signature\Signature::fromCompact($signature));
    }
}

