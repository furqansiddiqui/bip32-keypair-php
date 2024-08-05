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

use Charcoal\Adapters\GMP\BigInteger;
use Charcoal\Adapters\GMP\CustomBaseCharset;
use Charcoal\Buffers\AbstractByteArray;
use Charcoal\Buffers\Buffer;
use FurqanSiddiqui\BIP32\Exception\Base58CheckException;

/**
 * Class Base58
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class Base58 extends CustomBaseCharset
{
    /**
     * @param \Charcoal\Buffers\AbstractByteArray $ser
     * @param bool $convertLeadingZeros
     * @return string
     */
    public function encode(AbstractByteArray $ser, bool $convertLeadingZeros = true): string
    {
        $zCount = $convertLeadingZeros ? $ser->len() - strlen(ltrim($ser->raw(), "\0")) : 0;
        $result = BigInteger::fromBuffer($ser)->toCustomBase($this);
        if ($zCount > 0) {
            $result = str_repeat($this->charset[0], $zCount) . $result;
        }

        return $result;
    }

    /**
     * @param string $encoded
     * @param bool $convertLeadingZeros
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function decode(string $encoded, bool $convertLeadingZeros = true): AbstractByteArray
    {
        $zCount = $convertLeadingZeros ? strlen($encoded) - strlen(ltrim($encoded, $this->charset[0])) : 0;
        return Buffer::fromBase16(BigInteger::fromCustomBase($encoded, $this)->toBase16())
            ->prepend(str_repeat("\0", $zCount));
    }

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $bn
     * @return \FurqanSiddiqui\BIP32\Buffers\Bits32
     */
    public function computeChecksum(AbstractByteArray $bn): Bits32
    {
        return new Bits32(substr(hash("sha256", hash("sha256", $bn->raw(), true), true), 0, 4));
    }

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $ser
     * @param bool $convertLeadingZeros
     * @return string
     */
    public function checkEncode(AbstractByteArray $ser, bool $convertLeadingZeros = true): string
    {
        $ser2 = new Buffer($ser->raw());
        $ser2->append($this->computeChecksum($ser));
        return $this->encode($ser2, $convertLeadingZeros);
    }

    /**
     * @param string $encoded
     * @param bool $convertLeadingZeros
     * @return \Charcoal\Buffers\AbstractByteArray
     * @throws \FurqanSiddiqui\BIP32\Exception\Base58CheckException
     */
    public function checkDecode(string $encoded, bool $convertLeadingZeros = true): AbstractByteArray
    {
        $serBf = $this->decode($encoded, $convertLeadingZeros)->raw();
        $data = new Buffer(substr($serBf, 0, -4));
        if ($this->computeChecksum($data)->raw() !== substr($serBf, -4)) {
            throw new Base58CheckException('Checksum does not match');
        }

        return $data;
    }
}
