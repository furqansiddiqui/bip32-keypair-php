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
use Comely\Buffer\BigInteger;
use Comely\Buffer\BigInteger\BaseCharset;
use Comely\Buffer\Buffer;
use FurqanSiddiqui\BIP32\Exception\Base58CheckException;

/**
 * Class Base58
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class Base58 extends BaseCharset
{
    /**
     * Base58 charset constructor
     */
    public function __construct()
    {
        return parent::__construct(
            charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            caseSensitive: true
        );
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $ser
     * @return string
     */
    public function encode(AbstractByteArray $ser): string
    {
        return (new BigInteger($ser))->toCustomBase($this);
    }

    /**
     * @param string $encoded
     * @return \Comely\Buffer\AbstractByteArray
     */
    public function decode(string $encoded): AbstractByteArray
    {
        return BigInteger::fromCustomBase($encoded, $this)->toBuffer();
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $bn
     * @return \FurqanSiddiqui\BIP32\Buffers\Bits32
     */
    public function computeChecksum(AbstractByteArray $bn): Bits32
    {
        return new Bits32(substr(hash("sha256", hash("sha256", $bn->raw(), true), true), 0, 4));
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $ser
     * @return string
     */
    public function checkEncode(AbstractByteArray $ser): string
    {
        $ser2 = new Buffer($ser->raw());
        $ser2->append($this->computeChecksum($ser));
        return $this->encode($ser2);
    }

    /**
     * @param string $encoded
     * @return \Comely\Buffer\AbstractByteArray
     * @throws \FurqanSiddiqui\BIP32\Exception\Base58CheckException
     */
    public function checkDecode(string $encoded): AbstractByteArray
    {
        $serBf = $this->decode($encoded)->raw();
        $data = new Buffer(substr($serBf, 0, -4));
        if ($this->computeChecksum($data)->raw() !== substr($serBf, -4)) {
            throw new Base58CheckException('Checksum does not match');
        }

        return $data;
    }
}
