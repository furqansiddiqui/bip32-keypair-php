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

use Comely\Buffer\AbstractFixedLenBuffer;
use Comely\Buffer\Traits\CompareBuffersDataTrait;

/**
 * Class Bits32
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class Bits32 extends AbstractFixedLenBuffer
{
    /** @var int */
    protected const SIZE = 4;
    /** @var int */
    protected const PAD_TO_LENGTH = STR_PAD_LEFT;
    /** @var bool */
    protected bool $readOnly = true;

    use CompareBuffersDataTrait;

    /**
     * @param int $value
     * @return static
     */
    public static function fromInteger(int $value): static
    {
        if ($value < 0 || $value > 0xffffffff) {
            throw new \OverflowException('Argument is not a 32 bit unsigned integer');
        }

        return new static(str_pad(pack("N", $value), 4, "\0", STR_PAD_LEFT));
    }

    /**
     * @return int
     */
    public function toInt(): int
    {
        return unpack("N", $this->data)[1];
    }

    /**
     * @return bool
     */
    public function isZeroBytes(): bool
    {
        return $this->toInt() === 0;
    }
}
