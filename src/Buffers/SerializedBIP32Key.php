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

/**
 * Class SerializedBIP32Key
 * @package FurqanSiddiqui\BIP32\Buffers
 */
class SerializedBIP32Key extends AbstractFixedLenBuffer
{
    /** @var int */
    protected const SIZE = 78;
    /** @var bool */
    protected bool $readOnly = true;
}
