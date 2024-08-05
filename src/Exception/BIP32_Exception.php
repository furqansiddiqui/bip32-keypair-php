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

namespace FurqanSiddiqui\BIP32\Exception;


/**
 * Class BIP32_Exception
 * @package FurqanSiddiqui\BIP32\Exception
 */
class BIP32_Exception extends \Exception
{
    /**
     * @param string $message
     * @param int $code
     * @param \Throwable|null $previous
     * @param array $debug
     */
    public function __construct(
        string       $message = "",
        int          $code = 0,
        \Throwable   $previous = null,
        public array $debug = []
    )
    {
        parent::__construct($message, $code, $previous);
    }
}
