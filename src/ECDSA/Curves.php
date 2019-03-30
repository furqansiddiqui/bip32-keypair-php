<?php
/**
 * This file is a part of "furqansiddiqui/bip32-keypair-php" package.
 * https://github.com/"furqansiddiqui/bip32/bip32-keypair-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/"furqansiddiqui/bip32/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\BIP32\ECDSA;

/**
 * Class Curves
 * @package FurqanSiddiqui\BIP32\ECDSA
 */
class Curves
{
    /** @var array */
    public const INDEX = [
        self::SECP256K1 => "Secp256k1",
        self::SECP256K1_OPENSSL => "Secp256k1_OpenSSL"
    ];

    public const SECP256K1 = 8;
    public const SECP256K1_OPENSSL = 16;

    /** @var callable */
    private $callback;

    /**
     * Curves constructor.
     * @param callable $callback
     */
    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }

    /**
     * @param int $curve
     */
    private function select(int $curve): void
    {
        if (!in_array($curve, array_keys(self::INDEX))) {
            throw new \InvalidArgumentException('Cannot use an invalid ECDSA curve');
        }

        call_user_func_array($this->callback, [$curve]);
    }

    /**
     * @return void
     */
    public function secp256k1(): void
    {
        $this->select(self::SECP256K1);
    }

    /**
     * @return void
     */
    public function secp256k1_OpenSSL(): void
    {
        $this->select(self::SECP256K1_OPENSSL);
    }
}