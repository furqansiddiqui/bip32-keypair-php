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

require "vector_test_incl.php";

$ecc = \FurqanSiddiqui\ECDSA\ECDSA::Secp256k1_GMP();
$bip32 = new \FurqanSiddiqui\BIP32\BIP32($ecc, \FurqanSiddiqui\BIP32\Networks\Bitcoin::loadConfig());
$result = run_vector_test(4, $bip32);
process_vector_test_results($result);
