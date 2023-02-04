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

require "../vendor/autoload.php";
require "vector_test_incl.php";

$vectors = json_decode(file_get_contents("vectors.json"), true);
$vector = $vectors["vector5"] ?? null;
if (!$vector) {
    throw new RuntimeException('Test vector 5 not configured');
}

$ecc = FurqanSiddiqui\ECDSA\ECDSA::Secp256k1_GMP();
$bip32 = new \FurqanSiddiqui\BIP32\BIP32($ecc, \FurqanSiddiqui\BIP32\Networks\Bitcoin::loadConfig());

$report = [
    "vectorId" => 5,
    "total" => count($vector),
    "passed" => 0,
    "failed" => 0,
    "tests" => []
];
foreach ($vector as $test) {
    unset($key, $buffer);
    $part = [
        "pass" => false,
        "test" => $test
    ];

    try {
        $buffer = new \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key($bip32->base58->checkDecode($test["key"]));
        $key = \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair::Unserialize($bip32, $buffer);
        $report["failed"]++;
    } catch (Throwable $t) {
        $part["exception"] = [
            "class" => get_class($t),
            "code" => $t->getCode(),
            "message" => $t->getMessage()
        ];

        $part["pass"] = true;
        $report["passed"]++;
    }

    $report["tests"][] = $part;
}

process_vector_test_results($report);
