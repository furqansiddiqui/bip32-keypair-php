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

require "../vendor/autoload.php";

function run_vector_test(int $num, \FurqanSiddiqui\BIP32\BIP32 $bip32): array
{
    $vectors = json_decode(file_get_contents("vectors.json"), true);
    $vector = $vectors["vector" . $num] ?? null;
    if (!$vector) {
        throw new RuntimeException('No such test vector is configured');
    }

    $m = $bip32->masterKeyFromEntropy(\Comely\Buffer\Buffer::fromBase16($vector["seed"]));
    $report = [
        "vectorId" => $num,
        "total" => count($vector["tests"]),
        "failed" => 0,
        "passed" => 0,
        "tests" => []
    ];

    foreach ($vector["tests"] as $test) {
        unset($driven, $part, $crossCheck);
        $part = array_merge($test, [
            "result" => [
                "private" => null,
                "public" => null,
                "pass" => false,
                "private_unSerializes" => false,
                "private_crossChecked" => false,
                "public_unSerializes" => false,
                "public_crossChecked" => false,
            ]
        ]);

        try {
            $driven = $m->derivePath($test["path"]);
            $part["result"]["private"] = $bip32->base58->checkEncode($driven->serializePrivateKey());
            $crossCheck = \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair::Unserialize(
                $bip32,
                new \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key($bip32->base58->checkDecode($part["result"]["private"])->raw())
            );
            $part["result"]["private_unSerializes"] = true;
            if ($bip32->base58->checkEncode($crossCheck->serializePrivateKey()) === $part["result"]["private"]) {
                $part["result"]["private_crossChecked"] = true;
            }

            $part["result"]["public"] = $bip32->base58->checkEncode($driven->serializePublicKey());
            $crossCheck = \FurqanSiddiqui\BIP32\KeyPair\ExtendedKeyPair::Unserialize(
                $bip32,
                new \FurqanSiddiqui\BIP32\Buffers\SerializedBIP32Key($bip32->base58->checkDecode($part["result"]["public"])->raw())
            );
            $part["result"]["public_unSerializes"] = true;
            if ($bip32->base58->checkEncode($crossCheck->serializePublicKey()) === $part["result"]["public"]) {
                $part["result"]["public_crossChecked"] = true;
            }
        } catch (Throwable $e) {
            $part["error"] = [
                get_class($e),
                $e->getCode(),
                $e->getMessage()
            ];
        }

        if ($part["result"]["private"] ?? null === $test["private"]) {
            if ($part["result"]["public"] ?? null === $test["public"]) {
                if ($part["result"]["private_unSerializes"] && $part["result"]["private_crossChecked"]) {
                    if ($part["result"]["public_unSerializes"] && $part["result"]["public_crossChecked"]) {
                        $part["result"]["pass"] = true;
                        $report["passed"]++;
                    }
                }
            }
        }

        if (!$part["result"]["pass"]) {
            $report["failed"]++;
        }

        $report["tests"][] = $part;
    }

    return $report;
}

function process_vector_test_results(array $report): never
{
    $json = json_encode($report);
    file_put_contents(sprintf("vector_%d_result.json", $report["vectorId"]), $json);
    header("Content-type: application/json");
    exit($json);
}


