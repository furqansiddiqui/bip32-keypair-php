<?php
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
        "failed" => 0,
        "passed" => 0,
        "tests" => []
    ];

    foreach ($vector["tests"] as $test) {
        unset($driven, $part);
        $part = array_merge($test, [
            "result" => [
                "private" => null,
                "public" => null,
                "pass" => false,
            ]
        ]);

        try {
            $driven = $m->derivePath($test["path"]);
            $part["result"]["private"] = $bip32->base58->checkEncode($driven->serializePrivateKey());
            $part["result"]["public"] = $bip32->base58->checkEncode($driven->serializePublicKey());
        } catch (Throwable $e) {
            $part["error"] = [
                get_class($e),
                $e->getCode(),
                $e->getMessage()
            ];
        }

        if ($part["result"]["private"] === $test["private"]) {
            if ($part["result"]["public"] === $test["public"]) {
                $part["result"]["pass"] = true;
                $report["passed"]++;
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


