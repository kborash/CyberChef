/**
 * Cryptocurrency Identifier and Address Inspector operation tests.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

const OPERATION = "Cryptocurrency Identifier and Address Inspector";
const BITCOIN_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const BITCOIN_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const BITCOIN_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
const EVM_CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const MONERO_STANDARD = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
const MONERO_INTEGRATED = "4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK";

/**
 * Build a recipe that inspects input and extracts JSON fields.
 *
 * @param {string} query
 * @param {string} [mode]
 * @param {string} [detection]
 * @param {number} [maximumResults]
 * @returns {Object[]}
 */
function queryRecipe(query, mode="Inspect identifier", detection="Strict", maximumResults=1000) {
    return [
        {
            op: OPERATION,
            args: [mode, detection, maximumResults],
        },
        {
            op: "JPath expression",
            args: [query, "\n"],
        },
    ];
}

TestRegister.addTests([
    {
        name: `${OPERATION}: Bitcoin P2PKH scriptPubKey`,
        input: BITCOIN_P2PKH,
        expectedOutput: '"76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"',
        recipeConfig: queryRecipe("$.results[0].derived.script_pubkey_hex"),
    },
    {
        name: `${OPERATION}: Bitcoin native SegWit`,
        input: BITCOIN_P2WPKH,
        expectedOutput: '"P2WPKH"',
        recipeConfig: queryRecipe("$.results[0].address_type"),
    },
    {
        name: `${OPERATION}: Bitcoin Taproot`,
        input: BITCOIN_P2TR,
        expectedOutput: '"P2TR"',
        recipeConfig: queryRecipe("$.results[0].address_type"),
    },
    {
        name: `${OPERATION}: EIP-55 address`,
        input: EVM_CHECKSUMMED,
        expectedOutput: "true",
        recipeConfig: queryRecipe("$.results[0].checksum.valid"),
    },
    {
        name: `${OPERATION}: invalid mixed-case EIP-55`,
        input: "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        expectedOutput: '"invalid_eip55_checksum"',
        recipeConfig: queryRecipe("$.results[0].errors[0].code"),
    },
    {
        name: `${OPERATION}: Monero standard address keys`,
        input: MONERO_STANDARD,
        expectedOutput: '"eda9fe8dfcdd25d5430ea64229d04f6b41b2e5a1587c29cd499a63eb79d11711"',
        recipeConfig: queryRecipe("$.results[0].decoded.public_spend_key"),
    },
    {
        name: `${OPERATION}: Monero integrated payment ID`,
        input: MONERO_INTEGRATED,
        expectedOutput: '"8a125052fe6f3877"',
        recipeConfig: queryRecipe("$.results[0].decoded.payment_id"),
    },
    {
        name: `${OPERATION}: generic Bech32 stays generic`,
        input: "custom1w3jhxaq593qur",
        expectedOutput: '"generic_bech32"',
        recipeConfig: queryRecipe("$.results[0].format"),
    },
    {
        name: `${OPERATION}: malformed exact input is diagnostic`,
        input: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tx",
        expectedOutput: '"checksum_mismatch"',
        recipeConfig: queryRecipe("$.results[0].errors[0].code", "Inspect identifier", "Loose"),
    },
    {
        name: `${OPERATION}: scan finds ordered byte offsets`,
        input: `A🙂 pay ${BITCOIN_P2PKH} and ${EVM_CHECKSUMMED} then ${BITCOIN_P2WPKH}`,
        expectedOutput: "10\n49\n97",
        recipeConfig: queryRecipe("$.results[*].offset", "Scan bytes"),
    },
    {
        name: `${OPERATION}: strict scan rejects bare EVM ambiguity`,
        input: `hash=${EVM_CHECKSUMMED.slice(2)}`,
        expectedOutput: "[]",
        recipeConfig: queryRecipe("$.results", "Scan bytes", "Strict"),
    },
    {
        name: `${OPERATION}: loose scan includes bare EVM ambiguity`,
        input: `hash=${EVM_CHECKSUMMED.slice(2)}`,
        expectedOutput: '"low"',
        recipeConfig: queryRecipe("$.results[0].confidence", "Scan bytes", "Loose"),
    },
    {
        name: `${OPERATION}: scan preserves duplicate occurrences`,
        input: `${BITCOIN_P2PKH}\x00${BITCOIN_P2PKH}`,
        expectedOutput: `"${BITCOIN_P2PKH}"\n"${BITCOIN_P2PKH}"`,
        recipeConfig: queryRecipe("$.results[*].value", "Scan bytes"),
    },
    {
        name: `${OPERATION}: scan result limit`,
        input: `${BITCOIN_P2PKH} ${EVM_CHECKSUMMED}`,
        expectedOutput: '"result_limit_reached"',
        recipeConfig: queryRecipe("$.warnings[0].code", "Scan bytes", "Strict", 1),
    },
    {
        name: `${OPERATION}: empty input envelope`,
        input: "",
        expectedOutput: '"empty_input"',
        recipeConfig: queryRecipe("$.errors[0].code"),
    },
    {
        name: `${OPERATION}: human-readable presentation`,
        input: BITCOIN_P2PKH,
        expectedMatch: /Inspection summary.*Results.*P2PKH.*Bitcoin.*script_pubkey_hex/s,
        recipeConfig: [
            {
                op: OPERATION,
                args: ["Inspect identifier", "Strict", 1000],
            },
        ],
    },
]);
