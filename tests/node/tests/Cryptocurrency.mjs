/**
 * Cryptocurrency identifier inspection library tests.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

/* eslint camelcase: 0 */

import assert from "assert";
import {createHash} from "crypto";
import JSSHA3 from "js-sha3";
import TestRegister from "../../lib/TestRegister.mjs";
import {encode as encodeBase58} from "../../../src/core/lib/Base58.mjs";
import {encode as encodeBech32} from "../../../src/core/lib/Bech32.mjs";
import {cryptocurrencyIdentifierAndAddressInspector} from "../../../src/node/index.mjs";
import {
    decodeCryptoNoteBase58,
    encodeCryptoNoteBase58,
    inspectCryptocurrencyData,
} from "../../../src/core/lib/Cryptocurrency.mjs";
import CryptocurrencyIdentifierAndAddressInspector from "../../../src/core/operations/CryptocurrencyIdentifierAndAddressInspector.mjs";

const BITCOIN_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const BITCOIN_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
const BITCOIN_TESTNET_P2PKH = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
const BITCOIN_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const BITCOIN_TESTNET_P2WSH = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
const BITCOIN_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
const EVM_CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const MONERO_STANDARD = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
const MONERO_INTEGRATED = "4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK";
const GENERIC_BASE58CHECK = "TZJqCCFeCFdJJaGGgNhTbhcLdyjmqUrgFq";
const GENERIC_BECH32 = "custom1w3jhxaq593qur";

const textEncoder = new TextEncoder();

/**
 * Inspect one textual value.
 *
 * @param {string} value
 * @param {string} [detection]
 * @returns {Object}
 */
function inspect(value, detection="strict") {
    return inspectCryptocurrencyData(textEncoder.encode(value), {detection});
}

/**
 * Generate a Base58Check fixture from checksum-stripped bytes.
 *
 * @param {number[]|Uint8Array} body
 * @returns {string}
 */
function base58CheckFixture(body) {
    const first = createHash("sha256").update(Uint8Array.from(body)).digest();
    const checksum = createHash("sha256").update(first).digest().subarray(0, 4);
    return encodeBase58(Uint8Array.from([...body, ...checksum]));
}

/**
 * Generate a checksummed Monero fixture from a prefix and fixed public keys.
 *
 * @param {number} prefix
 * @param {boolean} integrated
 * @returns {string}
 */
function moneroFixture(prefix, integrated) {
    const spendKey = Uint8Array.from({length: 32}, (unused, index) => index + 1);
    const viewKey = Uint8Array.from({length: 32}, (unused, index) => 0x80 + index);
    const paymentId = Uint8Array.from([1, 3, 3, 7, 0xaa, 0xbb, 0xcc, 0xdd]);
    const body = Uint8Array.from([
        prefix,
        ...spendKey,
        ...viewKey,
        ...(integrated ? paymentId : []),
    ]);
    const checksum = JSSHA3.keccak256.array(body).slice(0, 4);
    return encodeCryptoNoteBase58([...body, ...checksum]);
}

TestRegister.addApiTests([
    {
        name: "Cryptocurrency inspection: stable envelope and Bitcoin P2PKH facts",
        run() {
            const envelope = inspect(`  ${BITCOIN_P2PKH}\r\n`);
            assert.strictEqual(envelope.schema_version, 1);
            assert.deepStrictEqual(envelope.source, {
                byte_length: 38,
                offset_unit: "byte",
                scan_encoding: "ASCII",
            });
            assert.deepStrictEqual(Object.keys(envelope).sort(), [
                "errors",
                "mode",
                "result_limit",
                "results",
                "schema_version",
                "source",
                "truncated",
                "warnings",
            ]);
            assert.strictEqual(envelope.mode, "inspect");
            assert.strictEqual(envelope.result_limit, null);
            assert.strictEqual(envelope.truncated, false);
            assert.deepStrictEqual(envelope.warnings, []);
            assert.deepStrictEqual(envelope.errors, []);
            assert.strictEqual(envelope.results.length, 1);
            const result = envelope.results[0];
            assert.deepStrictEqual(Object.keys(result).sort(), [
                "address_type",
                "candidates",
                "category",
                "checksum",
                "confidence",
                "currency",
                "currency_family",
                "decoded",
                "derived",
                "encoding",
                "errors",
                "format",
                "length",
                "network",
                "offset",
                "search_values",
                "valid",
                "value",
                "warnings",
            ]);
            assert.deepStrictEqual(Object.keys(result.checksum).sort(), [
                "algorithm",
                "computed",
                "encoded",
                "present",
                "valid",
            ]);
            assert.deepStrictEqual(Object.keys(result.candidates[0]).sort(), [
                "address_type",
                "basis",
                "confidence",
                "currency",
                "currency_family",
                "network",
            ]);
            assert.deepStrictEqual(Object.keys(result.search_values[0]).sort(), ["encoding", "name", "value"]);
            assert.strictEqual(result.offset, 2);
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.currency, "Bitcoin");
            assert.strictEqual(result.network, "mainnet");
            assert.strictEqual(result.address_type, "P2PKH");
            assert.strictEqual(result.decoded.payload_hex, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
            assert.strictEqual(result.derived.script_pubkey_hex, "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
        },
    },
    {
        name: "Cryptocurrency inspection: Bitcoin P2SH and checksum failure",
        run() {
            const p2sh = inspect(BITCOIN_P2SH).results[0];
            assert.strictEqual(p2sh.valid, true);
            assert.strictEqual(p2sh.address_type, "P2SH");
            assert.match(p2sh.derived.script_pubkey_hex, /^a914[0-9a-f]{40}87$/);

            const damaged = inspect(`${BITCOIN_P2PKH.slice(0, -1)}b`, "loose").results[0];
            assert.strictEqual(damaged.valid, false);
            assert.ok(damaged.errors.some(error => error.code === "checksum_mismatch"));
        },
    },
    {
        name: "Cryptocurrency inspection: Bitcoin leading zeros and wrong payload length",
        run() {
            const leadingZeros = base58CheckFixture([0x00, ...new Uint8Array(20)]);
            const p2pkh = inspect(leadingZeros).results[0];
            assert.strictEqual(p2pkh.valid, true);
            assert.strictEqual(p2pkh.value, "1111111111111111111114oLvT2");
            assert.strictEqual(p2pkh.decoded.payload_hex, "00".repeat(20));

            const wrongLength = base58CheckFixture([0x00, ...new Uint8Array(19)]);
            const invalid = inspect(wrongLength).results[0];
            assert.strictEqual(invalid.valid, false);
            assert.ok(invalid.errors.some(error => error.code === "invalid_bitcoin_payload_length"));

            const sharedP2sh = inspect(base58CheckFixture([0xc4, ...new Uint8Array(20)])).results[0];
            assert.strictEqual(sharedP2sh.valid, true);
            assert.strictEqual(sharedP2sh.address_type, "P2SH");
            assert.strictEqual(sharedP2sh.network, null);
        },
    },
    {
        name: "Cryptocurrency inspection: Bitcoin shared-network conventions remain ambiguous",
        run() {
            const legacy = inspect(BITCOIN_TESTNET_P2PKH).results[0];
            assert.strictEqual(legacy.valid, true);
            assert.strictEqual(legacy.currency, "Bitcoin");
            assert.strictEqual(legacy.network, null);
            assert.strictEqual(legacy.confidence, "medium");
            assert.deepStrictEqual(
                legacy.candidates.map(candidate => candidate.network).sort(),
                ["regtest", "signet", "testnet"]
            );
            assert.ok(legacy.warnings.some(warning => warning.code === "ambiguous_bitcoin_network"));

            const segwit = inspect(BITCOIN_TESTNET_P2WSH).results[0];
            assert.strictEqual(segwit.valid, true);
            assert.strictEqual(segwit.address_type, "P2WSH");
            assert.strictEqual(segwit.network, null);
            assert.deepStrictEqual(
                segwit.candidates.map(candidate => candidate.network).sort(),
                ["signet", "testnet"]
            );

            const program = Uint8Array.from({length: 20}, (unused, index) => index);
            const regtest = encodeBech32("bcrt", Uint8Array.from([0, ...program]), "Bech32", true);
            assert.strictEqual(inspect(regtest).results[0].network, "regtest");
        },
    },
    {
        name: "Cryptocurrency inspection: Bitcoin SegWit and Taproot",
        run() {
            const p2wpkh = inspect(BITCOIN_P2WPKH).results[0];
            assert.strictEqual(p2wpkh.valid, true);
            assert.strictEqual(p2wpkh.address_type, "P2WPKH");
            assert.strictEqual(p2wpkh.encoding, "bech32");
            assert.strictEqual(p2wpkh.derived.script_pubkey_hex, "0014751e76e8199196d454941c45d1b3a323f1433bd6");

            const p2tr = inspect(BITCOIN_P2TR).results[0];
            assert.strictEqual(p2tr.valid, true);
            assert.strictEqual(p2tr.address_type, "P2TR");
            assert.strictEqual(p2tr.encoding, "bech32m");
            assert.match(p2tr.derived.script_pubkey_hex, /^5120[0-9a-f]{64}$/);
        },
    },
    {
        name: "Cryptocurrency inspection: SegWit rejects the wrong checksum variant",
        run() {
            const program = Uint8Array.from({length: 32}, (unused, index) => index);
            const wrongVariant = encodeBech32("bc", Uint8Array.from([1, ...program]), "Bech32", true);
            const result = inspect(wrongVariant).results[0];
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(error => error.code === "wrong_witness_checksum_variant"));
        },
    },
    {
        name: "Cryptocurrency inspection: SegWit profile errors never downgrade to generic Bech32",
        run() {
            const invalidLength = inspect("bc1rw5uspcuh").results[0];
            assert.strictEqual(invalidLength.format, "bitcoin_segwit");
            assert.strictEqual(invalidLength.valid, false);
            assert.ok(invalidLength.errors.some(error => error.code === "invalid_witness_program_length"));

            const invalidPadding = inspect("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw5t87").results[0];
            assert.strictEqual(invalidPadding.format, "bitcoin_segwit");
            assert.ok(invalidPadding.errors.some(error => error.code === "invalid_witness_padding"));

            const invalidVersion = inspect("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7K8ZLUES").results[0];
            assert.strictEqual(invalidVersion.format, "bitcoin_segwit");
            assert.ok(invalidVersion.errors.some(error => error.code === "invalid_witness_version"));

            const uppercase = inspect(BITCOIN_P2WPKH.toUpperCase()).results[0];
            assert.strictEqual(uppercase.valid, true);
            assert.strictEqual(uppercase.derived.canonical_address, BITCOIN_P2WPKH);
        },
    },
    {
        name: "Cryptocurrency inspection: EIP-55 and uniform-case EVM addresses",
        run() {
            const checksummed = inspect(EVM_CHECKSUMMED).results[0];
            assert.strictEqual(checksummed.valid, true);
            assert.strictEqual(checksummed.currency_family, "EVM");
            assert.strictEqual(checksummed.network, null);
            assert.strictEqual(checksummed.checksum.present, true);
            assert.strictEqual(checksummed.checksum.valid, true);

            const lowercase = inspect(EVM_CHECKSUMMED.toLowerCase()).results[0];
            assert.strictEqual(lowercase.valid, true);
            assert.strictEqual(lowercase.checksum.present, false);
            assert.strictEqual(lowercase.checksum.valid, null);
            assert.strictEqual(lowercase.derived.checksummed_address, EVM_CHECKSUMMED);
        },
    },
    {
        name: "Cryptocurrency inspection: invalid EIP-55 remains diagnostic",
        run() {
            const invalid = inspect("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").results[0];
            assert.strictEqual(invalid.valid, false);
            assert.ok(invalid.errors.some(error => error.code === "invalid_eip55_checksum"));

            const overlong = inspect(`0x${"a".repeat(41)}`).results[0];
            assert.ok(overlong.errors.some(error => error.code === "invalid_evm_length"));

            const nonHex = inspect(`0x${"a".repeat(39)}g`).results[0];
            assert.ok(nonHex.errors.some(error => error.code === "invalid_evm_characters"));
        },
    },
    {
        name: "Cryptocurrency inspection: uppercase and bare EVM forms",
        run() {
            const uppercase = inspect(`0X${EVM_CHECKSUMMED.slice(2).toUpperCase()}`).results[0];
            assert.strictEqual(uppercase.valid, true);
            assert.strictEqual(uppercase.checksum.present, false);
            assert.strictEqual(uppercase.checksum.valid, null);

            const bare = inspect(EVM_CHECKSUMMED.slice(2)).results[0];
            assert.strictEqual(bare.valid, true);
            assert.strictEqual(bare.confidence, "medium");
            assert.ok(bare.warnings.some(warning => warning.code === "bare_hex_ambiguous"));
        },
    },
    {
        name: "Cryptocurrency inspection: official Monero standard and integrated addresses",
        run() {
            const standard = inspect(MONERO_STANDARD).results[0];
            assert.strictEqual(standard.valid, true);
            assert.strictEqual(standard.network, "mainnet");
            assert.strictEqual(standard.address_type, "standard");
            assert.strictEqual(standard.decoded.network_byte, "12");
            assert.strictEqual(standard.decoded.public_spend_key, "eda9fe8dfcdd25d5430ea64229d04f6b41b2e5a1587c29cd499a63eb79d11711");

            const integrated = inspect(MONERO_INTEGRATED).results[0];
            assert.strictEqual(integrated.valid, true);
            assert.strictEqual(integrated.address_type, "integrated");
            assert.strictEqual(integrated.decoded.payment_id, "8a125052fe6f3877");
        },
    },
    {
        name: "Cryptocurrency inspection: all Monero network and address-type prefixes",
        run() {
            const profiles = [
                [18, "mainnet", "standard"],
                [19, "mainnet", "integrated"],
                [42, "mainnet", "subaddress"],
                [53, "testnet", "standard"],
                [54, "testnet", "integrated"],
                [63, "testnet", "subaddress"],
                [24, "stagenet", "standard"],
                [25, "stagenet", "integrated"],
                [36, "stagenet", "subaddress"],
            ];

            profiles.forEach(([prefix, network, addressType]) => {
                const value = moneroFixture(prefix, addressType === "integrated");
                const result = inspect(value).results[0];
                assert.strictEqual(result.valid, true, `prefix ${prefix}`);
                assert.strictEqual(result.network, network, `prefix ${prefix}`);
                assert.strictEqual(result.address_type, addressType, `prefix ${prefix}`);
            });
        },
    },
    {
        name: "Cryptocurrency inspection: Monero checksum and block overflow diagnostics",
        run() {
            const replacement = MONERO_STANDARD.endsWith("1") ? "2" : "1";
            const damaged = inspect(MONERO_STANDARD.slice(0, -1) + replacement).results[0];
            assert.strictEqual(damaged.valid, false);
            assert.strictEqual(damaged.confidence, "low");
            assert.ok(damaged.errors.some(error => error.code === "checksum_mismatch"));
            assert.throws(() => decodeCryptoNoteBase58("z".repeat(11)), /overflows/);
            assert.throws(() => decodeCryptoNoteBase58("1"), /final block length/);
            assert.throws(() => decodeCryptoNoteBase58("0"), /invalid character/);
        },
    },
    {
        name: "Cryptocurrency inspection: valid generic encodings do not invent currencies",
        run() {
            const base58 = inspect(GENERIC_BASE58CHECK).results[0];
            assert.strictEqual(base58.valid, true);
            assert.strictEqual(base58.format, "generic_base58check");
            assert.strictEqual(base58.currency, null);
            assert.strictEqual(base58.decoded.body_hex, "42000102030405060708090a0b0c0d0e0f10111213");
            assert.strictEqual(Object.prototype.hasOwnProperty.call(base58.decoded, "version_byte"), false);

            const bech32 = inspect(GENERIC_BECH32).results[0];
            assert.strictEqual(bech32.valid, true);
            assert.strictEqual(bech32.format, "generic_bech32");
            assert.strictEqual(bech32.currency, null);
            assert.deepStrictEqual(bech32.decoded.data_words.slice(0, 3), [14, 17, 18]);

            const bech32m = inspect("A1LQFN3A").results[0];
            assert.strictEqual(bech32m.valid, true);
            assert.strictEqual(bech32m.encoding, "bech32m");
            assert.strictEqual(bech32m.currency, null);
            assert.strictEqual(bech32m.derived.canonical_value, "a1lqfn3a");

            const shortBase58 = inspect("8TAtRrz").results[0];
            assert.strictEqual(shortBase58.valid, true);
            assert.strictEqual(shortBase58.format, "generic_base58check");
        },
    },
    {
        name: "Cryptocurrency inspection: overlong Bech32 remains diagnostic",
        run() {
            const result = inspect(`bc1${"q".repeat(88)}`).results[0];
            assert.strictEqual(result.format, "bitcoin_segwit");
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(error => error.code === "invalid_bech32"));
            assert.match(result.errors[0].message, /maximum length/);
        },
    },
    {
        name: "Cryptocurrency scanning: byte offsets, order, and duplicate values",
        run() {
            const prefix = Uint8Array.from([0xff, 0x00, 0x41, 0x20]);
            const separator = textEncoder.encode(" / ");
            const address = textEncoder.encode(BITCOIN_P2PKH);
            const input = Uint8Array.from([...prefix, ...address, ...separator, ...address]);
            const envelope = inspectCryptocurrencyData(input, {mode: "scan", detection: "strict"});
            assert.strictEqual(envelope.mode, "scan");
            assert.strictEqual(envelope.result_limit, 1000);
            assert.strictEqual(envelope.truncated, false);
            assert.strictEqual(envelope.results.length, 2);
            assert.deepStrictEqual(envelope.results.map(result => result.offset), [4, 41]);
            assert.deepStrictEqual(envelope.results.map(result => result.value), [BITCOIN_P2PKH, BITCOIN_P2PKH]);
        },
    },
    {
        name: "Cryptocurrency scanning: bare EVM addresses are loose-only",
        run() {
            const bare = EVM_CHECKSUMMED.slice(2);
            const input = textEncoder.encode(`hash=${bare}`);
            const strict = inspectCryptocurrencyData(input, {mode: "scan", detection: "strict"});
            const loose = inspectCryptocurrencyData(input, {mode: "scan", detection: "loose"});
            assert.strictEqual(strict.results.length, 0);
            assert.strictEqual(loose.results.length, 1);
            assert.strictEqual(loose.results[0].confidence, "low");
            assert.ok(loose.results[0].warnings.some(warning => warning.code === "bare_hex_ambiguous"));
        },
    },
    {
        name: "Cryptocurrency scanning: short generic Base58Check and detector overlap",
        run() {
            const generic = inspectCryptocurrencyData(textEncoder.encode("id=8TAtRrz"), {
                mode: "scan",
                detection: "strict",
            });
            assert.strictEqual(generic.results.length, 1);
            assert.strictEqual(generic.results[0].format, "generic_base58check");

            const dottedHrp = inspectCryptocurrencyData(textEncoder.encode("value x.y1qypqx6prk9p."), {
                mode: "scan",
                detection: "strict",
            });
            assert.strictEqual(dottedHrp.results.length, 1);
            assert.strictEqual(dottedHrp.results[0].format, "generic_bech32");

            const overlap = inspectCryptocurrencyData(textEncoder.encode(`id=${"1".repeat(40)}`), {
                mode: "scan",
                detection: "loose",
            });
            assert.strictEqual(overlap.results.length, 1);
            assert.strictEqual(overlap.results[0].format, "evm_address");
        },
    },
    {
        name: "Cryptocurrency scanning: strict filters corruption and loose reports it",
        run() {
            const damaged = BITCOIN_P2WPKH.slice(0, -1) + "x";
            const input = textEncoder.encode(`address:${damaged}`);
            const strict = inspectCryptocurrencyData(input, {mode: "scan", detection: "strict"});
            const loose = inspectCryptocurrencyData(input, {mode: "scan", detection: "loose"});
            assert.strictEqual(strict.results.length, 0);
            assert.strictEqual(loose.results.length, 1);
            assert.strictEqual(loose.results[0].valid, false);
            assert.ok(loose.results[0].errors.some(error => error.code === "checksum_mismatch"));
        },
    },
    {
        name: "Cryptocurrency scanning: loose mode does not emit arbitrary invalid long Base58",
        run() {
            const input = textEncoder.encode(`token=${"z".repeat(95)} other=${`1${"z".repeat(94)}`}`);
            const loose = inspectCryptocurrencyData(input, {mode: "scan", detection: "loose"});
            assert.deepStrictEqual(loose.results, []);

            const replacement = MONERO_STANDARD.endsWith("1") ? "2" : "1";
            const damaged = MONERO_STANDARD.slice(0, -1) + replacement;
            const known = inspectCryptocurrencyData(textEncoder.encode(damaged), {
                mode: "scan",
                detection: "loose",
            });
            assert.strictEqual(known.results.length, 1);
            assert.strictEqual(known.results[0].currency, "Monero");
            assert.strictEqual(known.results[0].valid, false);
        },
    },
    {
        name: "Cryptocurrency scanning: result limits set truncation metadata",
        run() {
            const input = textEncoder.encode(`${BITCOIN_P2PKH} ${EVM_CHECKSUMMED}`);
            const envelope = inspectCryptocurrencyData(input, {
                mode: "scan",
                detection: "strict",
                maxResults: 1,
            });
            assert.strictEqual(envelope.results.length, 1);
            assert.strictEqual(envelope.truncated, true);
            assert.ok(envelope.warnings.some(warning => warning.code === "result_limit_reached"));
        },
    },
    {
        name: "Cryptocurrency inspection: empty and overlong values return envelope diagnostics",
        run() {
            assert.strictEqual(inspect(" \r\n").errors[0].code, "empty_input");
            assert.strictEqual(inspect("1".repeat(129)).errors[0].code, "identifier_too_long");
        },
    },
    {
        name: "Cryptocurrency operation: case-insensitive ingredients and generated Node wrapper",
        run() {
            const operation = new CryptocurrencyIdentifierAndAddressInspector();
            assert.strictEqual(operation.validateIngredients(["scan bytes", "strict", 1]), true);
            const direct = operation.run(textEncoder.encode(BITCOIN_P2PKH).buffer, ["scan bytes", "strict", 1]);
            assert.strictEqual(direct.mode, "scan");
            assert.strictEqual(direct.result_limit, 1);

            const defaultResult = cryptocurrencyIdentifierAndAddressInspector(BITCOIN_P2PKH).get("JSON");
            assert.strictEqual(defaultResult.mode, "inspect");
            assert.strictEqual(defaultResult.results[0].address_type, "P2PKH");

            const scanResult = cryptocurrencyIdentifierAndAddressInspector(`value=${BITCOIN_P2PKH}`, {
                mode: "scan bytes",
                detection: "strict",
                maximumResults: 1,
            }).get("JSON");
            assert.strictEqual(scanResult.mode, "scan");
            assert.strictEqual(scanResult.result_limit, 1);
            assert.strictEqual(scanResult.results.length, 1);
        },
    },
    {
        name: "Cryptocurrency presentation escapes untrusted keys and values",
        run() {
            const operation = new CryptocurrencyIdentifierAndAddressInspector();
            const html = operation.present({
                z_envelope: "last",
                a_envelope: "first",
                results: [{
                    z_result: "last",
                    a_result: [{"<img src=x onerror=alert(1)>": "<script>alert(1)</script>"}],
                }],
            });
            assert.ok(!html.includes("<script>"));
            assert.ok(!html.includes("<img src=x"));
            assert.ok(html.includes("&lt;script&gt;"));
            assert.ok(html.includes("&lt;img"));
            assert.ok(html.indexOf("a_envelope") < html.indexOf("z_envelope"));
            assert.ok(html.indexOf("a_result") < html.indexOf("z_result"));
        },
    },
]);
