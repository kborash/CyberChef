/**
 * Offline cryptocurrency identifier inspection resources.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

/* eslint camelcase: 0 */

import JSSHA3 from "js-sha3";
import Utils from "../Utils.mjs";
import {decode as decodeBase58, encode as encodeBase58, ALPHABET_OPTIONS} from "./Base58.mjs";
import {fromWords, parse as parseBech32} from "./Bech32.mjs";
import {runHash} from "./Hash.mjs";
import {fromHex, toHexFast} from "./Hex.mjs";


const BITCOIN_BASE58_ALPHABET = ALPHABET_OPTIONS[0].value;
const MAX_IDENTIFIER_LENGTH = 128;
const MAX_CANDIDATE_ATTEMPTS = 100000;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const MONERO_ENCODED_BLOCK_SIZE = 11;
const MONERO_FULL_BLOCK_SIZE = 8;
const MONERO_ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const MONERO_DECODED_BLOCK_SIZES = new Map([
    [2, 1],
    [3, 2],
    [5, 3],
    [6, 4],
    [7, 5],
    [9, 6],
    [10, 7],
]);

const BITCOIN_VERSIONS = new Map([
    [0x00, {
        addressType: "P2PKH",
        networks: ["mainnet"],
        confidence: "high",
    }],
    [0x05, {
        addressType: "P2SH",
        networks: ["mainnet"],
        confidence: "high",
    }],
    [0x6f, {
        addressType: "P2PKH",
        networks: ["testnet", "signet", "regtest"],
        confidence: "medium",
    }],
    [0xc4, {
        addressType: "P2SH",
        networks: ["testnet", "signet", "regtest"],
        confidence: "medium",
    }],
]);

const BITCOIN_BECH32_NETWORKS = new Map([
    ["bc", ["mainnet"]],
    ["tb", ["testnet", "signet"]],
    ["bcrt", ["regtest"]],
]);

const MONERO_PREFIXES = new Map([
    [18, {network: "mainnet", addressType: "standard"}],
    [19, {network: "mainnet", addressType: "integrated"}],
    [42, {network: "mainnet", addressType: "subaddress"}],
    [53, {network: "testnet", addressType: "standard"}],
    [54, {network: "testnet", addressType: "integrated"}],
    [63, {network: "testnet", addressType: "subaddress"}],
    [24, {network: "stagenet", addressType: "standard"}],
    [25, {network: "stagenet", addressType: "integrated"}],
    [36, {network: "stagenet", addressType: "subaddress"}],
]);

const CONFIDENCE_RANK = new Map([
    ["low", 0],
    ["medium", 1],
    ["high", 2],
]);


/**
 * Create a diagnostic entry.
 *
 * @param {string} code
 * @param {string} message
 * @param {number} [position]
 * @returns {Object}
 */
function diagnostic(code, message, position) {
    const result = {code, message};
    if (typeof position === "number") result.position = position;
    return result;
}


/**
 * Create a stable result object.
 *
 * @param {string} value
 * @param {number} offset
 * @returns {Object}
 */
function createResult(value, offset) {
    return {
        value,
        offset,
        length: value.length,
        valid: false,
        category: "unrecognized",
        format: null,
        encoding: null,
        currency_family: null,
        currency: null,
        network: null,
        address_type: null,
        confidence: null,
        checksum: {
            algorithm: null,
            present: false,
            valid: null,
            encoded: null,
            computed: null,
        },
        decoded: {},
        derived: {},
        candidates: [],
        search_values: [],
        warnings: [],
        errors: [],
    };
}


/**
 * Add a unique search value.
 *
 * @param {Object} result
 * @param {string} name
 * @param {string} value
 * @param {string} encoding
 */
function addSearchValue(result, name, value, encoding) {
    if (value === null || value === undefined || value === "") return;
    if (result.search_values.some(item => item.value === value && item.encoding === encoding)) return;
    result.search_values.push({name, value, encoding});
}


/**
 * Return a common non-null candidate property, or null when candidates disagree.
 *
 * @param {Object[]} candidates
 * @param {string} property
 * @returns {*}
 */
function commonCandidateValue(candidates, property) {
    if (!candidates.length) return null;
    const values = [...new Set(candidates.map(candidate => candidate[property]))];
    return values.length === 1 ? values[0] : null;
}


/**
 * Populate common summary fields from interpretations.
 *
 * @param {Object} result
 * @returns {Object}
 */
function finaliseResult(result) {
    result.currency_family = commonCandidateValue(result.candidates, "currency_family");
    result.currency = commonCandidateValue(result.candidates, "currency");
    result.network = commonCandidateValue(result.candidates, "network");
    result.address_type = commonCandidateValue(result.candidates, "address_type");

    if (result.candidates.length) {
        result.confidence = result.candidates.reduce((lowest, candidate) => {
            if (CONFIDENCE_RANK.get(candidate.confidence) < CONFIDENCE_RANK.get(lowest)) {
                return candidate.confidence;
            }
            return lowest;
        }, "high");
    }

    return result;
}


/**
 * Convert bytes to an isolated ArrayBuffer.
 *
 * @param {number[]|Uint8Array} bytes
 * @returns {ArrayBuffer}
 */
function toArrayBuffer(bytes) {
    return Uint8Array.from(bytes).buffer;
}


/**
 * Calculate SHA-256.
 *
 * @param {number[]|Uint8Array} bytes
 * @returns {Uint8Array}
 */
function sha256(bytes) {
    return Uint8Array.from(fromHex(runHash("sha256", toArrayBuffer(bytes)), "None"));
}


/**
 * Calculate double SHA-256.
 *
 * @param {number[]|Uint8Array} bytes
 * @returns {Uint8Array}
 */
function doubleSha256(bytes) {
    return sha256(sha256(bytes));
}


/**
 * Calculate legacy Keccak-256.
 *
 * @param {string|number[]|Uint8Array} value
 * @returns {Uint8Array}
 */
function keccak256(value) {
    return Uint8Array.from(JSSHA3.keccak256.array(value));
}


/**
 * Compare byte arrays without early return.
 *
 * @param {number[]|Uint8Array} left
 * @param {number[]|Uint8Array} right
 * @returns {boolean}
 */
function bytesEqual(left, right) {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
    return difference === 0;
}


/**
 * Add a Bitcoin candidate for every possible network.
 *
 * @param {Object} result
 * @param {string[]} networks
 * @param {string} addressType
 * @param {string} confidence
 * @param {string} basis
 */
function addBitcoinCandidates(result, networks, addressType, confidence, basis) {
    networks.forEach(network => {
        result.candidates.push({
            currency_family: null,
            currency: "Bitcoin",
            network,
            address_type: addressType,
            confidence,
            basis: [basis],
        });
    });
}


/**
 * Infer a damaged Bitcoin Base58 address profile from its textual prefix.
 *
 * @param {string} value
 * @returns {Object|null}
 */
function damagedBitcoinProfile(value) {
    if (value.length < 20 || value.length > 40) return null;
    if (value[0] === "1") return BITCOIN_VERSIONS.get(0x00);
    if (value[0] === "3") return BITCOIN_VERSIONS.get(0x05);
    if (value[0] === "m" || value[0] === "n") return BITCOIN_VERSIONS.get(0x6f);
    if (value[0] === "2") return BITCOIN_VERSIONS.get(0xc4);
    return null;
}


/**
 * Inspect a Base58Check value.
 *
 * @param {string} value
 * @param {number} offset
 * @param {boolean} allowDamaged
 * @returns {Object|null}
 */
function inspectBase58Check(value, offset, allowDamaged=false) {
    if (!new RegExp(`^[${BITCOIN_BASE58_ALPHABET}]+$`).test(value)) return null;

    const result = createResult(value, offset);
    result.format = "generic_base58check";
    result.encoding = "base58check";
    result.category = "generic_encoding";
    result.checksum.algorithm = "double_sha256";

    let decoded;
    try {
        decoded = Uint8Array.from(decodeBase58(value, BITCOIN_BASE58_ALPHABET, false));
    } catch (error) {
        result.errors.push(diagnostic("invalid_base58", error.message));
        return {result: finaliseResult(result), known: false, generic: true};
    }

    result.decoded.bytes_hex = toHexFast(decoded);
    addSearchValue(result, "encoded_value", value, "text");

    if (decoded.length < 5) {
        result.errors.push(diagnostic(
            "base58check_too_short",
            "Base58Check data must contain a body and a four-byte checksum."
        ));
        return {result: finaliseResult(result), known: false, generic: true};
    }

    const body = decoded.slice(0, -4);
    const encodedChecksum = decoded.slice(-4);
    const computedChecksum = doubleSha256(body).slice(0, 4);
    const checksumValid = bytesEqual(encodedChecksum, computedChecksum);
    const binaryProfile = body.length ? BITCOIN_VERSIONS.get(body[0]) : null;
    const inferredProfile = !checksumValid && allowDamaged && !binaryProfile ? damagedBitcoinProfile(value) : null;
    const profile = binaryProfile || inferredProfile;
    const knownProfile = Boolean(profile);

    result.decoded.body_hex = toHexFast(body);
    result.checksum.present = true;
    result.checksum.valid = checksumValid;
    result.checksum.encoded = toHexFast(encodedChecksum);
    result.checksum.computed = toHexFast(computedChecksum);
    addSearchValue(result, "checksum_stripped_body", result.decoded.body_hex, "hex");

    if (knownProfile) {
        result.format = "bitcoin_base58check";
        result.category = "probable_cryptocurrency_address";
        if (binaryProfile) result.decoded.version_byte = body[0].toString(16).padStart(2, "0");
        addBitcoinCandidates(
            result,
            profile.networks,
            profile.addressType,
            checksumValid && body.length === 21 ? profile.confidence : "low",
            binaryProfile ? `version_byte_${result.decoded.version_byte}` : `text_prefix_${value[0]}`
        );
        result.warnings.push(diagnostic(
            "base58_version_not_unique",
            "Base58Check version bytes are conventions and may be reused by other cryptocurrencies."
        ));

        if (profile.networks.length > 1) {
            result.warnings.push(diagnostic(
                "ambiguous_bitcoin_network",
                "This version byte is shared by Bitcoin testnet, signet, and regtest."
            ));
        }

        if (inferredProfile) {
            result.errors.push(diagnostic(
                "damaged_bitcoin_candidate",
                "The textual prefix resembles a Bitcoin address, but a valid version byte and checksum could not be recovered."
            ));
        }

        if (binaryProfile && body.length !== 21) {
            result.errors.push(diagnostic(
                "invalid_bitcoin_payload_length",
                `Bitcoin ${profile.addressType} addresses require a 20-byte payload; got ${Math.max(0, body.length - 1)} bytes.`
            ));
        } else if (binaryProfile) {
            const payload = body.slice(1);
            const payloadHex = toHexFast(payload);
            result.decoded.payload_hex = payloadHex;
            result.derived.script_pubkey_hex = profile.addressType === "P2PKH" ?
                `76a914${payloadHex}88ac` : `a914${payloadHex}87`;
            addSearchValue(result, "payload", payloadHex, "hex");
            addSearchValue(result, "script_pubkey", result.derived.script_pubkey_hex, "hex");
        }
    } else {
        result.warnings.push(diagnostic(
            "generic_encoding_only",
            "A valid Base58Check checksum does not by itself identify a cryptocurrency or define a version-byte boundary."
        ));
    }

    if (!checksumValid) {
        result.errors.push(diagnostic("checksum_mismatch", "Base58Check checksum mismatch."));
    }

    result.valid = checksumValid && (!knownProfile || (Boolean(binaryProfile) && body.length === 21));
    if (result.valid) {
        result.category = knownProfile ? "cryptocurrency_address" : "generic_encoding";
        result.derived.canonical_value = encodeBase58(decoded, BITCOIN_BASE58_ALPHABET);
        addSearchValue(result, "canonical_value", result.derived.canonical_value, "text");
    }

    const plausibleKnownProfile = knownProfile && (
        body.length === 21 ||
        (allowDamaged && value.length >= 20 && value.length <= 40)
    );
    return {
        result: finaliseResult(result),
        known: knownProfile,
        generic: !knownProfile,
        looseScan: plausibleKnownProfile,
    };
}


/**
 * Generate an EIP-55 representation.
 *
 * @param {string} lowercaseHex
 * @returns {string}
 */
function toEip55(lowercaseHex) {
    const hash = JSSHA3.keccak256(lowercaseHex);
    let result = "0x";

    for (let i = 0; i < lowercaseHex.length; i++) {
        const character = lowercaseHex[i];
        result += /[a-f]/.test(character) && parseInt(hash[i], 16) >= 8 ?
            character.toUpperCase() : character;
    }

    return result;
}


/**
 * Inspect an EVM address.
 *
 * @param {string} value
 * @param {number} offset
 * @param {boolean} bareScanCandidate
 * @returns {Object|null}
 */
function inspectEvm(value, offset, bareScanCandidate=false) {
    const hasPrefix = /^0x/i.test(value);
    const hex = hasPrefix ? value.slice(2) : value;
    if (!hasPrefix && !/^[0-9a-fA-F]{40}$/.test(hex)) return null;
    const hexCharactersValid = /^[0-9a-fA-F]*$/.test(hex);

    const result = createResult(value, offset);
    result.format = "evm_address";
    result.encoding = "hex";
    result.category = "probable_cryptocurrency_address";
    result.checksum.algorithm = "eip55";

    const lowercaseHex = hex.toLowerCase();
    const syntacticallyValid = hexCharactersValid && hex.length === 40;
    const hasLowercaseLetters = /[a-f]/.test(hex);
    const hasUppercaseLetters = /[A-F]/.test(hex);
    const mixedCase = hasLowercaseLetters && hasUppercaseLetters;
    const checksummed = syntacticallyValid ? toEip55(lowercaseHex) : null;
    const checksumValid = mixedCase && checksummed ? checksummed.slice(2) === hex : null;

    result.checksum.present = mixedCase;
    result.checksum.valid = checksumValid;
    result.decoded.payload_hex = syntacticallyValid ? lowercaseHex : null;

    if (!hexCharactersValid) {
        result.errors.push(diagnostic(
            "invalid_evm_characters",
            "EVM addresses may contain only hexadecimal characters after the optional 0x prefix."
        ));
    } else if (!syntacticallyValid) {
        result.errors.push(diagnostic(
            "invalid_evm_length",
            `EVM addresses require 40 hexadecimal characters; got ${hex.length}.`
        ));
    } else {
        result.derived.lowercase_address = `0x${lowercaseHex}`;
        result.derived.checksummed_address = checksummed;
        addSearchValue(result, "payload", lowercaseHex, "hex");
        addSearchValue(result, "lowercase_address", result.derived.lowercase_address, "text");
        addSearchValue(result, "checksummed_address", checksummed, "text");
    }

    if (mixedCase && checksumValid === false) {
        result.errors.push(diagnostic("invalid_eip55_checksum", "Mixed-case EVM address does not satisfy EIP-55."));
    }

    let confidence = hasPrefix ? "high" : "medium";
    if (bareScanCandidate) confidence = "low";
    if (!syntacticallyValid || checksumValid === false) confidence = "low";
    result.candidates.push({
        currency_family: "EVM",
        currency: null,
        network: null,
        address_type: null,
        confidence,
        basis: [hasPrefix ? "0x_prefixed_20_byte_hex" : "bare_20_byte_hex"],
    });
    result.warnings.push(diagnostic(
        "evm_network_ambiguous",
        "This address format is shared by many EVM-compatible networks and does not identify a blockchain."
    ));
    result.warnings.push(diagnostic(
        "evm_account_type_unknown",
        "Address bytes do not distinguish a contract from an externally owned account."
    ));
    if (!hasPrefix) {
        result.warnings.push(diagnostic(
            "bare_hex_ambiguous",
            "A bare 40-character hexadecimal value may be an unrelated 160-bit hash."
        ));
    }

    result.valid = syntacticallyValid && checksumValid !== false;
    if (result.valid) result.category = "cryptocurrency_address";

    return {result: finaliseResult(result), known: true, generic: false};
}


/**
 * Convert a witness version to its script opcode.
 *
 * @param {number} witnessVersion
 * @returns {number}
 */
function witnessOpcode(witnessVersion) {
    return witnessVersion === 0 ? 0 : 0x50 + witnessVersion;
}


/**
 * Inspect a Bech32 or Bech32m value.
 *
 * @param {string} value
 * @param {number} offset
 * @returns {Object|null}
 */
function inspectBech32(value, offset) {
    if (value.length < 8 || value.lastIndexOf("1") <= 0) return null;

    let parsed;
    try {
        parsed = parseBech32(value);
    } catch (error) {
        const looksBech32 = /^[!-~]+1[0-9A-Za-z]+$/.test(value);
        if (!looksBech32) return null;
        const result = createResult(value, offset);
        result.format = /^(?:bc|tb|bcrt)1/i.test(value) ? "bitcoin_segwit" : "generic_bech32";
        result.encoding = "bech32";
        result.category = /^(?:bc|tb|bcrt)1/i.test(value) ?
            "probable_cryptocurrency_address" : "generic_encoding";
        result.errors.push(diagnostic("invalid_bech32", error.message));
        return {
            result: finaliseResult(result),
            known: result.format === "bitcoin_segwit",
            generic: result.format === "generic_bech32",
        };
    }

    const result = createResult(value, offset);
    const hrp = parsed.hrp.toLowerCase();
    const knownBitcoinHrp = BITCOIN_BECH32_NETWORKS.has(hrp);
    const dataWords = parsed.dataWords || [];
    const checksumWords = parsed.checksumWords || [];
    const checksumEncoding = parsed.checksumEncoding || null;

    result.format = knownBitcoinHrp ? "bitcoin_segwit" : "generic_bech32";
    result.encoding = checksumEncoding ? checksumEncoding.toLowerCase() : "bech32";
    result.category = knownBitcoinHrp ? "probable_cryptocurrency_address" : "generic_encoding";
    result.checksum.algorithm = checksumEncoding ? checksumEncoding.toLowerCase() : "bech32_or_bech32m";
    result.checksum.present = checksumWords.length === 6;
    result.checksum.valid = parsed.checksumValid;
    result.checksum.encoded = checksumWords;
    result.decoded.hrp = hrp;
    result.decoded.data_words = dataWords;
    result.decoded.checksum_words = checksumWords;
    addSearchValue(result, "encoded_value", value, "text");

    if (!parsed.checksumValid) {
        result.errors.push(diagnostic("checksum_mismatch", "Bech32/Bech32m checksum mismatch."));
    }

    if (knownBitcoinHrp) {
        const networks = BITCOIN_BECH32_NETWORKS.get(hrp);
        const witnessVersion = dataWords.length ? dataWords[0] : null;
        let witnessProgram = null;
        let profileValid = true;

        if (witnessVersion === null) {
            profileValid = false;
            result.errors.push(diagnostic("missing_witness_version", "Bitcoin SegWit data must include a witness version."));
        } else if (witnessVersion < 0 || witnessVersion > 16) {
            profileValid = false;
            result.errors.push(diagnostic(
                "invalid_witness_version",
                `Bitcoin witness version must be between 0 and 16; got ${witnessVersion}.`
            ));
        }

        if (witnessVersion !== null && witnessVersion >= 0 && witnessVersion <= 16) {
            try {
                witnessProgram = Uint8Array.from(fromWords(dataWords.slice(1)));
            } catch (error) {
                profileValid = false;
                result.errors.push(diagnostic("invalid_witness_padding", error.message));
            }
        }

        if (witnessProgram) {
            if (witnessProgram.length < 2 || witnessProgram.length > 40) {
                profileValid = false;
                result.errors.push(diagnostic(
                    "invalid_witness_program_length",
                    `Witness programs must be 2 to 40 bytes; got ${witnessProgram.length}.`
                ));
            }
            if (witnessVersion === 0 && witnessProgram.length !== 20 && witnessProgram.length !== 32) {
                profileValid = false;
                result.errors.push(diagnostic(
                    "invalid_v0_witness_program_length",
                    `Witness version 0 programs must be 20 or 32 bytes; got ${witnessProgram.length}.`
                ));
            }

            const expectedEncoding = witnessVersion === 0 ? "Bech32" : "Bech32m";
            if (checksumEncoding && checksumEncoding !== expectedEncoding) {
                profileValid = false;
                result.errors.push(diagnostic(
                    "wrong_witness_checksum_variant",
                    `Witness version ${witnessVersion} requires ${expectedEncoding}.`
                ));
            }

            const programHex = toHexFast(witnessProgram);
            let addressType = `witness_v${witnessVersion}`;
            if (witnessVersion === 0 && witnessProgram.length === 20) addressType = "P2WPKH";
            if (witnessVersion === 0 && witnessProgram.length === 32) addressType = "P2WSH";
            if (witnessVersion === 1 && witnessProgram.length === 32) addressType = "P2TR";

            result.decoded.witness_version = witnessVersion;
            result.decoded.witness_program_hex = programHex;
            result.derived.script_pubkey_hex = `${witnessOpcode(witnessVersion).toString(16).padStart(2, "0")}${witnessProgram.length.toString(16).padStart(2, "0")}${programHex}`;
            result.derived.canonical_address = value.toLowerCase();
            addSearchValue(result, "canonical_address", result.derived.canonical_address, "text");
            addSearchValue(result, "witness_program", programHex, "hex");
            addSearchValue(result, "script_pubkey", result.derived.script_pubkey_hex, "hex");

            addBitcoinCandidates(
                result,
                networks,
                addressType,
                parsed.checksumValid && profileValid ? (networks.length === 1 ? "high" : "medium") : "low",
                `hrp_${hrp}`
            );
        }

        if (!result.candidates.length) {
            addBitcoinCandidates(result, networks, null, "low", `hrp_${hrp}`);
        }

        if (networks.length > 1) {
            result.warnings.push(diagnostic(
                "ambiguous_bitcoin_network",
                "The tb human-readable prefix is shared by Bitcoin testnet and signet."
            ));
        }

        result.valid = parsed.checksumValid && profileValid && Boolean(witnessProgram);
        if (result.valid) result.category = "cryptocurrency_address";
    } else {
        try {
            const payload = Uint8Array.from(fromWords(dataWords));
            result.decoded.payload_hex = toHexFast(payload);
            addSearchValue(result, "decoded_payload", result.decoded.payload_hex, "hex");
        } catch (error) {
            result.warnings.push(diagnostic(
                "non_byte_aligned_data",
                "Generic Bech32 data words are valid but do not form a canonically padded byte sequence."
            ));
        }

        result.valid = parsed.checksumValid;
        if (result.valid) {
            result.derived.canonical_value = value.toLowerCase();
            addSearchValue(result, "canonical_value", result.derived.canonical_value, "text");
        }
        result.warnings.push(diagnostic(
            "generic_encoding_only",
            "A valid Bech32 checksum and human-readable prefix do not by themselves identify a cryptocurrency."
        ));
    }

    return {result: finaliseResult(result), known: knownBitcoinHrp, generic: !knownBitcoinHrp};
}


/**
 * Decode one fixed-width CryptoNote Base58 block.
 *
 * @param {string} block
 * @param {number} decodedSize
 * @returns {Uint8Array}
 */
function decodeCryptoNoteBlock(block, decodedSize) {
    const littleEndian = [];

    for (let charIndex = 0; charIndex < block.length; charIndex++) {
        let carry = BITCOIN_BASE58_ALPHABET.indexOf(block[charIndex]);
        if (carry < 0) throw new Error(`Invalid Base58 character at position ${charIndex}.`);

        for (let byteIndex = 0; byteIndex < littleEndian.length; byteIndex++) {
            carry += littleEndian[byteIndex] * 58;
            littleEndian[byteIndex] = carry & 0xff;
            carry >>>= 8;
        }

        while (carry > 0) {
            littleEndian.push(carry & 0xff);
            carry >>>= 8;
        }
    }

    if (littleEndian.length > decodedSize) {
        throw new Error("CryptoNote Base58 block overflows its decoded size.");
    }

    const output = new Uint8Array(decodedSize);
    for (let i = 0; i < littleEndian.length; i++) {
        output[decodedSize - 1 - i] = littleEndian[i];
    }
    return output;
}


/**
 * Encode one CryptoNote Base58 block using its required fixed width.
 *
 * @param {Uint8Array} block
 * @returns {string}
 */
function encodeCryptoNoteBlock(block) {
    const working = Array.from(block);
    const encodedSize = MONERO_ENCODED_BLOCK_SIZES[block.length];
    const encoded = [];
    let firstNonZero = 0;

    while (firstNonZero < working.length) {
        let remainder = 0;
        for (let i = firstNonZero; i < working.length; i++) {
            const value = remainder * 256 + working[i];
            working[i] = Math.floor(value / 58);
            remainder = value % 58;
        }
        encoded.push(BITCOIN_BASE58_ALPHABET[remainder]);
        while (firstNonZero < working.length && working[firstNonZero] === 0) firstNonZero++;
    }

    return encoded.reverse().join("").padStart(encodedSize, BITCOIN_BASE58_ALPHABET[0]);
}


/**
 * Encode bytes with CryptoNote block-based Base58.
 *
 * @param {number[]|Uint8Array} input
 * @returns {string}
 */
export function encodeCryptoNoteBase58(input) {
    const bytes = Uint8Array.from(input);
    let output = "";

    for (let offset = 0; offset < bytes.length; offset += MONERO_FULL_BLOCK_SIZE) {
        output += encodeCryptoNoteBlock(bytes.slice(offset, offset + MONERO_FULL_BLOCK_SIZE));
    }
    return output;
}


/**
 * Decode CryptoNote block-based Base58.
 *
 * @param {string} value
 * @returns {Uint8Array}
 */
export function decodeCryptoNoteBase58(value) {
    if (!value.length) return new Uint8Array();
    if (!new RegExp(`^[${BITCOIN_BASE58_ALPHABET}]+$`).test(value)) {
        throw new Error("CryptoNote Base58 contains an invalid character.");
    }

    const fullBlocks = Math.floor(value.length / MONERO_ENCODED_BLOCK_SIZE);
    const finalEncodedSize = value.length % MONERO_ENCODED_BLOCK_SIZE;
    const finalDecodedSize = finalEncodedSize === 0 ? 0 : MONERO_DECODED_BLOCK_SIZES.get(finalEncodedSize);
    if (finalEncodedSize && !finalDecodedSize) {
        throw new Error(`Invalid CryptoNote Base58 final block length: ${finalEncodedSize}.`);
    }

    const output = new Uint8Array(fullBlocks * MONERO_FULL_BLOCK_SIZE + finalDecodedSize);
    for (let i = 0; i < fullBlocks; i++) {
        const encodedOffset = i * MONERO_ENCODED_BLOCK_SIZE;
        output.set(
            decodeCryptoNoteBlock(
                value.slice(encodedOffset, encodedOffset + MONERO_ENCODED_BLOCK_SIZE),
                MONERO_FULL_BLOCK_SIZE
            ),
            i * MONERO_FULL_BLOCK_SIZE
        );
    }

    if (finalEncodedSize) {
        output.set(
            decodeCryptoNoteBlock(value.slice(fullBlocks * MONERO_ENCODED_BLOCK_SIZE), finalDecodedSize),
            fullBlocks * MONERO_FULL_BLOCK_SIZE
        );
    }

    return output;
}


/**
 * Inspect a possible Monero address.
 *
 * @param {string} value
 * @param {number} offset
 * @param {boolean} allowDamaged
 * @returns {Object|null}
 */
function inspectMonero(value, offset, allowDamaged=false) {
    const plausibleLength = value.length === 95 || value.length === 106 ||
        (allowDamaged && value.length >= 80 && value.length <= 106);
    if (!plausibleLength || !new RegExp(`^[${BITCOIN_BASE58_ALPHABET}]+$`).test(value)) return null;

    const result = createResult(value, offset);
    result.format = "monero_address";
    result.encoding = "cryptonote_base58";
    result.category = "probable_cryptocurrency_address";
    result.checksum.algorithm = "keccak_256";

    let decoded;
    try {
        decoded = decodeCryptoNoteBase58(value);
    } catch (error) {
        result.errors.push(diagnostic("invalid_cryptonote_base58", error.message));
        return {result: finaliseResult(result), known: false, generic: false};
    }

    result.decoded.bytes_hex = toHexFast(decoded);
    addSearchValue(result, "encoded_address", value, "text");
    addSearchValue(result, "decoded_bytes", result.decoded.bytes_hex, "hex");

    const prefix = decoded.length ? decoded[0] : null;
    const profile = prefix === null ? null : MONERO_PREFIXES.get(prefix);
    const expectedLength = profile && profile.addressType === "integrated" ? 77 : 69;

    if (prefix !== null) {
        result.decoded.network_byte = prefix.toString(16).padStart(2, "0");
        result.decoded.network_byte_decimal = prefix;
    }

    if (!profile) {
        result.errors.push(diagnostic(
            "unknown_monero_network_byte",
            prefix === null ? "Monero address has no network byte." : `Unknown Monero network byte: ${prefix}.`
        ));
    } else {
        result.candidates.push({
            currency_family: null,
            currency: "Monero",
            network: profile.network,
            address_type: profile.addressType,
            confidence: "high",
            basis: [`network_byte_${prefix}`],
        });
    }

    if (profile && decoded.length !== expectedLength) {
        result.errors.push(diagnostic(
            "invalid_monero_payload_length",
            `${profile.addressType} Monero addresses decode to ${expectedLength} bytes; got ${decoded.length}.`
        ));
    } else if (!profile && decoded.length !== 69 && decoded.length !== 77) {
        result.errors.push(diagnostic(
            "invalid_monero_payload_length",
            `Monero addresses decode to 69 or 77 bytes; got ${decoded.length}.`
        ));
    }

    if (decoded.length >= 5) {
        const body = decoded.slice(0, -4);
        const encodedChecksum = decoded.slice(-4);
        const computedChecksum = keccak256(body).slice(0, 4);
        result.checksum.present = true;
        result.checksum.valid = bytesEqual(encodedChecksum, computedChecksum);
        result.checksum.encoded = toHexFast(encodedChecksum);
        result.checksum.computed = toHexFast(computedChecksum);
        result.decoded.checksum_stripped_hex = toHexFast(body);
        addSearchValue(result, "checksum_stripped_body", result.decoded.checksum_stripped_hex, "hex");
        if (!result.checksum.valid) {
            result.errors.push(diagnostic("checksum_mismatch", "Monero address checksum mismatch."));
        }
    }

    if (decoded.length >= 65) {
        result.decoded.public_spend_key = toHexFast(decoded.slice(1, 33));
        result.decoded.public_view_key = toHexFast(decoded.slice(33, 65));
        addSearchValue(result, "public_spend_key", result.decoded.public_spend_key, "hex");
        addSearchValue(result, "public_view_key", result.decoded.public_view_key, "hex");
    }
    if (profile && profile.addressType === "integrated" && decoded.length >= 73) {
        result.decoded.payment_id = toHexFast(decoded.slice(65, 73));
        addSearchValue(result, "payment_id", result.decoded.payment_id, "hex");
    }

    result.warnings.push(diagnostic(
        "monero_public_key_points_unchecked",
        "The encoded public-key bytes are exposed, but Ed25519 point validity is not checked."
    ));

    const canonicalAddress = encodeCryptoNoteBase58(decoded);
    if (canonicalAddress !== value) {
        result.errors.push(diagnostic(
            "noncanonical_cryptonote_base58",
            "CryptoNote Base58 value is not canonically encoded."
        ));
    }

    result.valid = Boolean(profile) && decoded.length === expectedLength &&
        result.checksum.valid === true && canonicalAddress === value;
    if (!result.valid) {
        result.candidates.forEach(candidate => {
            candidate.confidence = "low";
        });
    }
    if (result.valid) {
        result.category = "cryptocurrency_address";
        result.derived.canonical_address = canonicalAddress;
    }

    return {result: finaliseResult(result), known: Boolean(profile), generic: false};
}


/**
 * Rank parser results so exact inspection selects the most specific interpretation.
 *
 * @param {Object} inspected
 * @returns {number}
 */
function inspectionScore(inspected) {
    if (inspected.result.valid && inspected.known) return 100;
    if (inspected.result.valid && inspected.generic) return 80;
    if (inspected.known) return 60;
    return 40;
}


/**
 * Inspect one candidate.
 *
 * @param {string} value
 * @param {number} offset
 * @param {Object} options
 * @returns {Object}
 */
function inspectCandidate(value, offset, options) {
    const attempts = [];
    const hasEvmPrefix = /^0x/i.test(value);
    const bareEvm = /^[0-9a-fA-F]{40}$/.test(value);
    const looksBech32 = value.lastIndexOf("1") > 0;
    const allowDamaged = options.detection === "loose";

    if (hasEvmPrefix || bareEvm) {
        const inspected = inspectEvm(value, offset, options.mode === "scan" && !hasEvmPrefix);
        if (inspected) attempts.push(inspected);
    }
    if (looksBech32) {
        const inspected = inspectBech32(value, offset);
        if (inspected) attempts.push(inspected);
    }
    if (new RegExp(`^[${BITCOIN_BASE58_ALPHABET}]+$`).test(value)) {
        const monero = inspectMonero(value, offset, allowDamaged);
        if (monero) attempts.push(monero);
        const base58Check = inspectBase58Check(value, offset, allowDamaged);
        if (base58Check) attempts.push(base58Check);
    }

    if (!attempts.length) {
        const result = createResult(value, offset);
        result.errors.push(diagnostic(
            "unrecognized_identifier",
            "Input does not match a supported cryptocurrency address or checksummed generic encoding."
        ));
        return {result, known: false, generic: false};
    }

    attempts.sort((left, right) => inspectionScore(right) - inspectionScore(left));
    return attempts[0];
}


/**
 * Add regex matches to a range map.
 *
 * @param {Map} ranges
 * @param {string} source
 * @param {RegExp} regex
 * @param {string} hint
 * @param {number} priority
 * @param {Object} state
 */
function collectMatches(ranges, source, regex, hint, priority, state) {
    let match;
    while ((match = regex.exec(source)) !== null) {
        state.attempts++;
        if (state.attempts > MAX_CANDIDATE_ATTEMPTS) {
            state.truncated = true;
            return;
        }

        const leadingBoundary = match[1] || "";
        const value = match[2];
        if ((hint === "bitcoin_bech32" || hint === "generic_bech32") && value.length > 90) {
            continue;
        }
        const offset = match.index + leadingBoundary.length;
        const key = `${offset}:${value.length}`;
        const previous = ranges.get(key);
        if (!previous || previous.priority < priority) {
            ranges.set(key, {value, offset, hint, priority});
        }
    }
}


/**
 * Scan raw bytes for bounded ASCII candidates.
 *
 * @param {Uint8Array} bytes
 * @param {string} detection
 * @returns {{candidates: Object[], truncated: boolean}}
 */
function collectScanCandidates(bytes, detection) {
    const source = Utils.byteArrayToChars(bytes);
    const ranges = new Map();
    const state = {attempts: 0, truncated: false};
    const boundary = "[^0-9A-Za-z]";

    collectMatches(
        ranges,
        source,
        new RegExp(`(^|${boundary})(0[xX][0-9a-fA-F]{${detection === "strict" ? "40" : "1,40"}})(?=$|${boundary})`, "g"),
        "evm",
        5,
        state
    );

    if (detection === "loose" && !state.truncated) {
        collectMatches(
            ranges,
            source,
            new RegExp(`(^|${boundary})([0-9a-fA-F]{40})(?=$|${boundary})`, "g"),
            "evm_bare",
            4,
            state
        );
    }

    if (!state.truncated) {
        collectMatches(
            ranges,
            source,
            new RegExp(`(^|${boundary})((?:bcrt|bc|tb)1[0-9A-Za-z]{1,87})(?=$|${boundary})`, "gi"),
            "bitcoin_bech32",
            4,
            state
        );
    }

    if (!state.truncated) {
        collectMatches(
            ranges,
            source,
            new RegExp(`(^|[^0-9A-Za-z_.-])([0-9A-Za-z_.-]{1,83}1[${BECH32_CHARSET}]{6,87})(?=$|[^0-9A-Za-z_-])`, "gi"),
            "generic_bech32",
            2,
            state
        );
    }

    if (!state.truncated) {
        collectMatches(
            ranges,
            source,
            new RegExp(`(^|[^0-9A-Za-z])([${BITCOIN_BASE58_ALPHABET}]{6,128})(?=$|[^0-9A-Za-z])`, "g"),
            "base58",
            1,
            state
        );
    }

    const candidates = [...ranges.values()];
    candidates.sort((left, right) => left.offset - right.offset || right.priority - left.priority);
    return {candidates, truncated: state.truncated};
}


/**
 * Convert supported input types to a Uint8Array view.
 *
 * @param {ArrayBuffer|Uint8Array} input
 * @returns {Uint8Array}
 */
function inputBytes(input) {
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    throw new TypeError("Cryptocurrency inspection input must be an ArrayBuffer or typed array.");
}


/**
 * Test for ASCII whitespace.
 *
 * @param {number} byte
 * @returns {boolean}
 */
function isAsciiWhitespace(byte) {
    return byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);
}


/**
 * Inspect or scan input data for cryptocurrency identifiers.
 *
 * @param {ArrayBuffer|Uint8Array} input
 * @param {Object} [options]
 * @param {string} [options.mode="inspect"]
 * @param {string} [options.detection="strict"]
 * @param {number} [options.maxResults=1000]
 * @returns {Object}
 */
export function inspectCryptocurrencyData(input, options={}) {
    const bytes = inputBytes(input);
    const mode = options.mode === "scan" ? "scan" : "inspect";
    const detection = options.detection === "loose" ? "loose" : "strict";
    const maxResults = Math.max(1, Math.min(10000, Math.trunc(options.maxResults || 1000)));
    const envelope = {
        schema_version: 1,
        mode,
        source: {
            byte_length: bytes.length,
            offset_unit: "byte",
            scan_encoding: "ASCII",
        },
        result_limit: mode === "scan" ? maxResults : null,
        results: [],
        truncated: false,
        warnings: [],
        errors: [],
    };

    if (mode === "inspect") {
        let start = 0;
        let end = bytes.length;
        while (start < end && isAsciiWhitespace(bytes[start])) start++;
        while (end > start && isAsciiWhitespace(bytes[end - 1])) end--;

        if (start === end) {
            envelope.errors.push(diagnostic("empty_input", "No identifier was provided."));
            return envelope;
        }
        if (end - start > MAX_IDENTIFIER_LENGTH) {
            envelope.errors.push(diagnostic(
                "identifier_too_long",
                `Identifiers are limited to ${MAX_IDENTIFIER_LENGTH} bytes; got ${end - start}.`
            ));
            return envelope;
        }

        const value = Utils.byteArrayToChars(bytes.slice(start, end));
        envelope.results.push(inspectCandidate(value, start, {mode, detection}).result);
        return envelope;
    }

    const collected = collectScanCandidates(bytes, detection);
    envelope.truncated = collected.truncated;
    if (collected.truncated) {
        envelope.warnings.push(diagnostic(
            "candidate_attempt_limit_reached",
            `Candidate analysis stopped after ${MAX_CANDIDATE_ATTEMPTS} attempts.`
        ));
    }

    for (let i = 0; i < collected.candidates.length; i++) {
        const candidate = collected.candidates[i];
        const inspected = inspectCandidate(candidate.value, candidate.offset, {mode, detection});
        const looseScanCandidate = inspected.looseScan === undefined ? inspected.known : inspected.looseScan;
        const include = inspected.result.valid || (detection === "loose" && looseScanCandidate);
        if (!include) continue;

        if (envelope.results.length >= maxResults) {
            envelope.truncated = true;
            envelope.warnings.push(diagnostic(
                "result_limit_reached",
                `Scanning stopped after ${maxResults} results.`
            ));
            break;
        }
        envelope.results.push(inspected.result);
    }

    return envelope;
}
