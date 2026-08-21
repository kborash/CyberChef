/**
 * Base58 resources.
 *
 * @author tlwr [toby@toby.codes]
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2017
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";

/**
 * Base58 alphabet options.
 */
export const ALPHABET_OPTIONS = [
    {
        name: "Bitcoin",
        value: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    },
    {
        name: "Ripple",
        value: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
    },
];

/**
 * Validate a Base58 alphabet.
 *
 * @param {string} alphabet
 * @param {string} errorMessage
 */
function validateAlphabet(alphabet, errorMessage) {
    if (alphabet.length !== 58 || new Set(alphabet.split("")).size !== 58) {
        throw new OperationError(errorMessage);
    }
}

/**
 * Encode data using Base58.
 *
 * @param {byteArray|Uint8Array|ArrayBuffer} input
 * @param {string} [alphabet]
 * @returns {string}
 */
export function encode(input, alphabet=ALPHABET_OPTIONS[0].value) {
    validateAlphabet(alphabet, "Error: alphabet must be of length 58");

    if (input instanceof ArrayBuffer) input = new Uint8Array(input);
    if (input.length === 0) return "";

    const result = [];
    let zeroPrefix = 0;
    for (let i = 0; i < input.length && input[i] === 0; i++) {
        zeroPrefix++;
    }

    input.forEach(function(b) {
        let carry = b;

        for (let i = 0; i < result.length; i++) {
            carry += result[i] << 8;
            result[i] = carry % 58;
            carry = (carry / 58) | 0;
        }

        while (carry > 0) {
            result.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    });

    let output = result.map(function(b) {
        return alphabet[b];
    }).reverse().join("");

    while (zeroPrefix--) {
        output = alphabet[0] + output;
    }

    return output;
}

/**
 * Decode Base58 data.
 *
 * @param {string} input
 * @param {string} [alphabet]
 * @param {boolean} [removeNonAlphaChars=true]
 * @returns {byteArray}
 */
export function decode(input, alphabet=ALPHABET_OPTIONS[0].value, removeNonAlphaChars=true) {
    validateAlphabet(alphabet, "Alphabet must be of length 58");

    if (input.length === 0) return [];

    const result = [];
    let zeroPrefix = 0;
    for (let i = 0; i < input.length && input[i] === alphabet[0]; i++) {
        zeroPrefix++;
    }

    [].forEach.call(input, function(c, charIndex) {
        const index = alphabet.indexOf(c);

        if (index === -1) {
            if (removeNonAlphaChars) {
                return;
            }
            throw new OperationError(`Char '${c}' at position ${charIndex} not in alphabet`);
        }

        let carry = index;

        for (let i = 0; i < result.length; i++) {
            carry += result[i] * 58;
            result[i] = carry & 0xFF;
            carry = carry >> 8;
        }

        while (carry > 0) {
            result.push(carry & 0xFF);
            carry = carry >> 8;
        }
    });

    while (zeroPrefix--) {
        result.push(0);
    }

    return result.reverse();
}
