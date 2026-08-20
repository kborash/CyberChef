/**
 * OpenSSH known_hosts conversion helpers.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";

/**
 * Decodes and validates unpadded or padded standard Base64.
 *
 * @param {string} value
 * @param {number} lineNumber
 * @param {string} fieldName
 * @returns {Uint8Array}
 */
function decodeBase64(value, lineNumber, fieldName) {
    if (!value || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 === 1 || (value.includes("=") && value.length % 4 !== 0)) {
        throw new OperationError(`Invalid hashed known_hosts entry on line ${lineNumber}: ${fieldName} is not valid Base64.`);
    }

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const clean = value.replace(/=+$/, "");
    const bytes = [];
    let accumulator = 0;
    let bits = 0;

    for (const character of clean) {
        const digit = alphabet.indexOf(character);
        accumulator = accumulator * 64 + digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((accumulator >> bits) & 0xff);
            accumulator &= (1 << bits) - 1;
        }
    }

    return new Uint8Array(bytes);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Converts OpenSSH hashed host names into Hashcat mode 160 input.
 *
 * @param {string} input
 * @returns {string}
 */
function knownHostsToHashcat(input) {
    const output = [];
    const lines = input.split(/\r?\n/);

    for (let index = 0; index < lines.length; index++) {
        const line = lines[index].trim();
        if (!line || line.startsWith("#")) continue;

        const fields = line.split(/\s+/);
        const hostIndex = fields[0].startsWith("@") ? 1 : 0;
        const host = fields[hostIndex];
        if (!host || !host.startsWith("|")) continue;

        const parts = host.split("|");
        const lineNumber = index + 1;
        if (parts.length !== 4 || parts[0] !== "" || !parts[1] || !parts[2] || !parts[3]) {
            throw new OperationError(`Invalid hashed known_hosts entry on line ${lineNumber}: expected |1|salt|digest.`);
        }
        if (parts[1] !== "1") {
            throw new OperationError(`Unsupported known_hosts hash version on line ${lineNumber}: ${parts[1]}.`);
        }

        const salt = decodeBase64(parts[2], lineNumber, "salt");
        const digest = decodeBase64(parts[3], lineNumber, "digest");
        if (!salt.length) {
            throw new OperationError(`Invalid hashed known_hosts entry on line ${lineNumber}: salt is empty.`);
        }
        if (digest.length !== 20) {
            throw new OperationError(`Invalid hashed known_hosts entry on line ${lineNumber}: HMAC-SHA1 digest must be 20 bytes.`);
        }

        output.push(`${toHex(digest)}:${toHex(salt)}`);
    }

    if (!output.length) {
        throw new OperationError("No hashed known_hosts entries were found.");
    }

    return output.join("\n");
}

export {
    knownHostsToHashcat,
};
