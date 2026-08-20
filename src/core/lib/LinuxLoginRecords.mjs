/**
 * Parsers for the traditional Linux utmp and lastlog binary formats.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";

const UTMP_RECORD_SIZE = 384;
const LASTLOG_32_RECORD_SIZE = 292;
const LASTLOG_64_RECORD_SIZE = 296;

const UTMP_TYPES = [
    "EMPTY",
    "RUN_LVL",
    "BOOT_TIME",
    "NEW_TIME",
    "OLD_TIME",
    "INIT_PROCESS",
    "LOGIN_PROCESS",
    "USER_PROCESS",
    "DEAD_PROCESS",
    "ACCOUNTING",
];

const UTMP_CSV_FIELDS = [
    ["index", record => record.index],
    ["type", record => record.type],
    ["typeCode", record => record.typeCode],
    ["pid", record => record.pid],
    ["line", record => record.line],
    ["id", record => record.id],
    ["user", record => record.user],
    ["host", record => record.host],
    ["exitTermination", record => record.exit.termination],
    ["exitStatus", record => record.exit.status],
    ["session", record => record.session],
    ["timestamp", record => record.timestamp],
    ["timestampSeconds", record => record.timestampSeconds],
    ["microseconds", record => record.microseconds],
    ["address", record => record.address],
    ["addressBytes", record => record.addressBytes],
    ["reserved", record => record.reserved],
];

const LASTLOG_CSV_FIELDS = [
    ["uid", record => record.uid],
    ["timestamp", record => record.timestamp],
    ["timestampSeconds", record => record.timestampSeconds],
    ["line", record => record.line],
    ["host", record => record.host],
];

/**
 * Reads a fixed-width, null-terminated UTF-8 string.
 *
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {number} length
 * @returns {string}
 */
function readString(bytes, offset, length) {
    const field = bytes.subarray(offset, offset + length);
    const terminator = field.indexOf(0);
    return new TextDecoder("utf-8").decode(terminator < 0 ? field : field.subarray(0, terminator));
}

/**
 * Converts bytes to a compact hexadecimal string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Reads a signed 64-bit value without requiring BigInt support.
 *
 * @param {DataView} view
 * @param {number} offset
 * @param {boolean} littleEndian
 * @returns {number}
 */
function readInt64(view, offset, littleEndian) {
    const high = view.getInt32(offset + (littleEndian ? 4 : 0), littleEndian);
    const low = view.getUint32(offset + (littleEndian ? 0 : 4), littleEndian);
    return high * 0x100000000 + low;
}

/**
 * Returns an ISO 8601 representation where the timestamp is in range.
 *
 * @param {number} seconds
 * @param {number} [microseconds=0]
 * @returns {string|null}
 */
function formatTimestamp(seconds, microseconds=0) {
    const milliseconds = seconds * 1000 + Math.trunc(microseconds / 1000);
    if (!Number.isSafeInteger(seconds) || milliseconds < -8640000000000000 || milliseconds > 8640000000000000)
        return null;

    return new Date(milliseconds).toISOString();
}

/**
 * Formats the address stored in ut_addr_v6.
 *
 * @param {Uint8Array} bytes
 * @returns {string|null}
 */
function formatAddress(bytes) {
    if (bytes.every(byte => byte === 0)) return null;

    if (bytes.subarray(4).every(byte => byte === 0))
        return Array.from(bytes.subarray(0, 4)).join(".");

    const groups = [];
    for (let i = 0; i < 16; i += 2)
        groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));

    let bestStart = -1;
    let bestLength = 0;
    for (let start = 0; start < groups.length;) {
        if (groups[start] !== "0") {
            start++;
            continue;
        }

        let end = start;
        while (end < groups.length && groups[end] === "0") end++;
        if (end - start > bestLength) {
            bestStart = start;
            bestLength = end - start;
        }
        start = end;
    }

    if (bestLength < 2) return groups.join(":");

    groups.splice(bestStart, bestLength, "");
    if (bestStart === 0) groups.unshift("");
    if (bestStart === groups.length - 1) groups.push("");
    return groups.join(":");
}

/**
 * Tests whether a record is entirely zero-filled.
 *
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
function isZeroFilled(bytes) {
    return bytes.every(byte => byte === 0);
}

/**
 * Escapes a value for an RFC 4180-style CSV field.
 *
 * @param {*} value
 * @returns {string}
 */
function escapeCSVField(value) {
    if (value === null || value === undefined) return "";

    const stringValue = value.toString();
    const escapedValue = stringValue.replace(/"/g, '""');
    return /[",\r\n]/.test(stringValue) ? `"${escapedValue}"` : escapedValue;
}

/**
 * Formats parsed records as JSON or CSV.
 *
 * @param {Object[]} records
 * @param {string} outputFormat
 * @param {Array[]} csvFields
 * @returns {string}
 */
function formatRecords(records, outputFormat, csvFields) {
    if (outputFormat !== "CSV") return JSON.stringify(records, null, 4);

    const rows = [csvFields.map(field => field[0])];
    records.forEach(record => {
        rows.push(csvFields.map(field => field[1](record)));
    });

    return rows
        .map(row => row.map(escapeCSVField).join(","))
        .join("\r\n") + "\r\n";
}

/**
 * Formats parsed utmp-family records.
 *
 * @param {Object[]} records
 * @param {string} outputFormat
 * @returns {string}
 */
function formatUtmp(records, outputFormat) {
    return formatRecords(records, outputFormat, UTMP_CSV_FIELDS);
}

/**
 * Formats parsed lastlog records.
 *
 * @param {Object[]} records
 * @param {string} outputFormat
 * @returns {string}
 */
function formatLastlog(records, outputFormat) {
    return formatRecords(records, outputFormat, LASTLOG_CSV_FIELDS);
}

/**
 * Parses records shared by Linux utmp, wtmp, and btmp files.
 *
 * @param {ArrayBuffer} input
 * @param {string} endianness
 * @param {boolean} includeEmpty
 * @returns {Object[]}
 */
function parseUtmp(input, endianness, includeEmpty) {
    if (input.byteLength % UTMP_RECORD_SIZE !== 0)
        throw new OperationError(`Invalid Linux login record file: size must be a multiple of ${UTMP_RECORD_SIZE} bytes.`);

    const bytes = new Uint8Array(input);
    const view = new DataView(input);
    const littleEndian = endianness === "Little";
    const records = [];

    for (let offset = 0, index = 0; offset < bytes.length; offset += UTMP_RECORD_SIZE, index++) {
        const rawRecord = bytes.subarray(offset, offset + UTMP_RECORD_SIZE);
        if (!includeEmpty && isZeroFilled(rawRecord)) continue;

        const typeCode = view.getInt16(offset, littleEndian);
        const seconds = view.getInt32(offset + 340, littleEndian);
        const microseconds = view.getInt32(offset + 344, littleEndian);
        const addressBytes = bytes.subarray(offset + 348, offset + 364);

        records.push({
            index,
            type: UTMP_TYPES[typeCode] || "UNKNOWN",
            typeCode,
            pid: view.getInt32(offset + 4, littleEndian),
            line: readString(bytes, offset + 8, 32),
            id: readString(bytes, offset + 40, 4),
            user: readString(bytes, offset + 44, 32),
            host: readString(bytes, offset + 76, 256),
            exit: {
                termination: view.getInt16(offset + 332, littleEndian),
                status: view.getInt16(offset + 334, littleEndian),
            },
            session: view.getInt32(offset + 336, littleEndian),
            timestamp: formatTimestamp(seconds, microseconds),
            timestampSeconds: seconds,
            microseconds,
            address: formatAddress(addressBytes),
            addressBytes: toHex(addressBytes),
            reserved: toHex(bytes.subarray(offset + 364, offset + 384)),
        });
    }

    return records;
}

/**
 * Parses a traditional sparse Linux lastlog file.
 *
 * @param {ArrayBuffer} input
 * @param {string} timestampSize
 * @param {string} endianness
 * @param {boolean} includeEmpty
 * @returns {Object[]}
 */
function parseLastlog(input, timestampSize, endianness, includeEmpty) {
    const is64Bit = timestampSize === "64-bit";
    const recordSize = is64Bit ? LASTLOG_64_RECORD_SIZE : LASTLOG_32_RECORD_SIZE;
    if (input.byteLength % recordSize !== 0)
        throw new OperationError(`Invalid lastlog file: size must be a multiple of ${recordSize} bytes for the selected layout.`);

    const bytes = new Uint8Array(input);
    const view = new DataView(input);
    const littleEndian = endianness === "Little";
    const stringOffset = is64Bit ? 8 : 4;
    const records = [];

    for (let offset = 0, uid = 0; offset < bytes.length; offset += recordSize, uid++) {
        const rawRecord = bytes.subarray(offset, offset + recordSize);
        if (!includeEmpty && isZeroFilled(rawRecord)) continue;

        const seconds = is64Bit ?
            readInt64(view, offset, littleEndian) :
            view.getInt32(offset, littleEndian);

        records.push({
            uid,
            timestamp: formatTimestamp(seconds),
            timestampSeconds: Number.isSafeInteger(seconds) ? seconds : seconds.toString(),
            line: readString(bytes, offset + stringOffset, 32),
            host: readString(bytes, offset + stringOffset + 32, 256),
        });
    }

    return records;
}

export {
    formatLastlog,
    formatUtmp,
    parseLastlog,
    parseUtmp,
};
