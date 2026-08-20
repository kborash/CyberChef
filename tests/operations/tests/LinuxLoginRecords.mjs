/**
 * Tests for the Linux login/session record parsers.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {string} value
 */
function writeString(bytes, offset, value) {
    for (let i = 0; i < value.length; i++)
        bytes[offset + i] = value.charCodeAt(i);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {boolean} littleEndian
 * @returns {Uint8Array}
 */
function makeUtmpRecord(littleEndian) {
    const bytes = new Uint8Array(384);
    const view = new DataView(bytes.buffer);

    view.setInt16(0, 7, littleEndian);
    view.setInt32(4, 4242, littleEndian);
    writeString(bytes, 8, "pts/3");
    writeString(bytes, 40, "ts/3");
    writeString(bytes, 44, "analyst");
    writeString(bytes, 76, "example.test");
    view.setInt16(332, 15, littleEndian);
    view.setInt16(334, 2, littleEndian);
    view.setInt32(336, 99, littleEndian);
    view.setInt32(340, 1700000000, littleEndian);
    view.setInt32(344, 123456, littleEndian);
    bytes.set([192, 0, 2, 5], 348);
    bytes[364] = 0xaa;
    return bytes;
}

const EXPECTED_UTMP = [{
    index: 0,
    type: "USER_PROCESS",
    typeCode: 7,
    pid: 4242,
    line: "pts/3",
    id: "ts/3",
    user: "analyst",
    host: "example.test",
    exit: {
        termination: 15,
        status: 2,
    },
    session: 99,
    timestamp: "2023-11-14T22:13:20.123Z",
    timestampSeconds: 1700000000,
    microseconds: 123456,
    address: "192.0.2.5",
    addressBytes: "c0000205000000000000000000000000",
    reserved: "aa00000000000000000000000000000000000000",
}];

const tests = [
    ["Parse UTMP", true, "Little"],
    ["Parse WTMP", false, "Big"],
    ["Parse BTMP", true, "Little"],
].map(([op, littleEndian, endianness]) => ({
    name: `${op}: parses a Linux utmp record`,
    input: toHex(makeUtmpRecord(littleEndian)),
    expectedOutput: JSON.stringify(EXPECTED_UTMP, null, 4),
    recipeConfig: [
        {
            op: "From Hex",
            args: ["None"],
        },
        {
            op,
            args: [endianness, false],
        },
    ],
}));

const sparseUtmp = new Uint8Array(768);
sparseUtmp.set(makeUtmpRecord(true), 384);
const sparseExpected = JSON.parse(JSON.stringify(EXPECTED_UTMP));
sparseExpected[0].index = 1;

tests.push(
    {
        name: "Parse UTMP: omits zero-filled slots while retaining the record index",
        input: toHex(sparseUtmp),
        expectedOutput: JSON.stringify(sparseExpected, null, 4),
        recipeConfig: [
            {
                op: "From Hex",
                args: ["None"],
            },
            {
                op: "Parse UTMP",
                args: ["Little", false],
            },
        ],
    },
    {
        name: "Parse WTMP: rejects a partial record",
        input: "000000",
        expectedOutput: "Invalid Linux login record file: size must be a multiple of 384 bytes.",
        expectedError: true,
        recipeConfig: [
            {
                op: "From Hex",
                args: ["None"],
            },
            {
                op: "Parse WTMP",
                args: ["Little", false],
            },
        ],
    },
);

const csvUtmp = makeUtmpRecord(true);
csvUtmp.fill(0, 44, 76);
csvUtmp.fill(0, 76, 332);
writeString(csvUtmp, 44, 'analyst, "blue"');
writeString(csvUtmp, 76, "first line\nsecond line");

tests.push({
    name: "Parse UTMP: exports CSV and escapes special characters",
    input: toHex(csvUtmp),
    expectedOutput: [
        "index,type,typeCode,pid,line,id,user,host,exitTermination,exitStatus,session,timestamp,timestampSeconds,microseconds,address,addressBytes,reserved",
        '0,USER_PROCESS,7,4242,pts/3,ts/3,"analyst, ""blue""","first line\nsecond line",15,2,99,2023-11-14T22:13:20.123Z,1700000000,123456,192.0.2.5,c0000205000000000000000000000000,aa00000000000000000000000000000000000000',
        "",
    ].join("\r\n"),
    recipeConfig: [
        {
            op: "From Hex",
            args: ["None"],
        },
        {
            op: "Parse UTMP",
            args: ["Little", false, "CSV"],
        },
    ],
});

const lastlog32 = new Uint8Array(584);
const lastlog32View = new DataView(lastlog32.buffer);
lastlog32View.setInt32(292, 1700000000, true);
writeString(lastlog32, 296, "pts/8");
writeString(lastlog32, 328, "198.51.100.8");

tests.push({
    name: "Parse lastlog: parses sparse 32-bit timestamp records",
    input: toHex(lastlog32),
    expectedOutput: JSON.stringify([{
        uid: 1,
        timestamp: "2023-11-14T22:13:20.000Z",
        timestampSeconds: 1700000000,
        line: "pts/8",
        host: "198.51.100.8",
    }], null, 4),
    recipeConfig: [
        {
            op: "From Hex",
            args: ["None"],
        },
        {
            op: "Parse lastlog",
            args: ["32-bit", "Little", false],
        },
    ],
});

tests.push({
    name: "Parse lastlog: exports CSV",
    input: toHex(lastlog32),
    expectedOutput: [
        "uid,timestamp,timestampSeconds,line,host",
        "1,2023-11-14T22:13:20.000Z,1700000000,pts/8,198.51.100.8",
        "",
    ].join("\r\n"),
    recipeConfig: [
        {
            op: "From Hex",
            args: ["None"],
        },
        {
            op: "Parse lastlog",
            args: ["32-bit", "Little", false, "CSV"],
        },
    ],
});

const lastlog64 = new Uint8Array(296);
const lastlog64View = new DataView(lastlog64.buffer);
lastlog64View.setInt32(0, 0, false);
lastlog64View.setUint32(4, 1700000000, false);
writeString(lastlog64, 8, "tty1");
writeString(lastlog64, 40, "console");

tests.push(
    {
        name: "Parse lastlog: parses big-endian 64-bit timestamp records",
        input: toHex(lastlog64),
        expectedOutput: JSON.stringify([{
            uid: 0,
            timestamp: "2023-11-14T22:13:20.000Z",
            timestampSeconds: 1700000000,
            line: "tty1",
            host: "console",
        }], null, 4),
        recipeConfig: [
            {
                op: "From Hex",
                args: ["None"],
            },
            {
                op: "Parse lastlog",
                args: ["64-bit", "Big", false],
            },
        ],
    },
    {
        name: "Parse lastlog: rejects a file that does not match the selected layout",
        input: "00000000",
        expectedOutput: "Invalid lastlog file: size must be a multiple of 292 bytes for the selected layout.",
        expectedError: true,
        recipeConfig: [
            {
                op: "From Hex",
                args: ["None"],
            },
            {
                op: "Parse lastlog",
                args: ["32-bit", "Little", false],
            },
        ],
    },
);

TestRegister.addTests(tests);
