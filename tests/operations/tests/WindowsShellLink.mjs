/**
 * Tests for Windows Shell Link parsing.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

const CLSID_BYTES = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

/** @param {Uint8Array} bytes @returns {string} */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {number} length
 * @param {number} flags
 * @returns {{bytes: Uint8Array, view: DataView}}
 */
function makeHeader(length, flags) {
    const bytes = new Uint8Array(length);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, 0x4c, true);
    bytes.set(CLSID_BYTES, 4);
    view.setUint32(20, flags, true);
    view.setUint32(24, 0x20, true); // Archive
    view.setUint32(52, 1234, true);
    view.setUint32(60, 1, true); // SW_SHOWNORMAL
    return {bytes, view};
}

/** @returns {Uint8Array} */
function makeTrackerLink() {
    const {bytes, view} = makeHeader(182, 0x04); // HasName, ANSI
    view.setUint16(76, 4, true);
    bytes.set(new TextEncoder().encode("Test"), 78);

    const tracker = 82;
    view.setUint32(tracker, 96, true);
    view.setUint32(tracker + 4, 0xa0000003, true);
    view.setUint32(tracker + 8, 88, true);
    view.setUint32(tracker + 12, 0, true);
    bytes.set(new TextEncoder().encode("HOST-01"), tracker + 16);
    // The final four zero bytes are the ExtraData terminal block.
    return bytes;
}

/** @returns {Uint8Array} */
function makeLinkInfoLink() {
    const localPath = new TextEncoder().encode("C:\\Temp\\file.txt\0");
    const suffix = new TextEncoder().encode("file.txt\0");
    const linkInfoSize = 28 + localPath.length + suffix.length;
    const {bytes, view} = makeHeader(76 + linkInfoSize + 4, 0x02);
    const offset = 76;
    view.setUint32(offset, linkInfoSize, true);
    view.setUint32(offset + 4, 28, true);
    view.setUint32(offset + 8, 1, true);
    view.setUint32(offset + 16, 28, true);
    view.setUint32(offset + 24, 28 + localPath.length, true);
    bytes.set(localPath, offset + 28);
    bytes.set(suffix, offset + 28 + localPath.length);
    return bytes;
}

const invalidClsid = makeHeader(80, 0).bytes;
invalidClsid[4] = 0xff;
const missingTerminal = makeHeader(76, 0).bytes;

TestRegister.addTests([
    {
        name: "Parse Windows LNK: parses StringData and tracker metadata",
        input: toHex(makeTrackerLink()),
        expectedMatch: /"description": "Test"[\s\S]*"machineId": "HOST-01"/,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Windows LNK", args: ["windows-1252", "JSON"]}],
    },
    {
        name: "Parse Windows LNK: resolves local LinkInfo paths",
        input: toHex(makeLinkInfoLink()),
        expectedMatch: /"resolvedPath": "C:\\\\Temp\\\\file\.txt"/,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Windows LNK", args: ["windows-1252", "JSON"]}],
    },
    {
        name: "Parse Windows LNK: exports a forensic summary as CSV",
        input: toHex(makeTrackerLink()),
        expectedMatch: /^targetPath,localBasePath,[^\r]+\r\n[^\r]*Test[^\r]*HOST-01/,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Windows LNK", args: ["windows-1252", "CSV"]}],
    },
    {
        name: "Parse Windows LNK: rejects an invalid class identifier",
        input: toHex(invalidClsid),
        expectedMatch: /^Invalid LNK class identifier:/,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Windows LNK", args: ["windows-1252", "JSON"]}],
    },
    {
        name: "Parse Windows LNK: requires the ExtraData terminal block",
        input: toHex(missingTerminal),
        expectedOutput: "Missing or truncated LNK ExtraData terminal block.",
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Windows LNK", args: ["windows-1252", "JSON"]}],
    },
]);
