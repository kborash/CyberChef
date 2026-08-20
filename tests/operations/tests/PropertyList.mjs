/**
 * Tests for Apple property list parsing.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

/** @param {Uint8Array} bytes @returns {string} */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** @param {string} value @returns {string} */
function stringToHex(value) {
    return toHex(new TextEncoder().encode(value));
}

/** @returns {Uint8Array} */
function makeBinaryPlist() {
    const bytes = new Uint8Array(66);
    bytes.set(new TextEncoder().encode("bplist00"));
    bytes.set([0x54, 0x6e, 0x61, 0x6d, 0x65], 8); // "name"
    bytes.set([0x54, 0x74, 0x65, 0x73, 0x74], 13); // "test"
    bytes.set([0x53, 0x75, 0x69, 0x64], 18); // "uid"
    bytes.set([0x80, 0x2a], 22); // UID(42)
    bytes.set([0xd2, 0x00, 0x02, 0x01, 0x03], 24); // {0: 1, 2: 3}
    bytes.set([8, 13, 18, 22, 24], 29); // offset table

    const view = new DataView(bytes.buffer);
    bytes[40] = 1; // offset integer size
    bytes[41] = 1; // object reference size
    view.setUint32(46, 5, false); // object count, low 32 bits
    view.setUint32(54, 4, false); // top object, low 32 bits
    view.setUint32(62, 29, false); // offset table location, low 32 bits
    return bytes;
}

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Name</key><string>Forensic &amp; Test</string>
<key>Enabled</key><true/>
<key>When</key><date>2024-01-02T03:04:05Z</date>
<key>Payload</key><data>AQID</data>
</dict></plist>`;

const xmlExpected = {
    Name: "Forensic & Test",
    Enabled: true,
    When: {$plistType: "date", value: "2024-01-02T03:04:05.000Z"},
    Payload: {$plistType: "data", base64: "AQID"},
};

TestRegister.addTests([
    {
        name: "Parse Property List: parses XML and preserves typed values",
        input: stringToHex(xml),
        expectedOutput: JSON.stringify(xmlExpected, null, 4),
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["JSON"]}],
    },
    {
        name: "Parse Property List: parses binary UID values",
        input: toHex(makeBinaryPlist()),
        expectedOutput: JSON.stringify({name: "test", uid: {$plistType: "uid", value: 42}}, null, 4),
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["JSON"]}],
    },
    {
        name: "Parse Property List: parses legacy OpenStep syntax",
        input: stringToHex('{ name = "Case File"; flags = (yes, no, 7); data = <01 02 ff>; }'),
        expectedOutput: JSON.stringify({
            name: "Case File",
            flags: ["yes", "no", "7"],
            data: {$plistType: "data", base64: "AQL/"},
        }, null, 4),
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["JSON"]}],
    },
    {
        name: "Parse Property List: exports flattened CSV",
        input: stringToHex("{ name = test; values = (1, 2); }"),
        expectedOutput: [
            "path,type,value",
            "$,dictionary,2",
            "$.name,string,test",
            "$.values,array,2",
            "$.values[0],string,1",
            "$.values[1],string,2",
            "",
        ].join("\r\n"),
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["CSV"]}],
    },
    {
        name: "Parse Property List: rejects XML entities",
        input: stringToHex('<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x "unsafe">]><plist><string>&x;</string></plist>'),
        expectedOutput: "XML property list entity declarations are not supported.",
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["JSON"]}],
    },
    {
        name: "Parse Property List: rejects undeclared XML entities",
        input: stringToHex('<plist version="1.0"><string>&unknown;</string></plist>'),
        expectedOutput: "Invalid or unsupported XML entity in property list.",
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse Property List", args: ["JSON"]}],
    },
]);
