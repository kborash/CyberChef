/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {formatWindowsShellLink, parseWindowsShellLink} from "../lib/WindowsShellLink.mjs";

const ANSI_ENCODINGS = [
    "windows-1252",
    "windows-1250",
    "windows-1251",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "windows-874",
    "shift_jis",
    "gbk",
    "euc-kr",
    "big5",
    "utf-8",
];

/** Parse Windows LNK operation. */
class ParseWindowsLNK extends Operation {

    /** ParseWindowsLNK constructor. */
    constructor() {
        super();
        this.name = "Parse Windows LNK";
        this.module = "DFIR";
        this.description = "Parses the Windows Shell Link (.LNK) binary format, including header metadata, target item IDs, local and network paths, StringData, and forensic ExtraData such as tracker, environment, known-folder, and shim blocks. Unrecognised structures retain their raw bytes.";
        this.infoURL = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "ANSI encoding",
                type: "option",
                value: ANSI_ENCODINGS,
            },
            {
                name: "Output format",
                type: "option",
                value: ["JSON", "CSV"],
            },
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        return formatWindowsShellLink(parseWindowsShellLink(input, args[0]), args[1]);
    }
}

export default ParseWindowsLNK;
