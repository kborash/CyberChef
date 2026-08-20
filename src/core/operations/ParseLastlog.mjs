/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {formatLastlog, parseLastlog} from "../lib/LinuxLoginRecords.mjs";

/**
 * Parse lastlog operation
 */
class ParseLastlog extends Operation {

    /**
     * ParseLastlog constructor
     */
    constructor() {
        super();

        this.name = "Parse lastlog";
        this.module = "Default";
        this.description = "Parses a traditional sparse Linux <code>lastlog</code> file into structured JSON or CSV. Each record's file position identifies its UID; zero-filled records are omitted by default. Input should be the raw contents of <code>/var/log/lastlog</code>.";
        this.infoURL = "https://man7.org/linux/man-pages/man8/lastlog.8.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Timestamp size",
                type: "option",
                value: ["32-bit", "64-bit"],
            },
            {
                name: "Endianness",
                type: "option",
                value: ["Little", "Big"],
            },
            {
                name: "Include empty records",
                type: "boolean",
                value: false,
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
        return formatLastlog(parseLastlog(input, args[0], args[1], args[2]), args[3]);
    }
}

export default ParseLastlog;
