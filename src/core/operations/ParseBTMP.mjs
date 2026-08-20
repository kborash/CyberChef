/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {formatUtmp, parseUtmp} from "../lib/LinuxLoginRecords.mjs";

/**
 * Parse BTMP operation
 */
class ParseBTMP extends Operation {

    /**
     * ParseBTMP constructor
     */
    constructor() {
        super();

        this.name = "Parse BTMP";
        this.module = "Default";
        this.description = "Parses a traditional Linux <code>btmp</code> file into structured JSON or CSV. BTMP records failed login attempts. Input should be the raw contents of a file such as <code>/var/log/btmp</code>.";
        this.infoURL = "https://man7.org/linux/man-pages/man5/utmp.5.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
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
        return formatUtmp(parseUtmp(input, args[0], args[1]), args[2]);
    }
}

export default ParseBTMP;
