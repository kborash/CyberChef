/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {formatMboxCsv, parseMbox} from "../lib/MBOX.mjs";

/** Extract forensic message metadata from an MBOX mailbox. */
class ParseMBOX extends Operation {

    /** ParseMBOX constructor. */
    constructor() {
        super();
        this.name = "Parse MBOX";
        this.module = "DFIR";
        this.description = "Extracts forensic metadata from each message in a Unix MBOX mailbox and exports it as CSV. Fields include envelope sender and date, common addressing headers, subject, message ID, and a probable sender IP derived from explicit originating-IP headers or the oldest Received hop.";
        this.infoURL = "https://www.rfc-editor.org/rfc/rfc4155";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [{
            name: "Input encoding",
            type: "option",
            value: ["utf-8", "windows-1252", "iso-8859-1"],
        }];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        return formatMboxCsv(parseMbox(input, args[0]));
    }
}

export default ParseMBOX;
