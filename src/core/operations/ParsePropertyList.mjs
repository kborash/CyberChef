/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {formatPropertyList, parsePropertyList} from "../lib/PropertyList.mjs";

/**
 * Parse Property List operation
 */
class ParsePropertyList extends Operation {

    /** ParsePropertyList constructor. */
    constructor() {
        super();
        this.name = "Parse Property List";
        this.module = "DFIR";
        this.description = "Parses Apple binary, XML, and legacy OpenStep/ASCII property list files. Binary data, dates, UID objects, and integers that cannot be represented safely by JavaScript are preserved with typed JSON wrappers. CSV output flattens the hierarchy into path, type, and value rows.";
        this.infoURL = "https://developer.apple.com/library/archive/documentation/General/Conceptual/DevPedia-CocoaCore/PropertyList.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [{
            name: "Output format",
            type: "option",
            value: ["JSON", "CSV"],
        }];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        return formatPropertyList(parsePropertyList(input), args[0]);
    }
}

export default ParsePropertyList;
