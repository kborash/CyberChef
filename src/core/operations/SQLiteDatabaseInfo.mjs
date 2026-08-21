/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {databaseInfo, formatDatabaseInfoSummary, openSqlite} from "../lib/SQLiteDFIR.mjs";

/** Produce a forensic overview of an SQLite database. */
class SQLiteDatabaseInfo extends Operation {

    /** SQLiteDatabaseInfo constructor. */
    constructor() {
        super();
        this.name = "SQLite Database Info";
        this.module = "SQLiteDFIR";
        this.description = "Validates an SQLite database and reports header, page, version, encoding, vacuum, journal, integrity, schema-object, and forensic-interest metadata without dumping table contents.";
        this.infoURL = "https://sqlite.org/fileformat.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Output format",
                type: "option",
                value: ["Summary", "JSON"],
            },
            {
                name: "Calculate table row counts",
                type: "boolean",
                value: false,
            },
            {
                name: "Run quick integrity check",
                type: "boolean",
                value: false,
            },
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {Promise<string>}
     */
    async run(input, args) {
        const opened = await openSqlite(input);
        try {
            const info = databaseInfo(opened.db, opened.header, args[1], args[2]);
            return args[0] === "JSON" ? JSON.stringify(info, null, 4) : formatDatabaseInfoSummary(info);
        } finally {
            opened.db.close();
        }
    }
}

export default SQLiteDatabaseInfo;
