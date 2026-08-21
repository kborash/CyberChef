/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {executeRows, formatQueryRows, openSqlite, validateReadOnlySql} from "../lib/SQLiteDFIR.mjs";

/** Execute one bounded read-only SQLite query. */
class QuerySQLite extends Operation {

    /** QuerySQLite constructor. */
    constructor() {
        super();
        this.name = "Query SQLite";
        this.module = "SQLiteDFIR";
        this.description = "Runs one read-only SELECT, WITH, or allow-listed PRAGMA statement against an in-memory copy of an SQLite database. Query-only mode, row limits, time checks, explicit BLOB handling, and precision-safe integers protect forensic input and recipe execution.";
        this.infoURL = "https://sqlite.org/lang_select.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "SQL query",
                type: "text",
                value: "SELECT name, type FROM sqlite_schema ORDER BY type, name",
                allowEmpty: false,
                maxLength: 100000,
            },
            {
                name: "Output format",
                type: "option",
                value: ["CSV", "JSON", "JSON Lines"],
            },
            {
                name: "Maximum rows",
                type: "number",
                value: 1000,
                min: 1,
                max: 100000,
                integer: true,
            },
            {
                name: "Maximum execution time (ms)",
                type: "number",
                value: 10000,
                min: 100,
                max: 60000,
                integer: true,
            },
            {
                name: "Include column type information",
                type: "boolean",
                value: true,
            },
            {
                name: "BLOB representation",
                type: "option",
                value: ["Base64", "Hex", "Metadata only"],
            },
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {Promise<string>}
     */
    async run(input, args) {
        const [sql, outputFormat, maximumRows, maximumMilliseconds, includeTypes, blobMode] = args;
        const statement = validateReadOnlySql(sql);
        const opened = await openSqlite(input);
        try {
            return formatQueryRows(
                executeRows(opened.db, statement, maximumRows, maximumMilliseconds),
                outputFormat,
                blobMode,
                includeTypes,
            );
        } finally {
            opened.db.close();
        }
    }
}

export default QuerySQLite;
