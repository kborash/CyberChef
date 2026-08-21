/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {openSqlite} from "../lib/SQLiteDFIR.mjs";
import {exportSqliteArchive} from "../lib/SQLiteExport.mjs";

/** Export the logical contents and forensic metadata of an SQLite database. */
class ExportSQLiteDatabase extends Operation {

    /** ExportSQLiteDatabase constructor. */
    constructor() {
        super();
        this.name = "Export SQLite Database";
        this.module = "SQLiteDFIR";
        this.description = "Exports SQLite metadata, complete schema definitions, and one bounded logical data file per table in a ZIP archive. BLOBs can be encoded inline, represented by metadata, or extracted into collision-resistant paths.";
        this.infoURL = "https://sqlite.org/fileformat.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "File";
        this.args = [
            {
                name: "Filename",
                type: "string",
                value: "sqlite_export.zip",
                allowEmpty: false,
                maxLength: 255,
            },
            {
                name: "Table output format",
                type: "option",
                value: ["CSV", "JSON", "JSON Lines"],
            },
            {
                name: "Maximum rows per table",
                type: "number",
                value: 100000,
                min: 1,
                max: 1000000,
                integer: true,
            },
            {
                name: "Include row counts",
                type: "boolean",
                value: false,
            },
            {
                name: "Include views",
                type: "boolean",
                value: false,
            },
            {
                name: "BLOB representation",
                type: "option",
                value: ["Base64", "Hex", "Separate files", "Metadata only"],
            },
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {Promise<File>}
     */
    async run(input, args) {
        const opened = await openSqlite(input);
        try {
            const bytes = exportSqliteArchive(opened.db, opened.header, {
                outputFormat: args[1],
                maximumRows: args[2],
                includeRowCounts: args[3],
                includeViews: args[4],
                blobMode: args[5],
            });
            return new File([bytes], args[0], {type: "application/zip"});
        } finally {
            opened.db.close();
        }
    }
}

export default ExportSQLiteDatabase;
