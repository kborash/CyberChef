/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {openSqlite, readSchema, tableColumns} from "../lib/SQLiteDFIR.mjs";
import {rowsToCSV} from "../lib/DFIRStructuredOutput.mjs";

/** List SQLite schema objects and optional column metadata. */
class ListSQLiteTables extends Operation {

    /** ListSQLiteTables constructor. */
    constructor() {
        super();
        this.name = "List SQLite Tables";
        this.module = "SQLiteDFIR";
        this.description = "Lists SQLite tables, views, indexes, and triggers with their root pages and creation SQL. Optional column metadata includes declared type, nullability, default, primary-key order, and hidden/generated status.";
        this.infoURL = "https://sqlite.org/schematab.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Object type",
                type: "option",
                value: ["All", "Tables", "Views", "Indexes", "Triggers"],
            },
            {
                name: "Include sqlite_* objects",
                type: "boolean",
                value: false,
            },
            {
                name: "Include columns",
                type: "boolean",
                value: true,
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
     * @returns {Promise<string>}
     */
    async run(input, args) {
        const [filter, includeInternal, includeColumns, outputFormat] = args;
        const opened = await openSqlite(input);
        try {
            const typeMap = {Tables: "table", Views: "view", Indexes: "index", Triggers: "trigger"};
            let objects = readSchema(opened.db, includeInternal);
            if (filter !== "All") objects = objects.filter(object => object.type === typeMap[filter]);
            if (includeColumns) {
                objects.forEach(object => {
                    if (object.type === "table" || object.type === "view") object.columns = tableColumns(opened.db, object.name);
                });
            }
            if (outputFormat === "JSON") return JSON.stringify(objects, null, 4);
            return rowsToCSV([
                ["type", "name", "tableName", "rootPage", "internal", "virtualTable", "withoutRowid", "sql", "columns"],
                ...objects.map(object => [
                    object.type,
                    object.name,
                    object.tableName,
                    object.rootPage,
                    object.internal,
                    object.virtualTable,
                    object.withoutRowid,
                    object.sql,
                    object.columns ? JSON.stringify(object.columns) : "",
                ]),
            ]);
        } finally {
            opened.db.close();
        }
    }
}

export default ListSQLiteTables;
