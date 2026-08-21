/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import {
    convertValue,
    executeRows,
    openSqlite,
    parseColumnSelection,
    quoteIdentifier,
    readSchema,
    rowsToDelimited,
    selectColumns,
    tableColumns,
    validateReadOnlySql,
} from "../lib/SQLiteDFIR.mjs";

/** Extract one SQLite table into a structured format. */
class DumpSQLiteTable extends Operation {

    /** DumpSQLiteTable constructor. */
    constructor() {
        super();
        this.name = "Dump SQLite Table";
        this.module = "SQLiteDFIR";
        this.description = "Extracts a selected SQLite table as CSV, TSV, JSON, or JSON Lines. Supports exact column selection, exclusions, a read-only WHERE expression, ordering, bounded row counts, explicit BLOB representations, and precision-safe 64-bit integers.";
        this.infoURL = "https://sqlite.org/lang_select.html";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Table name",
                type: "string",
                value: "",
                allowEmpty: false,
                maxLength: 1000,
            },
            {
                name: "Output format",
                type: "option",
                value: ["CSV", "TSV", "JSON", "JSON Lines"],
            },
            {
                name: "Include columns (comma list or JSON array)",
                type: "string",
                value: "",
                maxLength: 10000,
            },
            {
                name: "Exclude columns (comma list or JSON array)",
                type: "string",
                value: "",
                maxLength: 10000,
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
                name: "WHERE condition",
                type: "string",
                value: "",
                maxLength: 50000,
            },
            {
                name: "ORDER BY expression",
                type: "string",
                value: "",
                maxLength: 10000,
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
        const [tableName, outputFormat, includeText, excludeText, maximumRows, where, orderBy, blobMode] = args;
        const opened = await openSqlite(input);
        try {
            const object = readSchema(opened.db, true).find(item => item.name === tableName && item.type === "table");
            if (!object) throw new OperationError(`SQLite table not found: ${tableName}`);
            const selected = selectColumns(tableColumns(opened.db, tableName), parseColumnSelection(includeText), parseColumnSelection(excludeText));
            const selectList = selected.map(column => quoteIdentifier(column.name)).join(", ");
            const sql = `SELECT ${selectList} FROM ${quoteIdentifier(tableName)}` +
                (where.trim() ? ` WHERE ${where}` : "") +
                (orderBy.trim() ? ` ORDER BY ${orderBy}` : "");
            validateReadOnlySql(sql);
            const result = executeRows(opened.db, sql, maximumRows, 10000);
            const structured = outputFormat === "JSON" || outputFormat === "JSON Lines";
            const rows = result.rows.map(row => Object.fromEntries(selected.map((column, index) => [
                column.name,
                convertValue(row[index], blobMode, structured),
            ])));
            const metadata = {
                table: tableName,
                columns: selected,
                rowCount: rows.length,
                truncated: result.truncated,
            };

            if (outputFormat === "JSON") return JSON.stringify({...metadata, rows}, null, 4);
            if (outputFormat === "JSON Lines") return [
                JSON.stringify({$sqliteMetadata: metadata}),
                ...rows.map(row => JSON.stringify(row)),
            ].join("\n");
            return rowsToDelimited([
                selected.map(column => column.name),
                ...result.rows.map(row => row.map(value => convertValue(value, blobMode, false))),
            ], outputFormat === "TSV" ? "\t" : ",");
        } finally {
            opened.db.close();
        }
    }
}

export default DumpSQLiteTable;
