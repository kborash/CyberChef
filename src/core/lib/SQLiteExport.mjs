/**
 * Logical SQLite database ZIP export.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import zip from "zlibjs/bin/zip.min.js";
import {
    convertValue,
    databaseInfo,
    executeRows,
    quoteIdentifier,
    readSchema,
    rowsToDelimited,
    tableColumns,
} from "./SQLiteDFIR.mjs";

const Zlib = zip.Zlib;
const encoder = new TextEncoder();

/** @param {string} value @returns {string} */
function hashName(value) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < value.length; i++) {
        hash ^= value.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
}

/** @param {string} value @returns {string} */
function safeName(value) {
    const sanitized = value.replace(/[\x00-\x1f\\/:*?"<>|]/g, "_").replace(/[. ]+$/g, "").slice(0, 100) || "unnamed";
    return `${sanitized}--${hashName(value)}`;
}

/**
 * @param {Object} archive
 * @param {string} path
 * @param {string|Uint8Array} content
 */
function addFile(archive, path, content) {
    archive.addFile(typeof content === "string" ? encoder.encode(content) : content, {
        filename: encoder.encode(path),
        compressionMethod: Zlib.Zip.CompressionMethod.DEFLATE,
        os: Zlib.Zip.OperatingSystem.UNIX,
    });
}

/**
 * @param {Object} db
 * @param {Object} header
 * @param {Object} options
 * @returns {Uint8Array}
 */
function exportSqliteArchive(db, header, options) {
    const archive = new Zlib.Zip();
    const allSchema = readSchema(db, true);
    const exportedObjects = allSchema.filter(object =>
        object.type === "table" || (options.includeViews && object.type === "view"));
    const schemaWithColumns = allSchema.map(object => ({
        ...object,
        ...((object.type === "table" || object.type === "view") ? {columns: tableColumns(db, object.name)} : {}),
    }));

    const info = databaseInfo(db, header, options.includeRowCounts, false);
    info.export = {
        format: options.outputFormat,
        blobRepresentation: options.blobMode,
        maximumRowsPerObject: options.maximumRows,
        includeViews: options.includeViews,
        exportedObjects: exportedObjects.map(object => object.name),
    };
    addFile(archive, "sqlite_export/metadata.json", JSON.stringify(info, null, 4));
    addFile(archive, "sqlite_export/schema.json", JSON.stringify(schemaWithColumns, null, 4));
    addFile(archive, "sqlite_export/schema.sql", allSchema
        .filter(object => object.sql)
        .map(object => `${object.sql.replace(/;\s*$/, "")};`)
        .join("\n\n") + "\n");

    for (const object of exportedObjects) {
        const columns = tableColumns(db, object.name).filter(column => !column.hidden);
        if (!columns.length) continue;
        const result = executeRows(db,
            `SELECT ${columns.map(column => quoteIdentifier(column.name)).join(", ")} FROM ${quoteIdentifier(object.name)}`,
            options.maximumRows,
            30000);
        const objectBase = safeName(object.name);
        const extension = options.outputFormat === "CSV" ? "csv" : options.outputFormat === "JSON" ? "json" : "jsonl";
        const structured = options.outputFormat !== "CSV";

        const rows = result.rows.map((row, rowIndex) => Object.fromEntries(columns.map((column, columnIndex) => {
            const externalBlob = bytes => {
                const path = `sqlite_export/blobs/${objectBase}/${rowIndex}/${safeName(column.name)}.bin`;
                addFile(archive, path, bytes);
                return structured ? {$sqliteType: "blob", file: path, byteLength: bytes.length} : `@file:${path}`;
            };
            return [column.name, convertValue(row[columnIndex], options.blobMode, structured, externalBlob)];
        })));
        const exportMetadata = {
            object: object.name,
            objectType: object.type,
            columns,
            rowCount: rows.length,
            truncated: result.truncated,
        };

        let content;
        if (options.outputFormat === "JSON") {
            content = JSON.stringify({...exportMetadata, rows}, null, 4);
        } else if (options.outputFormat === "JSON Lines") {
            content = [
                JSON.stringify({$sqliteMetadata: exportMetadata}),
                ...rows.map(row => JSON.stringify(row)),
            ].join("\n");
        } else {
            content = rowsToDelimited([
                columns.map(column => column.name),
                ...rows.map(row => columns.map(column => row[column.name])),
            ], ",");
        }
        addFile(archive, `sqlite_export/tables/${objectBase}.${extension}`, content);
    }
    return archive.compress();
}

export {
    exportSqliteArchive,
};
