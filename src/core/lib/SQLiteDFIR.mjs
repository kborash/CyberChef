/**
 * Shared read-only SQLite helpers for DFIR operations.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import initSqlJs from "sql.js/dist/sql-asm.js";
import OperationError from "../errors/OperationError.mjs";
import {rowsToCSV} from "./DFIRStructuredOutput.mjs";

const SQLITE_HEADER = "SQLite format 3\0";
const MAX_DATABASE_SIZE = 256 * 1024 * 1024;
const MAX_RESULT_SIZE = 64 * 1024 * 1024;
const MAX_SQL_LENGTH = 100000;
const READ_ONLY_PRAGMAS = new Set([
    "application_id",
    "auto_vacuum",
    "cache_size",
    "collation_list",
    "compile_options",
    "database_list",
    "encoding",
    "foreign_key_check",
    "foreign_key_list",
    "freelist_count",
    "function_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "journal_mode",
    "module_list",
    "page_count",
    "page_size",
    "pragma_list",
    "quick_check",
    "schema_version",
    "table_info",
    "table_list",
    "table_xinfo",
    "user_version",
]);
const PARAMETERIZED_PRAGMAS = new Set([
    "foreign_key_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "quick_check",
    "table_info",
    "table_xinfo",
]);

let sqlPromise;

/** @returns {Promise<Object>} */
function getSql() {
    if (!sqlPromise) sqlPromise = initSqlJs();
    return sqlPromise;
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
function u16be(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
function u32be(bytes, offset) {
    return (bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
}

/**
 * @param {number} version
 * @returns {string}
 */
function sqliteVersionString(version) {
    return `${Math.floor(version / 1000000)}.${Math.floor(version / 1000) % 1000}.${version % 1000}`;
}

/**
 * Reads and validates the fixed SQLite database header.
 *
 * @param {ArrayBuffer} input
 * @returns {Object}
 */
function parseSqliteHeader(input) {
    const bytes = new Uint8Array(input);
    if (bytes.length < 100) throw new OperationError("Truncated SQLite database header; at least 100 bytes are required.");
    const magic = new TextDecoder("ascii").decode(bytes.subarray(0, 16));
    if (magic !== SQLITE_HEADER)
        throw new OperationError("Invalid SQLite database header. The input may be encrypted or use an unsupported format.");

    const rawPageSize = u16be(bytes, 16);
    const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0)
        throw new OperationError(`Invalid SQLite page size: ${pageSize}.`);
    if (![1, 2].includes(bytes[18]) || ![1, 2].includes(bytes[19]))
        throw new OperationError("Invalid SQLite file format read/write version.");
    if (bytes[20] >= pageSize || bytes[21] !== 64 || bytes[22] !== 32 || bytes[23] !== 32)
        throw new OperationError("Invalid SQLite database header payload configuration.");

    const databasePageCount = u32be(bytes, 28);
    if (databasePageCount && databasePageCount * pageSize > bytes.length)
        throw new OperationError(`Truncated SQLite database: header declares ${databasePageCount} pages (${databasePageCount * pageSize} bytes), but the input contains ${bytes.length} bytes.`);

    const textEncodingCode = u32be(bytes, 56);
    const encodings = {0: "Unspecified", 1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"};
    if (!(textEncodingCode in encodings)) throw new OperationError(`Invalid SQLite text encoding code: ${textEncodingCode}.`);

    const sqliteVersionNumber = u32be(bytes, 96);
    return {
        magic: "SQLite format 3",
        pageSize,
        writeVersion: bytes[18],
        readVersion: bytes[19],
        writeMode: bytes[18] === 2 ? "WAL" : bytes[18] === 1 ? "Rollback journal" : "Unknown",
        readMode: bytes[19] === 2 ? "WAL" : bytes[19] === 1 ? "Rollback journal" : "Unknown",
        reservedBytesPerPage: bytes[20],
        fileChangeCounter: u32be(bytes, 24),
        databasePageCount,
        firstFreelistTrunkPage: u32be(bytes, 32),
        freelistPageCount: u32be(bytes, 36),
        schemaVersion: u32be(bytes, 40),
        schemaFormat: u32be(bytes, 44),
        textEncodingCode,
        textEncoding: encodings[textEncodingCode],
        userVersion: u32be(bytes, 60),
        incrementalVacuum: Boolean(u32be(bytes, 64)),
        applicationId: u32be(bytes, 68),
        applicationIdHex: `0x${u32be(bytes, 68).toString(16).padStart(8, "0")}`,
        versionValidFor: u32be(bytes, 92),
        sqliteVersionNumber,
        sqliteVersion: sqliteVersionString(sqliteVersionNumber),
        inputSize: bytes.length,
    };
}

/**
 * @param {ArrayBuffer} input
 * @returns {Promise<{db: Object, header: Object}>}
 */
async function openSqlite(input) {
    if (input.byteLength > MAX_DATABASE_SIZE)
        throw new OperationError(`SQLite input exceeds the ${MAX_DATABASE_SIZE / 1024 / 1024} MiB safety limit.`);
    const header = parseSqliteHeader(input);
    const SQL = await getSql();
    let db;
    try {
        db = new SQL.Database(new Uint8Array(input));
        db.run("PRAGMA query_only = ON");
        db.exec("SELECT name FROM sqlite_schema LIMIT 1");
    } catch (error) {
        if (db) db.close();
        throw new OperationError(`Unable to open SQLite database: ${error.message || error}`);
    }
    return {db, header};
}

/** @param {string} identifier @returns {string} */
function quoteIdentifier(identifier) {
    return `"${identifier.replace(/"/g, '""')}"`;
}

/** @param {string} value @returns {string} */
function quoteSqlString(value) {
    return `'${value.replace(/'/g, "''")}'`;
}

/**
 * Splits SQL at statement separators while respecting quoted text and comments.
 *
 * @param {string} sql
 * @returns {string[]}
 */
function splitSqlStatements(sql) {
    const statements = [];
    let start = 0;
    let state = "normal";
    for (let i = 0; i < sql.length; i++) {
        const char = sql[i];
        const next = sql[i + 1];
        if (state === "lineComment") {
            if (char === "\n" || char === "\r") state = "normal";
        } else if (state === "blockComment") {
            if (char === "*" && next === "/") {
                state = "normal";
                i++;
            }
        } else if (state !== "normal") {
            const closing = state === "single" ? "'" : state === "double" ? '"' : state === "backtick" ? "`" : "]";
            if (char === closing) {
                if (state !== "bracket" && next === closing) i++;
                else state = "normal";
            }
        } else if (char === "-" && next === "-") {
            state = "lineComment";
            i++;
        } else if (char === "/" && next === "*") {
            state = "blockComment";
            i++;
        } else if (char === "'") state = "single";
        else if (char === '"') state = "double";
        else if (char === "`") state = "backtick";
        else if (char === "[") state = "bracket";
        else if (char === ";") {
            const statement = sql.slice(start, i).trim();
            if (statement) statements.push(statement);
            start = i + 1;
        }
    }
    const last = sql.slice(start).trim();
    if (last) statements.push(last);
    return statements;
}

/**
 * @param {string} sql
 * @returns {string}
 */
function stripLeadingComments(sql) {
    let value = sql.trimStart();
    while (true) {
        if (value.startsWith("--")) {
            const end = value.search(/[\r\n]/);
            value = end < 0 ? "" : value.slice(end + 1).trimStart();
        } else if (value.startsWith("/*")) {
            const end = value.indexOf("*/", 2);
            if (end < 0) throw new OperationError("SQL contains an unclosed block comment.");
            value = value.slice(end + 2).trimStart();
        } else return value;
    }
}

/**
 * @param {string} sql
 * @returns {string}
 */
function validateReadOnlySql(sql) {
    if (!sql.trim()) throw new OperationError("SQL query cannot be empty.");
    if (sql.length > MAX_SQL_LENGTH) throw new OperationError(`SQL query length cannot exceed ${MAX_SQL_LENGTH} characters.`);
    const statements = splitSqlStatements(sql);
    if (statements.length !== 1) throw new OperationError("Exactly one read-only SQL statement is permitted.");
    const statement = stripLeadingComments(statements[0]);
    const keyword = (statement.match(/^([a-z]+)/i) || [])[1]?.toUpperCase();
    if (keyword === "SELECT" || keyword === "WITH") return statement;
    if (keyword !== "PRAGMA")
        throw new OperationError("Only SELECT, WITH, and allow-listed read-only PRAGMA statements are permitted.");

    const pragma = statement.match(/^PRAGMA\s+(?:(?:main|temp)\s*\.\s*)?([a-z_][a-z\d_]*)\s*(\([^)]*\))?\s*$/i);
    if (!pragma || !READ_ONLY_PRAGMAS.has(pragma[1].toLowerCase()))
        throw new OperationError("This PRAGMA is not included in the read-only allow-list.");
    if (pragma[2] && !PARAMETERIZED_PRAGMAS.has(pragma[1].toLowerCase()))
        throw new OperationError("Arguments are not permitted for this read-only PRAGMA.");
    return statement;
}

/**
 * @param {*} value
 * @returns {string}
 */
function storageType(value) {
    if (value === null) return "null";
    if (typeof value === "bigint") return "integer";
    if (typeof value === "number") return "real";
    if (typeof value === "string") return "text";
    if (value instanceof Uint8Array) return "blob";
    return typeof value;
}

/** @param {Uint8Array} bytes @returns {string} */
function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** @param {Uint8Array} bytes @returns {string} */
function bytesToBase64(bytes) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let output = "";
    for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i];
        const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
        const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
        output += alphabet[a >>> 2];
        output += alphabet[((a & 3) << 4) | (b >>> 4)];
        output += i + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >>> 6)] : "=";
        output += i + 2 < bytes.length ? alphabet[c & 63] : "=";
    }
    return output;
}

/**
 * @param {*} value
 * @param {string} blobMode
 * @param {boolean} structured
 * @param {Function|null} externalBlob
 * @returns {*}
 */
function convertValue(value, blobMode, structured, externalBlob=null) {
    if (value === null) return structured ? null : "<NULL>";
    if (typeof value === "bigint") {
        if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) return Number(value);
        return structured ? {$sqliteType: "integer", value: value.toString()} : value.toString();
    }
    if (!(value instanceof Uint8Array)) return value;
    if (blobMode === "Separate files" && externalBlob) return externalBlob(value);
    if (blobMode === "Metadata only")
        return structured ? {$sqliteType: "blob", byteLength: value.length} : `<BLOB ${value.length} bytes>`;
    const encoding = blobMode === "Hex" ? "hex" : "base64";
    const encoded = encoding === "hex" ? bytesToHex(value) : bytesToBase64(value);
    return structured ? {$sqliteType: "blob", encoding, value: encoded, byteLength: value.length} : `${encoding}:${encoded}`;
}

/**
 * @param {Object} db
 * @param {string} sql
 * @param {number} maximumRows
 * @param {number} maximumMilliseconds
 * @returns {Object}
 */
function executeRows(db, sql, maximumRows, maximumMilliseconds) {
    const started = Date.now();
    let statement;
    try {
        statement = db.prepare(sql);
        const columns = statement.getColumnNames();
        const rows = [];
        const types = columns.map(() => new Set());
        let resultSize = 0;
        let truncated = false;
        while (statement.step()) {
            if (Date.now() - started > maximumMilliseconds)
                throw new OperationError(`SQLite query exceeded the ${maximumMilliseconds} ms execution limit.`);
            if (rows.length >= maximumRows) {
                truncated = true;
                break;
            }
            const row = statement.get(null, {useBigInt: true});
            for (const value of row) {
                resultSize += value instanceof Uint8Array ? value.length : typeof value === "string" ? value.length * 2 : 8;
            }
            if (resultSize > MAX_RESULT_SIZE)
                throw new OperationError(`SQLite result exceeds the ${MAX_RESULT_SIZE / 1024 / 1024} MiB safety limit.`);
            row.forEach((value, index) => types[index].add(storageType(value)));
            rows.push(row);
        }
        return {
            columns,
            rows,
            storageTypes: types.map(values => Array.from(values)),
            truncated,
            elapsedMilliseconds: Date.now() - started,
        };
    } catch (error) {
        if (error instanceof OperationError) throw error;
        throw new OperationError(`SQLite query failed: ${error.message || error}`);
    } finally {
        if (statement) statement.free();
    }
}

/**
 * @param {string[]} names
 * @returns {string[]}
 */
function uniqueColumnNames(names) {
    const counts = new Map();
    return names.map(name => {
        const count = (counts.get(name) || 0) + 1;
        counts.set(name, count);
        return count === 1 ? name : `${name}_${count}`;
    });
}

/**
 * @param {Object} result
 * @param {string} outputFormat
 * @param {string} blobMode
 * @param {boolean} includeTypes
 * @returns {string}
 */
function formatQueryRows(result, outputFormat, blobMode, includeTypes) {
    const structured = outputFormat === "JSON" || outputFormat === "JSON Lines";
    const keys = uniqueColumnNames(result.columns);
    const rows = result.rows.map(row => Object.fromEntries(keys.map((key, index) => [key, convertValue(row[index], blobMode, structured)])));
    const metadata = {
        columns: result.columns.map((name, index) => ({name, key: keys[index], storageTypes: result.storageTypes[index]})),
        truncated: result.truncated,
        rowCount: rows.length,
        elapsedMilliseconds: result.elapsedMilliseconds,
    };

    if (outputFormat === "JSON") return JSON.stringify(includeTypes ? {...metadata, rows} : rows, null, 4);
    if (outputFormat === "JSON Lines") {
        const lines = [];
        if (includeTypes) lines.push(JSON.stringify({$sqliteMetadata: metadata}));
        rows.forEach(row => lines.push(JSON.stringify(row)));
        return lines.join("\n");
    }

    const delimiter = outputFormat === "TSV" ? "\t" : ",";
    return rowsToDelimited([
        keys,
        ...result.rows.map(row => row.map(value => convertValue(value, blobMode, false))),
    ], delimiter);
}

/**
 * @param {Array[]} rows
 * @param {string} delimiter
 * @returns {string}
 */
function rowsToDelimited(rows, delimiter) {
    if (delimiter === ",") return rowsToCSV(rows);
    return rows.map(row => row.map(value => {
        if (value === null || value === undefined) return "";
        const text = value.toString();
        return /["\t\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
    }).join(delimiter)).join("\r\n") + "\r\n";
}

/**
 * @param {Object} db
 * @param {boolean} includeInternal
 * @returns {Object[]}
 */
function readSchema(db, includeInternal=true) {
    const where = includeInternal ? "" : "WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'";
    const result = executeRows(db,
        `SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema ${where} ORDER BY type, name`,
        100000, 10000);
    return result.rows.map(row => ({
        type: row[0],
        name: row[1],
        tableName: row[2],
        rootPage: Number(row[3]),
        sql: row[4],
        internal: row[1].startsWith("sqlite_"),
        virtualTable: row[0] === "table" && /^CREATE\s+VIRTUAL\s+TABLE\b/i.test(row[4] || ""),
        withoutRowid: row[0] === "table" && /\bWITHOUT\s+ROWID\b/i.test(row[4] || ""),
    }));
}

/**
 * @param {Object} db
 * @param {string} tableName
 * @returns {Object[]}
 */
function tableColumns(db, tableName) {
    const result = executeRows(db, `PRAGMA table_xinfo(${quoteSqlString(tableName)})`, 10000, 5000);
    return result.rows.map(row => ({
        ordinal: Number(row[0]),
        name: row[1],
        declaredType: row[2] || "",
        notNull: Boolean(row[3]),
        defaultValue: row[4],
        primaryKeyOrder: Number(row[5]),
        hidden: Boolean(row[6]),
    }));
}

/**
 * @param {Object} db
 * @param {string} tableName
 * @returns {number|string}
 */
function tableRowCount(db, tableName) {
    const result = executeRows(db, `SELECT count(*) FROM ${quoteIdentifier(tableName)}`, 1, 10000);
    const value = result.rows[0]?.[0] ?? 0n;
    return typeof value === "bigint" && (value > BigInt(Number.MAX_SAFE_INTEGER)) ? value.toString() : Number(value);
}

/**
 * @param {Object} db
 * @param {Object} header
 * @param {boolean} calculateRowCounts
 * @param {boolean} runQuickCheck
 * @returns {Object}
 */
function databaseInfo(db, header, calculateRowCounts, runQuickCheck=false) {
    const schema = readSchema(db, true);
    const scalarPragma = name => {
        const result = executeRows(db, `PRAGMA ${name}`, 1, 5000);
        const value = result.rows[0]?.[0];
        return typeof value === "bigint" ? Number(value) : value;
    };
    const warnings = [];
    if (header.freelistPageCount) warnings.push(`Database contains ${header.freelistPageCount} freelist pages that may retain recoverable content.`);
    if (header.writeVersion === 2 || header.readVersion === 2) warnings.push("Database header indicates WAL mode; an associated -wal file may contain newer or deleted records.");
    if (header.applicationId) warnings.push(`Database uses non-zero application ID ${header.applicationIdHex}; interpret it using producer documentation.`);
    if (header.databasePageCount * header.pageSize < header.inputSize) warnings.push("Input contains bytes beyond the database size declared in the header.");

    const objects = schema.map(object => ({...object}));
    if (calculateRowCounts) {
        for (const object of objects.filter(item => item.type === "table" && !item.virtualTable)) {
            try {
                object.rowCount = tableRowCount(db, object.name);
            } catch (error) {
                object.rowCountError = error.message;
                warnings.push(`Unable to count rows in ${object.name}: ${error.message}`);
            }
        }
    }

    let quickCheck = ["not run"];
    if (runQuickCheck) {
        try {
            quickCheck = executeRows(db, "PRAGMA quick_check(10)", 10, 10000).rows.map(row => row[0].toString());
            if (quickCheck.length !== 1 || quickCheck[0] !== "ok") warnings.push("SQLite quick_check reported possible database corruption.");
        } catch (error) {
            quickCheck = [error.message];
            warnings.push("SQLite quick_check could not complete.");
        }
    }

    const autoVacuumValue = scalarPragma("auto_vacuum");
    const connectionJournalMode = scalarPragma("journal_mode");
    const journalMode = header.writeVersion === 2 ? "wal" : "rollback journal (specific mode is not stored in the database file)";
    return {
        format: "SQLite 3",
        header,
        runtime: {
            sqliteVersion: executeRows(db, "SELECT sqlite_version()", 1, 5000).rows[0][0],
            pageCount: scalarPragma("page_count"),
            freelistPageCount: scalarPragma("freelist_count"),
            autoVacuum: {value: autoVacuumValue, name: ["None", "Full", "Incremental"][autoVacuumValue] || "Unknown"},
            journalMode,
            connectionJournalMode,
            quickCheck,
        },
        objectCounts: {
            tables: schema.filter(object => object.type === "table").length,
            views: schema.filter(object => object.type === "view").length,
            indexes: schema.filter(object => object.type === "index").length,
            triggers: schema.filter(object => object.type === "trigger").length,
            virtualTables: schema.filter(object => object.virtualTable).length,
            withoutRowidTables: schema.filter(object => object.withoutRowid).length,
        },
        objects,
        warnings,
    };
}

/** @param {Object} info @returns {string} */
function formatDatabaseInfoSummary(info) {
    const lines = [
        "SQLite Database Information",
        `SQLite header version: ${info.header.sqliteVersion} (${info.header.sqliteVersionNumber})`,
        `SQLite runtime version: ${info.runtime.sqliteVersion}`,
        `Page size: ${info.header.pageSize}`,
        `Database pages: ${info.runtime.pageCount}`,
        `Freelist pages: ${info.runtime.freelistPageCount}`,
        `Schema version: ${info.header.schemaVersion}`,
        `User version: ${info.header.userVersion}`,
        `Application ID: ${info.header.applicationId} (${info.header.applicationIdHex})`,
        `Text encoding: ${info.header.textEncoding}`,
        `Auto-vacuum: ${info.runtime.autoVacuum.name}`,
        `Journal mode: ${info.runtime.journalMode} (header: ${info.header.writeMode})`,
        `Quick check: ${info.runtime.quickCheck.join("; ")}`,
        "",
        `Tables: ${info.objectCounts.tables}`,
        `Views: ${info.objectCounts.views}`,
        `Indexes: ${info.objectCounts.indexes}`,
        `Triggers: ${info.objectCounts.triggers}`,
        `Virtual tables: ${info.objectCounts.virtualTables}`,
        `WITHOUT ROWID tables: ${info.objectCounts.withoutRowidTables}`,
        "",
        "Schema objects:",
    ];
    info.objects.forEach(object => {
        const flags = [object.virtualTable ? "virtual" : "", object.withoutRowid ? "WITHOUT ROWID" : ""].filter(Boolean);
        const count = "rowCount" in object ? `, ${object.rowCount} rows` : "";
        lines.push(`- ${object.type}: ${object.name} (root page ${object.rootPage}${count}${flags.length ? `, ${flags.join(", ")}` : ""})`);
    });
    if (info.warnings.length) {
        lines.push("", "Forensic warnings:");
        info.warnings.forEach(warning => lines.push(`- ${warning}`));
    }
    return lines.join("\n");
}

/**
 * @param {string} value
 * @returns {string[]}
 */
function parseColumnSelection(value) {
    const trimmed = value.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith("[")) {
        let parsed;
        try {
            parsed = JSON.parse(trimmed);
        } catch (error) {
            throw new OperationError(`Invalid JSON column list: ${error.message}`);
        }
        if (!Array.isArray(parsed) || parsed.some(item => typeof item !== "string"))
            throw new OperationError("JSON column lists must contain only strings.");
        return parsed;
    }
    return trimmed.split(",").map(item => item.trim()).filter(Boolean);
}

/**
 * @param {Object[]} columns
 * @param {string[]} included
 * @param {string[]} excluded
 * @returns {Object[]}
 */
function selectColumns(columns, included, excluded) {
    const byName = new Map(columns.map(column => [column.name, column]));
    for (const name of [...included, ...excluded]) {
        if (!byName.has(name)) throw new OperationError(`SQLite table does not contain column: ${name}`);
    }
    const selected = included.length ? included.map(name => byName.get(name)) : columns.filter(column => !column.hidden);
    const excludedSet = new Set(excluded);
    const result = selected.filter(column => !excludedSet.has(column.name));
    if (!result.length) throw new OperationError("At least one SQLite table column must be selected.");
    return result;
}

export {
    MAX_DATABASE_SIZE,
    bytesToBase64,
    bytesToHex,
    convertValue,
    databaseInfo,
    executeRows,
    formatDatabaseInfoSummary,
    formatQueryRows,
    openSqlite,
    parseColumnSelection,
    parseSqliteHeader,
    quoteIdentifier,
    readSchema,
    rowsToDelimited,
    selectColumns,
    tableColumns,
    tableRowCount,
    validateReadOnlySql,
};
