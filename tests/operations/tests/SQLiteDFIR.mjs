/**
 * Tests for logical SQLite DFIR operations.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import initSqlJs from "sql.js/dist/sql-asm.js";
import TestRegister from "../../lib/TestRegister.mjs";

/** @param {Uint8Array} bytes @returns {string} */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

const SQL = await initSqlJs();
const fixture = new SQL.Database();
fixture.run(`
    PRAGMA user_version = 42;
    PRAGMA application_id = 305419896;
    CREATE TABLE records (id INTEGER PRIMARY KEY, note TEXT, payload BLOB);
    INSERT INTO records VALUES (1, '', x'');
    INSERT INTO records VALUES (9223372036854775807, NULL, x'00ff');
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
    INSERT INTO settings VALUES ('owner', 'analyst');
    CREATE INDEX records_note_idx ON records(note);
    CREATE VIEW record_notes AS SELECT id, note FROM records;
    CREATE TRIGGER records_delete_trigger AFTER DELETE ON records BEGIN SELECT 1; END;
    CREATE TABLE discarded (data BLOB);
    INSERT INTO discarded VALUES (zeroblob(5000));
    DROP TABLE discarded;
`);
const databaseHex = toHex(fixture.export());
fixture.close();

const inputRecipe = {op: "From Hex", args: ["None"]};

TestRegister.addTests([
    {
        name: "SQLite Database Info: reports forensic header and schema metadata",
        input: databaseHex,
        expectedMatch: /"userVersion": 42[\s\S]*"applicationId": 305419896[\s\S]*"withoutRowidTables": 1[\s\S]*freelist pages/,
        recipeConfig: [inputRecipe, {op: "SQLite Database Info", args: ["JSON", true, true]}],
    },
    {
        name: "SQLite Database Info: produces a human-readable summary",
        input: databaseHex,
        expectedMatch: /^SQLite Database Information[\s\S]*Tables: 2[\s\S]*WITHOUT ROWID tables: 1/,
        recipeConfig: [inputRecipe, {op: "SQLite Database Info", args: ["Summary", false, false]}],
    },
    {
        name: "SQLite Database Info: rejects non-SQLite input",
        input: "00010203",
        expectedOutput: "Truncated SQLite database header; at least 100 bytes are required.",
        recipeConfig: [inputRecipe, {op: "SQLite Database Info", args: ["JSON", false, false]}],
    },
    {
        name: "List SQLite Tables: lists table column metadata",
        input: databaseHex,
        expectedMatch: /"name": "records"[\s\S]*"declaredType": "INTEGER"[\s\S]*"name": "settings"[\s\S]*"withoutRowid": true/,
        recipeConfig: [inputRecipe, {op: "List SQLite Tables", args: ["Tables", false, true, "JSON"]}],
    },
    {
        name: "List SQLite Tables: exports CSV",
        input: databaseHex,
        expectedMatch: /^type,name,tableName,rootPage,internal,virtualTable,withoutRowid,sql,columns\r\ntable,records,/,
        recipeConfig: [inputRecipe, {op: "List SQLite Tables", args: ["Tables", false, false, "CSV"]}],
    },
    {
        name: "Dump SQLite Table: distinguishes NULL, empty strings, and empty BLOBs in CSV",
        input: databaseHex,
        expectedOutput: [
            "id,note,payload",
            "1,,base64:",
            "9223372036854775807,<NULL>,base64:AP8=",
            "",
        ].join("\r\n"),
        recipeConfig: [inputRecipe, {op: "Dump SQLite Table", args: ["records", "CSV", "", "", 100, "", "id", "Base64"]}],
    },
    {
        name: "Dump SQLite Table: preserves unsafe integers and BLOB metadata in JSON",
        input: databaseHex,
        expectedMatch: /"\$sqliteType": "integer",\s*"value": "9223372036854775807"[\s\S]*"\$sqliteType": "blob",\s*"byteLength": 2/,
        recipeConfig: [inputRecipe, {op: "Dump SQLite Table", args: ["records", "JSON", "", "", 100, "id > 1", "", "Metadata only"]}],
    },
    {
        name: "Dump SQLite Table: accepts JSON column lists for unusual identifiers",
        input: databaseHex,
        expectedMatch: /^note\r\n\r\n<NULL>\r\n$/,
        recipeConfig: [inputRecipe, {op: "Dump SQLite Table", args: ["records", "CSV", '["note"]', "", 100, "", "id", "Hex"]}],
    },
    {
        name: "Query SQLite: supports CTEs and includes storage type information",
        input: databaseHex,
        expectedMatch: /"storageTypes": \[\s*"integer"\s*\][\s\S]*"total": 2/,
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["WITH selected AS (SELECT * FROM records) SELECT count(*) AS total FROM selected", "JSON", 100, 10000, true, "Base64"]}],
    },
    {
        name: "Query SQLite: permits allow-listed read-only PRAGMAs",
        input: databaseHex,
        expectedMatch: /^user_version\r\n42\r\n$/,
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["PRAGMA user_version", "CSV", 100, 10000, false, "Base64"]}],
    },
    {
        name: "Query SQLite: rejects modification statements",
        input: databaseHex,
        expectedOutput: "Only SELECT, WITH, and allow-listed read-only PRAGMA statements are permitted.",
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["DELETE FROM records", "JSON", 100, 10000, true, "Base64"]}],
    },
    {
        name: "Query SQLite: rejects multiple statements",
        input: databaseHex,
        expectedOutput: "Exactly one read-only SQL statement is permitted.",
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["SELECT 1; SELECT 2", "JSON", 100, 10000, true, "Base64"]}],
    },
    {
        name: "Query SQLite: rejects arguments to state-changing PRAGMAs",
        input: databaseHex,
        expectedOutput: "Arguments are not permitted for this read-only PRAGMA.",
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["PRAGMA journal_mode(WAL)", "JSON", 100, 10000, true, "Base64"]}],
    },
    {
        name: "Query SQLite: applies maximum result rows",
        input: databaseHex,
        expectedMatch: /"truncated": true[\s\S]*"rowCount": 1/,
        recipeConfig: [inputRecipe, {op: "Query SQLite", args: ["SELECT id FROM records ORDER BY id", "JSON", 1, 10000, true, "Base64"]}],
    },
]);
