/**
 * Node-level tests for SQLite logical ZIP export.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import assert from "assert";
import initSqlJs from "sql.js/dist/sql-asm.js";
import unzip from "zlibjs/bin/unzip.min.js";
import TestRegister from "../../lib/TestRegister.mjs";
import {openSqlite} from "../../../src/core/lib/SQLiteDFIR.mjs";
import {exportSqliteArchive} from "../../../src/core/lib/SQLiteExport.mjs";

const Zlib = unzip.Zlib;

TestRegister.addApiTests([{
    name: "Export SQLite Database creates metadata, schema, table, and external BLOB files",
    run: async () => {
        const SQL = await initSqlJs();
        const source = new SQL.Database();
        source.run("CREATE TABLE evidence (id INTEGER, payload BLOB); INSERT INTO evidence VALUES (1, x'0102');");
        const database = source.export();
        source.close();

        const opened = await openSqlite(database.buffer);
        let archive;
        try {
            archive = exportSqliteArchive(opened.db, opened.header, {
                outputFormat: "JSON Lines",
                maximumRows: 100,
                includeRowCounts: true,
                includeViews: false,
                blobMode: "Separate files",
            });
        } finally {
            opened.db.close();
        }

        const extracted = new Zlib.Unzip(archive);
        const filenames = extracted.getFilenames();
        assert.ok(filenames.includes("sqlite_export/metadata.json"));
        assert.ok(filenames.includes("sqlite_export/schema.sql"));
        assert.ok(filenames.some(name => /^sqlite_export\/tables\/evidence--[\da-f]{8}\.jsonl$/.test(name)));
        const blobName = filenames.find(name => /^sqlite_export\/blobs\/evidence--[\da-f]{8}\/0\/payload--[\da-f]{8}\.bin$/.test(name));
        assert.ok(blobName);
        assert.deepStrictEqual(Array.from(extracted.decompress(blobName)), [1, 2]);
    },
}]);
