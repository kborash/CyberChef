/**
 * Shared structured-output helpers for DFIR operations.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

/**
 * Escapes a value for an RFC 4180-style CSV cell.
 *
 * @param {*} value
 * @returns {string}
 */
function escapeCSV(value) {
    if (value === null || value === undefined) return "";

    const stringValue = value.toString();
    const escaped = stringValue.replace(/"/g, '""');
    return /[",\r\n]/.test(stringValue) ? `"${escaped}"` : escaped;
}

/**
 * Converts rows to CSV using CRLF line endings.
 *
 * @param {Array[]} rows
 * @returns {string}
 */
function rowsToCSV(rows) {
    return rows.map(row => row.map(escapeCSV).join(",")).join("\r\n") + "\r\n";
}

export {
    escapeCSV,
    rowsToCSV,
};
