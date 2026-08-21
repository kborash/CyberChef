/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import {inspectCryptocurrencyData} from "../lib/Cryptocurrency.mjs";

/**
 * Cryptocurrency Identifier and Address Inspector operation.
 */
class CryptocurrencyIdentifierAndAddressInspector extends Operation {

    /** CryptocurrencyIdentifierAndAddressInspector constructor. */
    constructor() {
        super();

        this.name = "Cryptocurrency Identifier and Address Inspector";
        this.module = "Cryptocurrency";
        this.description = "Identifies, validates, decodes, and explains supported cryptocurrency addresses and related encodings entirely offline. Inspect a single identifier or scan raw bytes for candidates. Results distinguish decoded facts from currency and network interpretations, include validation diagnostics, and expose useful derived search values where possible.";
        this.infoURL = "https://wikipedia.org/wiki/Cryptocurrency_wallet";
        this.inputType = "ArrayBuffer";
        this.outputType = "JSON";
        this.presentType = "html";
        this.args = [
            {
                name: "Mode",
                type: "argSelector",
                value: [
                    {
                        name: "Inspect identifier",
                        off: [2],
                    },
                    {
                        name: "Scan bytes",
                        on: [2],
                    },
                ],
            },
            {
                name: "Detection",
                type: "option",
                value: ["Strict", "Loose"],
            },
            {
                name: "Maximum results",
                type: "number",
                value: 1000,
                min: 1,
                max: 10000,
                integer: true,
            },
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {Object}
     */
    run(input, args) {
        const [mode, detection, maxResults] = args;
        const normalisedMode = mode.toLowerCase();

        return inspectCryptocurrencyData(new Uint8Array(input), {
            mode: normalisedMode === "scan bytes" ? "scan" : "inspect",
            detection: detection.toLowerCase(),
            maxResults,
        });
    }

    /**
     * Renders the result envelope and each detected identifier as escaped tables.
     *
     * @param {Object|Object[]} data
     * @returns {html}
     */
    present(data) {
        const {envelope, results} = splitResults(data);
        let output = '<div class="cryptocurrency-identifier-inspector">' +
            "<h3>Inspection summary</h3>" +
            renderObjectTable(envelope) +
            "<h3>Results</h3>";

        if (results.length === 0) {
            output += "<p>No cryptocurrency identifiers detected.</p>";
        } else {
            results.forEach((result, index) => {
                output += `<h4>Result ${index + 1}</h4>`;
                output += isRecord(result) ? renderObjectTable(result) : renderValue(result);
            });
        }

        return output + "</div>";
    }
}

/**
 * Separates an inspection envelope from its results while tolerating direct results.
 *
 * @param {*} data
 * @returns {{envelope: Object, results: Array}}
 */
function splitResults(data) {
    if (Array.isArray(data)) {
        return {envelope: {}, results: data};
    }

    if (!isRecord(data)) {
        return {envelope: {}, results: data === undefined ? [] : [data]};
    }

    if (!Object.prototype.hasOwnProperty.call(data, "results")) {
        return {envelope: {}, results: [data]};
    }

    const envelope = {};
    sortedKeys(data).forEach(key => {
        if (key !== "results") envelope[key] = data[key];
    });

    const results = Array.isArray(data.results) ? data.results :
        data.results === null || data.results === undefined ? [] : [data.results];

    return {envelope, results};
}

/**
 * Renders an object's keys and values in stable key order.
 *
 * @param {Object} value
 * @returns {string}
 */
function renderObjectTable(value) {
    const keys = sortedKeys(value);
    if (keys.length === 0) return "<p>None</p>";

    let output = '<table class="table table-hover table-sm table-bordered"><tbody>';
    keys.forEach(key => {
        output += "<tr>" +
            `<th scope="row">${escapeValue(key)}</th>` +
            `<td>${renderValue(value[key])}</td>` +
            "</tr>";
    });
    return output + "</tbody></table>";
}

/**
 * Renders a JSON-compatible value without inserting unescaped data into HTML.
 *
 * @param {*} value
 * @returns {string}
 */
function renderValue(value) {
    if (value === null) return '<span class="text-muted">null</span>';
    if (value === undefined) return '<span class="text-muted">undefined</span>';

    if (Array.isArray(value)) {
        if (value.length === 0) return '<span class="text-muted">None</span>';

        return "<ol>" + value.map(item => `<li>${renderValue(item)}</li>`).join("") + "</ol>";
    }

    if (isRecord(value)) return renderObjectTable(value);

    return `<code>${escapeValue(value)}</code>`;
}

/**
 * @param {Object} value
 * @returns {string[]}
 */
function sortedKeys(value) {
    return Object.keys(value).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}

/**
 * @param {*} value
 * @returns {string}
 */
function escapeValue(value) {
    return Utils.escapeHtml(String(value));
}

/**
 * @param {*} value
 * @returns {boolean}
 */
function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

export default CryptocurrencyIdentifierAndAddressInspector;
