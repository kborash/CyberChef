/**
 * MBOX metadata parser.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";
import {rowsToCSV} from "./DFIRStructuredOutput.mjs";

const MAX_MESSAGES = 100000;
const MAX_HEADER_LINES = 10000;
const MAX_HEADER_LENGTH = 1024 * 1024;
const CSV_HEADERS = [
    "messageIndex",
    "envelopeFrom",
    "envelopeDate",
    "from",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "returnPath",
    "subject",
    "date",
    "messageId",
    "senderIp",
    "senderIpSource",
    "receivedCount",
];

/**
 * @param {string} value
 * @returns {Uint8Array|null}
 */
function decodeBase64(value) {
    if (!/^(?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{2}==|[A-Za-z\d+/]{3}=)?$/.test(value)) return null;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const output = [];
    for (let i = 0; i < value.length; i += 4) {
        const a = alphabet.indexOf(value[i]);
        const b = alphabet.indexOf(value[i + 1]);
        const c = value[i + 2] === "=" ? 0 : alphabet.indexOf(value[i + 2]);
        const d = value[i + 3] === "=" ? 0 : alphabet.indexOf(value[i + 3]);
        output.push((a << 2) | (b >>> 4));
        if (value[i + 2] !== "=") output.push(((b & 15) << 4) | (c >>> 2));
        if (value[i + 3] !== "=") output.push(((c & 3) << 6) | d);
    }
    return new Uint8Array(output);
}

/**
 * @param {string} value
 * @returns {Uint8Array|null}
 */
function decodeQuotedPrintableWord(value) {
    const output = [];
    for (let i = 0; i < value.length; i++) {
        if (value[i] === "_") {
            output.push(0x20);
        } else if (value[i] === "=" && /^[\da-f]{2}$/i.test(value.slice(i + 1, i + 3))) {
            output.push(parseInt(value.slice(i + 1, i + 3), 16));
            i += 2;
        } else {
            const code = value.charCodeAt(i);
            if (code > 0x7f) return null;
            output.push(code);
        }
    }
    return new Uint8Array(output);
}

/**
 * Decodes common RFC 2047 encoded words while preserving malformed values.
 *
 * @param {string} value
 * @returns {string}
 */
function decodeEncodedWords(value) {
    const joined = value.replace(/(\?=)\s+(?==\?)/g, "$1");
    return joined.replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (match, charset, encoding, encoded) => {
        const bytes = encoding.toLowerCase() === "b" ? decodeBase64(encoded) : decodeQuotedPrintableWord(encoded);
        if (!bytes) return match;
        try {
            return new TextDecoder(charset.trim(), {fatal: true}).decode(bytes);
        } catch (error) {
            return match;
        }
    });
}

/**
 * @param {string[]} lines
 * @returns {Map<string, string[]>}
 */
function parseHeaders(lines) {
    const unfolded = [];
    for (const line of lines) {
        if (/^[ \t]/.test(line) && unfolded.length) {
            unfolded[unfolded.length - 1] += ` ${line.trim()}`;
        } else {
            unfolded.push(line);
        }
    }

    const headers = new Map();
    for (const line of unfolded) {
        const separator = line.indexOf(":");
        if (separator < 1) continue;
        const name = line.slice(0, separator).trim().toLowerCase();
        if (!/^[!-9;-~]+$/.test(name)) continue;
        const value = decodeEncodedWords(line.slice(separator + 1).trim());
        const existing = headers.get(name);
        if (existing) existing.push(value);
        else headers.set(name, [value]);
    }
    return headers;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isIPv4(value) {
    const parts = value.split(".");
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isIPv6(value) {
    const doubleColon = value.indexOf("::");
    if (doubleColon !== value.lastIndexOf("::")) return false;
    const halves = doubleColon < 0 ? [value] : [value.slice(0, doubleColon), value.slice(doubleColon + 2)];
    let groups = 0;
    for (const half of halves) {
        if (!half) continue;
        const parts = half.split(":");
        for (let i = 0; i < parts.length; i++) {
            const part = parts[i];
            if (part.includes(".")) {
                if (i !== parts.length - 1 || !isIPv4(part)) return false;
                groups += 2;
            } else {
                if (!/^[\da-f]{1,4}$/i.test(part)) return false;
                groups++;
            }
        }
    }
    return doubleColon < 0 ? groups === 8 : groups < 8;
}

/**
 * @param {string} value
 * @returns {string|null}
 */
function extractIp(value) {
    const bracketed = value.matchAll(/\[(?:IPv6:)?([\da-f:.]+)\]/gi);
    for (const match of bracketed) {
        if (isIPv4(match[1]) || isIPv6(match[1])) return match[1];
    }

    const ipv4 = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const candidate of ipv4) {
        if (isIPv4(candidate)) return candidate;
    }

    const ipv6 = value.match(/(?:[\da-f]{1,4}:){2,}[\da-f:.]*/gi) || [];
    for (const candidate of ipv6) {
        if (isIPv6(candidate)) return candidate;
    }
    return null;
}

/**
 * @param {Map<string, string[]>} headers
 * @returns {{value: string, source: string}|null}
 */
function findSenderIp(headers) {
    const explicitHeaders = ["x-originating-ip", "x-sender-ip", "x-source-ip", "x-client-ip"];
    for (const name of explicitHeaders) {
        for (const value of headers.get(name) || []) {
            const ip = extractIp(value);
            if (ip) return {value: ip, source: name};
        }
    }

    const received = headers.get("received") || [];
    for (let i = received.length - 1; i >= 0; i--) {
        const ip = extractIp(received[i]);
        if (ip) return {value: ip, source: `received[${i + 1}]`};
    }
    return null;
}

/**
 * @param {Map<string, string[]>} headers
 * @param {string} name
 * @returns {string}
 */
function headerValue(headers, name) {
    return (headers.get(name) || []).join("; ");
}

/**
 * @param {Object} message
 * @param {number} index
 * @returns {Object}
 */
function messageMetadata(message, index) {
    const headers = parseHeaders(message.headerLines);
    const senderIp = findSenderIp(headers);
    return {
        messageIndex: index,
        envelopeFrom: message.envelopeFrom,
        envelopeDate: message.envelopeDate,
        from: headerValue(headers, "from"),
        to: headerValue(headers, "to"),
        cc: headerValue(headers, "cc"),
        bcc: headerValue(headers, "bcc"),
        replyTo: headerValue(headers, "reply-to"),
        returnPath: headerValue(headers, "return-path"),
        subject: headerValue(headers, "subject"),
        date: headerValue(headers, "date"),
        messageId: headerValue(headers, "message-id"),
        senderIp: senderIp ? senderIp.value : "",
        senderIpSource: senderIp ? senderIp.source : "",
        receivedCount: (headers.get("received") || []).length,
    };
}

/**
 * Parses metadata from each message in an MBOX mailbox.
 *
 * @param {ArrayBuffer} input
 * @param {string} encoding
 * @returns {Object[]}
 */
function parseMbox(input, encoding) {
    let text;
    try {
        text = new TextDecoder(encoding || "utf-8", {fatal: false}).decode(input);
    } catch (error) {
        throw new OperationError(`Unsupported MBOX input encoding: ${encoding}.`);
    }

    const messages = [];
    let current = null;
    let inHeaders = false;
    let headerLength = 0;

    const finishMessage = () => {
        if (!current) return;
        messages.push(messageMetadata(current, messages.length));
        if (messages.length > MAX_MESSAGES) throw new OperationError(`MBOX contains more than ${MAX_MESSAGES} messages.`);
    };

    for (const line of text.split(/\r\n|\n|\r/)) {
        const separator = line.match(/^From\s+(\S+)\s+(.+\b\d{1,2}:\d{2}(?::\d{2})?\b.*\b\d{4}\b.*)$/);
        if (separator) {
            finishMessage();
            current = {envelopeFrom: separator[1], envelopeDate: separator[2], headerLines: []};
            inHeaders = true;
            headerLength = 0;
            continue;
        }
        if (!current || !inHeaders) continue;
        if (line === "") {
            inHeaders = false;
            continue;
        }
        current.headerLines.push(line);
        headerLength += line.length;
        if (current.headerLines.length > MAX_HEADER_LINES || headerLength > MAX_HEADER_LENGTH)
            throw new OperationError("MBOX message header exceeds the supported size limit.");
    }
    finishMessage();

    if (!messages.length) throw new OperationError("No MBOX message separators were found.");
    return messages;
}

/**
 * @param {Object[]} messages
 * @returns {string}
 */
function formatMboxCsv(messages) {
    return rowsToCSV([
        CSV_HEADERS,
        ...messages.map(message => CSV_HEADERS.map(header => message[header])),
    ]);
}

export {
    formatMboxCsv,
    parseMbox,
};
