/**
 * Tests for MBOX metadata extraction.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

/** @param {Uint8Array} bytes @returns {string} */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** @param {string} value @returns {string} */
function stringToHex(value) {
    return toHex(new TextEncoder().encode(value));
}

const mailbox = [
    "From jose@example.com Sat Jan  6 10:20:30 2024",
    "From: =?UTF-8?Q?Jos=C3=A9_Example?= <jose@example.com>",
    "To: Analyst <analyst@example.net>,",
    " Second Analyst <second@example.net>",
    "Subject: =?UTF-8?Q?Quarterly_=E2=9C=93?=",
    "Date: Sat, 6 Jan 2024 10:20:30 +0000",
    "Message-ID: <first@example.com>",
    "X-Originating-IP: [203.0.113.42]",
    "Received: from relay.example.net ([192.0.2.10]) by mx.example.net",
    "",
    "Body",
    ">From this line is escaped and is not a separator",
    "From second@example.org Sun Jan  7 11:22:33 2024",
    "From: Second Sender <second@example.org>",
    "To: recipient@example.net",
    "Cc: audit@example.net",
    "Reply-To: replies@example.org",
    "Return-Path: <bounce@example.org>",
    "Subject: A \"quoted\", subject",
    "Received: from newest.example ([10.0.0.2]) by destination.example",
    "Received: from source.example ([198.51.100.9]) by oldest-relay.example",
    "",
    "From not a separator",
].join("\n");

const expectedCsv = [
    "messageIndex,envelopeFrom,envelopeDate,from,to,cc,bcc,replyTo,returnPath,subject,date,messageId,senderIp,senderIpSource,receivedCount",
    '0,jose@example.com,Sat Jan  6 10:20:30 2024,José Example <jose@example.com>,"Analyst <analyst@example.net>, Second Analyst <second@example.net>",,,,,Quarterly ✓,"Sat, 6 Jan 2024 10:20:30 +0000",<first@example.com>,203.0.113.42,x-originating-ip,1',
    '1,second@example.org,Sun Jan  7 11:22:33 2024,Second Sender <second@example.org>,recipient@example.net,audit@example.net,,replies@example.org,<bounce@example.org>,"A ""quoted"", subject",,,198.51.100.9,received[2],2',
    "",
].join("\r\n");

const windowsMailbox = new Uint8Array([
    ...new TextEncoder().encode("From sender@example.com Mon Jan  8 01:02:03 2024\nFrom: Caf"),
    0xe9,
    ...new TextEncoder().encode(" <sender@example.com>\nSubject: Evidence\n\nBody\n"),
]);

TestRegister.addTests([
    {
        name: "Parse MBOX: exports decoded metadata and probable sender IPs",
        input: stringToHex(mailbox),
        expectedOutput: expectedCsv,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse MBOX", args: ["utf-8"]}],
    },
    {
        name: "Parse MBOX: supports legacy Windows-1252 headers",
        input: toHex(windowsMailbox),
        expectedMatch: /Café <sender@example\.com>/,
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse MBOX", args: ["windows-1252"]}],
    },
    {
        name: "Parse MBOX: rejects input without a mailbox separator",
        input: stringToHex("From: sender@example.com\nSubject: Not an MBOX\n"),
        expectedOutput: "No MBOX message separators were found.",
        recipeConfig: [{op: "From Hex", args: ["None"]}, {op: "Parse MBOX", args: ["utf-8"]}],
    },
]);
