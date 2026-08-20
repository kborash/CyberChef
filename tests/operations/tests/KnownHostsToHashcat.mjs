/**
 * Tests for known_hosts to Hashcat conversion.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

TestRegister.addTests([
    {
        name: "Known hosts to Hashcat: converts hashed entries and ignores ordinary entries",
        input: [
            "# collected known_hosts",
            "example.org ssh-ed25519 AAAA",
            "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|ExIREA8ODQwLCgkIBwYFBAMCAQA= ssh-rsa AAAA",
            "@cert-authority |1|+/z7+vn49/b18/Py8fDv7u3s6+o=|AAECAwQFBgcICQoLDA0ODxAREhM= ssh-ed25519 AAAA",
        ].join("\n"),
        expectedOutput: [
            "131211100f0e0d0c0b0a09080706050403020100:000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f10111213:fbfcfbfaf9f8f7f6f5f3f3f2f1f0efeeedecebea",
        ].join("\n"),
        recipeConfig: [{op: "Known hosts to Hashcat", args: []}],
    },
    {
        name: "Known hosts to Hashcat: rejects unsupported hash versions",
        input: "|2|AAECAwQ=|AAECAwQFBgcICQoLDA0ODxAREhM= ssh-rsa AAAA",
        expectedOutput: "Unsupported known_hosts hash version on line 1: 2.",
        recipeConfig: [{op: "Known hosts to Hashcat", args: []}],
    },
    {
        name: "Known hosts to Hashcat: reports when no hashed entries exist",
        input: "example.org ssh-ed25519 AAAA",
        expectedOutput: "No hashed known_hosts entries were found.",
        recipeConfig: [{op: "Known hosts to Hashcat", args: []}],
    },
    {
        name: "Known hosts to Hashcat: validates the HMAC-SHA1 digest length",
        input: "|1|AAECAwQ=|AAECAwQ= ssh-rsa AAAA",
        expectedOutput: "Invalid hashed known_hosts entry on line 1: HMAC-SHA1 digest must be 20 bytes.",
        recipeConfig: [{op: "Known hosts to Hashcat", args: []}],
    },
]);
