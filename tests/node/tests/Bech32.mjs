/**
 * Bech32 library tests.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import assert from "assert";
import TestRegister from "../../lib/TestRegister.mjs";
import { parse } from "../../../src/core/lib/Bech32.mjs";

TestRegister.addApiTests([
    {
        name: "Bech32 parse: valid Bech32 metadata",
        run() {
            assert.deepStrictEqual(parse("bc1gyufle22"), {
                hrp: "bc",
                dataWords: [8, 4],
                checksumWords: [28, 9, 31, 25, 10, 10],
                checksumEncoding: "Bech32",
                checksumValid: true
            });
        }
    },
    {
        name: "Bech32 parse: valid Bech32m metadata",
        run() {
            assert.deepStrictEqual(parse("bc1gyf4040g"), {
                hrp: "bc",
                dataWords: [8, 4],
                checksumWords: [9, 21, 15, 21, 15, 8],
                checksumEncoding: "Bech32m",
                checksumValid: true
            });
        }
    },
    {
        name: "Bech32 parse: invalid checksum remains inspectable",
        run() {
            assert.deepStrictEqual(parse("bc1gyufle2q"), {
                hrp: "bc",
                dataWords: [8, 4],
                checksumWords: [28, 9, 31, 25, 10, 0],
                checksumEncoding: null,
                checksumValid: false
            });
        }
    },
    {
        name: "Bech32 parse: structural errors still throw",
        run() {
            assert.throws(
                () => parse("bc1gyufle2!"),
                /Invalid character '!' at position 10\./
            );
        }
    }
]);
