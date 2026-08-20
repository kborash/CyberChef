/**
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {knownHostsToHashcat} from "../lib/SSHKnownHosts.mjs";

/** Convert hashed OpenSSH known_hosts entries to Hashcat mode 160 input. */
class KnownHostsToHashcat extends Operation {

    /** KnownHostsToHashcat constructor. */
    constructor() {
        super();
        this.name = "Known hosts to Hashcat";
        this.module = "DFIR";
        this.description = "Converts hashed OpenSSH known_hosts entries (|1|salt|HMAC-SHA1) into digest:hex-salt records accepted by Hashcat mode 160. Comments and unhashed host entries are ignored.";
        this.infoURL = "https://hashcat.net/wiki/doku.php?id=example_hashes";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * @param {string} input
     * @returns {string}
     */
    run(input) {
        return knownHostsToHashcat(input);
    }
}

export default KnownHostsToHashcat;
