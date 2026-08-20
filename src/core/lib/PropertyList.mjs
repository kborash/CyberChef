/**
 * Apple property list parsers and formatters.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";
import {rowsToCSV} from "./DFIRStructuredOutput.mjs";

const MAX_DEPTH = 256;
const APPLE_EPOCH = Date.UTC(2001, 0, 1);

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
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
 * @param {string} value
 * @returns {Uint8Array}
 */
function base64ToBytes(value) {
    const compact = value.replace(/\s/g, "");
    if (!/^(?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{2}==|[A-Za-z\d+/]{3}=)?$/.test(compact))
        throw new OperationError("Invalid Base64 data in property list.");

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const output = [];
    for (let i = 0; i < compact.length; i += 4) {
        const a = alphabet.indexOf(compact[i]);
        const b = alphabet.indexOf(compact[i + 1]);
        const c = compact[i + 2] === "=" ? 0 : alphabet.indexOf(compact[i + 2]);
        const d = compact[i + 3] === "=" ? 0 : alphabet.indexOf(compact[i + 3]);
        output.push((a << 2) | (b >>> 4));
        if (compact[i + 2] !== "=") output.push(((b & 15) << 4) | (c >>> 2));
        if (compact[i + 3] !== "=") output.push(((c & 3) << 6) | d);
    }
    return new Uint8Array(output);
}

/**
 * @param {string} type
 * @param {Object} fields
 * @returns {Object}
 */
function typedValue(type, fields) {
    return Object.assign(Object.create(null), {$plistType: type}, fields);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function unsignedBytesToDecimal(bytes) {
    let decimal = "0";
    for (const byte of bytes) {
        let carry = byte;
        let next = "";
        for (let i = decimal.length - 1; i >= 0; i--) {
            const value = Number(decimal[i]) * 256 + carry;
            next = (value % 10).toString() + next;
            carry = Math.floor(value / 10);
        }
        while (carry) {
            next = (carry % 10).toString() + next;
            carry = Math.floor(carry / 10);
        }
        decimal = next.replace(/^0+(?=\d)/, "");
    }
    return decimal;
}

/**
 * @param {Uint8Array} bytes
 * @returns {number|string}
 */
function readUnsigned(bytes) {
    let value = 0;
    for (const byte of bytes) value = value * 256 + byte;
    return Number.isSafeInteger(value) ? value : unsignedBytesToDecimal(bytes);
}

/**
 * @param {Uint8Array} bytes
 * @returns {number|string}
 */
function readSigned(bytes) {
    if (!(bytes[0] & 0x80)) return readUnsigned(bytes);

    const magnitude = Uint8Array.from(bytes, byte => byte ^ 0xff);
    for (let i = magnitude.length - 1; i >= 0; i--) {
        const next = magnitude[i] + 1;
        magnitude[i] = next & 0xff;
        if (next <= 0xff) break;
    }
    const decimal = unsignedBytesToDecimal(magnitude);
    const number = -Number(decimal);
    return Number.isSafeInteger(number) ? number : `-${decimal}`;
}

/**
 * @param {number|string} value
 * @returns {*}
 */
function wrapInteger(value) {
    return typeof value === "string" ? typedValue("integer", {value}) : value;
}

/**
 * @param {number} milliseconds
 * @returns {Object}
 */
function wrapDate(milliseconds) {
    if (!Number.isFinite(milliseconds) || milliseconds < -8640000000000000 || milliseconds > 8640000000000000)
        throw new OperationError("Property list date is outside the supported range.");
    return typedValue("date", {value: new Date(milliseconds).toISOString()});
}

/**
 * Binary property list parser.
 */
class BinaryPropertyListParser {

    /**
     * @param {Uint8Array} bytes
     */
    constructor(bytes) {
        this.bytes = bytes;
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        this.cache = new Map();
        this.active = new Set();
    }

    /**
     * @returns {*}
     */
    parse() {
        if (this.bytes.length < 40 || new TextDecoder().decode(this.bytes.subarray(0, 8)) !== "bplist00")
            throw new OperationError("Invalid or unsupported binary property list header.");

        const trailer = this.bytes.length - 32;
        this.offsetSize = this.bytes[trailer + 6];
        this.refSize = this.bytes[trailer + 7];
        this.objectCount = this.readSafeUnsigned(trailer + 8, 8, "object count");
        this.topObject = this.readSafeUnsigned(trailer + 16, 8, "top object");
        this.offsetTableOffset = this.readSafeUnsigned(trailer + 24, 8, "offset table");

        if (this.offsetSize < 1 || this.offsetSize > 8 || this.refSize < 1 || this.refSize > 8)
            throw new OperationError("Invalid binary property list integer sizes.");
        if (this.objectCount < 1 || this.objectCount > this.bytes.length || this.topObject >= this.objectCount)
            throw new OperationError("Invalid binary property list object table metadata.");
        if (this.offsetTableOffset < 8 || this.offsetTableOffset + this.objectCount * this.offsetSize > trailer)
            throw new OperationError("Binary property list offset table is outside the input.");

        this.offsets = [];
        for (let i = 0; i < this.objectCount; i++) {
            const offset = this.readSafeUnsigned(this.offsetTableOffset + i * this.offsetSize, this.offsetSize, "object offset");
            if (offset < 8 || offset >= this.offsetTableOffset)
                throw new OperationError(`Binary property list object ${i} has an invalid offset.`);
            this.offsets.push(offset);
        }
        return this.parseObject(this.topObject, 0);
    }

    /**
     * @param {number} offset
     * @param {number} length
     * @param {string} field
     * @returns {number}
     */
    readSafeUnsigned(offset, length, field) {
        this.requireRange(offset, length);
        const value = readUnsigned(this.bytes.subarray(offset, offset + length));
        if (typeof value === "string") throw new OperationError(`Binary property list ${field} is too large.`);
        return value;
    }

    /**
     * @param {number} offset
     * @param {number} length
     */
    requireRange(offset, length) {
        if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > this.bytes.length)
            throw new OperationError("Truncated binary property list object.");
    }

    /**
     * @param {number} offset
     * @param {number} info
     * @returns {Object}
     */
    readLength(offset, info) {
        if (info !== 0x0f) return {length: info, payloadOffset: offset + 1};
        this.requireRange(offset + 1, 1);
        const marker = this.bytes[offset + 1];
        if ((marker >>> 4) !== 1) throw new OperationError("Invalid extended binary property list length.");
        const byteLength = 2 ** (marker & 0x0f);
        if (byteLength > 8) throw new OperationError("Binary property list length is too large.");
        const length = this.readSafeUnsigned(offset + 2, byteLength, "object length");
        return {length, payloadOffset: offset + 2 + byteLength};
    }

    /**
     * @param {number} offset
     * @returns {number}
     */
    readReference(offset) {
        const reference = this.readSafeUnsigned(offset, this.refSize, "object reference");
        if (reference >= this.objectCount) throw new OperationError("Binary property list reference is outside the object table.");
        return reference;
    }

    /**
     * @param {number} index
     * @param {number} depth
     * @returns {*}
     */
    parseObject(index, depth) {
        if (depth > MAX_DEPTH) throw new OperationError("Property list nesting exceeds the supported limit.");
        if (this.active.has(index)) throw new OperationError("Binary property list contains a reference cycle.");
        if (this.cache.has(index)) return this.cache.get(index);
        this.active.add(index);

        const offset = this.offsets[index];
        this.requireRange(offset, 1);
        const marker = this.bytes[offset];
        const type = marker >>> 4;
        const info = marker & 0x0f;
        let value;

        if (type === 0) {
            if (info === 0) value = null;
            else if (info === 8) value = false;
            else if (info === 9) value = true;
            else throw new OperationError(`Unsupported binary property list simple object 0x${info.toString(16)}.`);
        } else if (type === 1) {
            const length = 2 ** info;
            this.requireRange(offset + 1, length);
            value = wrapInteger(readSigned(this.bytes.subarray(offset + 1, offset + 1 + length)));
        } else if (type === 2) {
            const length = 2 ** info;
            this.requireRange(offset + 1, length);
            if (length === 4) value = this.view.getFloat32(offset + 1, false);
            else if (length === 8) value = this.view.getFloat64(offset + 1, false);
            else throw new OperationError("Unsupported binary property list real size.");
        } else if (type === 3) {
            if (info !== 3) throw new OperationError("Invalid binary property list date object.");
            this.requireRange(offset + 1, 8);
            value = wrapDate(APPLE_EPOCH + this.view.getFloat64(offset + 1, false) * 1000);
        } else if (type === 4 || type === 5 || type === 6) {
            const lengthInfo = this.readLength(offset, info);
            const byteLength = type === 6 ? lengthInfo.length * 2 : lengthInfo.length;
            this.requireRange(lengthInfo.payloadOffset, byteLength);
            const data = this.bytes.subarray(lengthInfo.payloadOffset, lengthInfo.payloadOffset + byteLength);
            if (type === 4) value = typedValue("data", {base64: bytesToBase64(data)});
            else if (type === 5) value = new TextDecoder("ascii").decode(data);
            else {
                let text = "";
                for (let i = 0; i < data.length; i += 2) text += String.fromCharCode((data[i] << 8) | data[i + 1]);
                value = text;
            }
        } else if (type === 8) {
            const length = info + 1;
            this.requireRange(offset + 1, length);
            value = typedValue("uid", {value: readUnsigned(this.bytes.subarray(offset + 1, offset + 1 + length))});
        } else if (type === 0x0a || type === 0x0b || type === 0x0c) {
            const lengthInfo = this.readLength(offset, info);
            this.requireRange(lengthInfo.payloadOffset, lengthInfo.length * this.refSize);
            value = [];
            this.cache.set(index, value);
            for (let i = 0; i < lengthInfo.length; i++)
                value.push(this.parseObject(this.readReference(lengthInfo.payloadOffset + i * this.refSize), depth + 1));
        } else if (type === 0x0d) {
            const lengthInfo = this.readLength(offset, info);
            const referencesLength = lengthInfo.length * this.refSize * 2;
            this.requireRange(lengthInfo.payloadOffset, referencesLength);
            value = Object.create(null);
            this.cache.set(index, value);
            const valuesOffset = lengthInfo.payloadOffset + lengthInfo.length * this.refSize;
            for (let i = 0; i < lengthInfo.length; i++) {
                const key = this.parseObject(this.readReference(lengthInfo.payloadOffset + i * this.refSize), depth + 1);
                if (typeof key !== "string") throw new OperationError("Binary property list dictionary key is not a string.");
                if (Object.prototype.hasOwnProperty.call(value, key)) throw new OperationError(`Duplicate property list dictionary key: ${key}`);
                value[key] = this.parseObject(this.readReference(valuesOffset + i * this.refSize), depth + 1);
            }
        } else {
            throw new OperationError(`Unsupported binary property list object type 0x${type.toString(16)}.`);
        }

        this.active.delete(index);
        this.cache.set(index, value);
        return value;
    }
}

/**
 * @param {string} text
 * @returns {string}
 */
function decodeXMLEntities(text) {
    if (/&(?!#(?:x[\da-f]+|\d+);|(?:amp|lt|gt|quot|apos);)/i.test(text))
        throw new OperationError("Invalid or unsupported XML entity in property list.");
    return text.replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (match, entity) => {
        const names = {amp: "&", lt: "<", gt: ">", quot: '"', apos: "'"};
        if (entity[0] !== "#") return names[entity.toLowerCase()];
        const value = entity[1].toLowerCase() === "x" ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
        if (!Number.isFinite(value) || value > 0x10ffff || value === 0 || (value >= 0xd800 && value <= 0xdfff))
            throw new OperationError("Invalid XML character entity in property list.");
        return String.fromCodePoint(value);
    });
}

/**
 * XML property list parser.
 */
class XMLPropertyListParser {

    /**
     * @param {string} text
     */
    constructor(text) {
        if (/<!ENTITY/i.test(text)) throw new OperationError("XML property list entity declarations are not supported.");
        this.tokens = text.match(/<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<[^>]+>|[^<]+/g) || [];
        this.position = 0;
    }

    /**
     * @returns {*}
     */
    parse() {
        this.skipIgnored();
        const open = this.takeTag();
        if (!/^<plist(?:\s[^>]*)?>$/i.test(open)) throw new OperationError("XML property list does not contain a plist root element.");
        const value = this.parseElement(0);
        this.skipWhitespace();
        if (this.takeTag().toLowerCase() !== "</plist>") throw new OperationError("XML property list is missing its closing plist tag.");
        this.skipIgnored();
        if (this.position !== this.tokens.length) throw new OperationError("Unexpected data after XML property list.");
        return value;
    }

    /** Skip declarations, comments and whitespace. */
    skipIgnored() {
        while (this.position < this.tokens.length) {
            const token = this.tokens[this.position];
            if (/^\s*$/.test(token) || /^<\?|^<!--|^<!DOCTYPE/i.test(token)) this.position++;
            else break;
        }
    }

    /** Skip whitespace text nodes. */
    skipWhitespace() {
        while (this.position < this.tokens.length && /^\s*$/.test(this.tokens[this.position])) this.position++;
    }

    /**
     * @returns {string}
     */
    takeTag() {
        this.skipWhitespace();
        const token = this.tokens[this.position++];
        if (!token || token[0] !== "<") throw new OperationError("Expected an XML property list element.");
        return token;
    }

    /**
     * @param {string} name
     * @returns {string}
     */
    readTextElement(name) {
        let text = "";
        while (this.position < this.tokens.length && this.tokens[this.position].toLowerCase() !== `</${name}>`) {
            const token = this.tokens[this.position++];
            if (token[0] === "<") throw new OperationError(`Unexpected element inside plist ${name}.`);
            text += token;
        }
        if (this.position >= this.tokens.length) throw new OperationError(`Unclosed plist ${name} element.`);
        this.position++;
        return decodeXMLEntities(text);
    }

    /**
     * @param {number} depth
     * @returns {*}
     */
    parseElement(depth) {
        if (depth > MAX_DEPTH) throw new OperationError("Property list nesting exceeds the supported limit.");
        const tag = this.takeTag().toLowerCase();
        if (tag === "<true/>") return true;
        if (tag === "<false/>") return false;
        if (tag === "<string/>") return "";
        if (tag === "<data/>") return typedValue("data", {base64: ""});
        if (tag === "<array/>") return [];
        if (tag === "<dict/>") return Object.create(null);
        if (tag === "<string>") return this.readTextElement("string");
        if (tag === "<integer>") {
            const text = this.readTextElement("integer").trim();
            if (!/^[+-]?(?:\d+|0x[\da-f]+)$/i.test(text)) throw new OperationError("Invalid integer in XML property list.");
            const number = text.toLowerCase().includes("0x") ? parseInt(text, 16) : Number(text);
            return Number.isSafeInteger(number) ? number : typedValue("integer", {value: text});
        }
        if (tag === "<real>") {
            const value = Number(this.readTextElement("real").trim());
            if (!Number.isFinite(value)) throw new OperationError("Invalid real number in XML property list.");
            return value;
        }
        if (tag === "<date>") {
            const value = this.readTextElement("date").trim();
            const milliseconds = Date.parse(value);
            if (!Number.isFinite(milliseconds)) throw new OperationError("Invalid date in XML property list.");
            return wrapDate(milliseconds);
        }
        if (tag === "<data>") {
            const data = base64ToBytes(this.readTextElement("data"));
            return typedValue("data", {base64: bytesToBase64(data)});
        }
        if (tag === "<array>") {
            const array = [];
            while (true) {
                this.skipWhitespace();
                if ((this.tokens[this.position] || "").toLowerCase() === "</array>") {
                    this.position++;
                    return array;
                }
                array.push(this.parseElement(depth + 1));
            }
        }
        if (tag === "<dict>") {
            const dictionary = Object.create(null);
            while (true) {
                this.skipWhitespace();
                if ((this.tokens[this.position] || "").toLowerCase() === "</dict>") {
                    this.position++;
                    return dictionary;
                }
                const keyTag = this.takeTag().toLowerCase();
                if (keyTag !== "<key>" && keyTag !== "<key/>") throw new OperationError("Expected a key in XML property list dictionary.");
                const key = keyTag === "<key/>" ? "" : this.readTextElement("key");
                if (Object.prototype.hasOwnProperty.call(dictionary, key)) throw new OperationError(`Duplicate property list dictionary key: ${key}`);
                dictionary[key] = this.parseElement(depth + 1);
            }
        }
        throw new OperationError(`Unsupported XML property list element: ${tag}`);
    }
}

/**
 * OpenStep property list parser.
 */
class OpenStepPropertyListParser {

    /**
     * @param {string} text
     */
    constructor(text) {
        this.text = text;
        this.position = 0;
    }

    /**
     * @returns {*}
     */
    parse() {
        this.skipIgnored();
        if (this.peek() === "{" || this.peek() === "(") {
            const value = this.parseValue(0);
            this.skipIgnored();
            if (this.position !== this.text.length) throw this.error("Unexpected trailing input");
            return value;
        }

        const dictionary = Object.create(null);
        while (this.position < this.text.length) {
            const key = this.parseStringValue();
            this.skipIgnored();
            let value = key;
            if (this.peek() === "=") {
                this.position++;
                value = this.parseValue(1);
            }
            this.skipIgnored();
            this.expect(";");
            if (Object.prototype.hasOwnProperty.call(dictionary, key)) throw this.error(`Duplicate dictionary key: ${key}`);
            dictionary[key] = value;
            this.skipIgnored();
        }
        return dictionary;
    }

    /**
     * @param {string} message
     * @returns {OperationError}
     */
    error(message) {
        return new OperationError(`${message} at OpenStep plist offset ${this.position}.`);
    }

    /** Skip whitespace and C/C++ comments. */
    skipIgnored() {
        while (this.position < this.text.length) {
            if (/\s/.test(this.text[this.position])) {
                this.position++;
            } else if (this.text.startsWith("//", this.position)) {
                const end = this.text.indexOf("\n", this.position + 2);
                this.position = end < 0 ? this.text.length : end + 1;
            } else if (this.text.startsWith("/*", this.position)) {
                const end = this.text.indexOf("*/", this.position + 2);
                if (end < 0) throw this.error("Unclosed comment");
                this.position = end + 2;
            } else break;
        }
    }

    /**
     * @returns {string}
     */
    peek() {
        this.skipIgnored();
        return this.text[this.position];
    }

    /**
     * @param {string} character
     */
    expect(character) {
        this.skipIgnored();
        if (this.text[this.position] !== character) throw this.error(`Expected '${character}'`);
        this.position++;
    }

    /**
     * @param {number} depth
     * @returns {*}
     */
    parseValue(depth) {
        if (depth > MAX_DEPTH) throw this.error("Property list nesting exceeds the supported limit");
        const character = this.peek();
        if (character === "{") return this.parseDictionary(depth);
        if (character === "(") return this.parseArray(depth);
        if (character === "<") return this.parseData();
        return this.parseStringValue();
    }

    /**
     * @param {number} depth
     * @returns {Object}
     */
    parseDictionary(depth) {
        this.expect("{");
        const dictionary = Object.create(null);
        while (this.peek() !== "}") {
            if (this.position >= this.text.length) throw this.error("Unclosed dictionary");
            const key = this.parseStringValue();
            this.expect("=");
            const value = this.parseValue(depth + 1);
            this.expect(";");
            if (Object.prototype.hasOwnProperty.call(dictionary, key)) throw this.error(`Duplicate dictionary key: ${key}`);
            dictionary[key] = value;
        }
        this.position++;
        return dictionary;
    }

    /**
     * @param {number} depth
     * @returns {Array}
     */
    parseArray(depth) {
        this.expect("(");
        const array = [];
        while (this.peek() !== ")") {
            if (this.position >= this.text.length) throw this.error("Unclosed array");
            array.push(this.parseValue(depth + 1));
            this.skipIgnored();
            if (this.peek() === ",") this.position++;
            else if (this.peek() !== ")") throw this.error("Expected ',' or ')' in array");
        }
        this.position++;
        return array;
    }

    /**
     * @returns {Object}
     */
    parseData() {
        this.expect("<");
        const end = this.text.indexOf(">", this.position);
        if (end < 0) throw this.error("Unclosed data value");
        const hex = this.text.slice(this.position, end).replace(/\s/g, "");
        if (!/^(?:[\da-f]{2})*$/i.test(hex)) throw this.error("Invalid hexadecimal data");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        this.position = end + 1;
        return typedValue("data", {base64: bytesToBase64(bytes)});
    }

    /**
     * @returns {string}
     */
    parseStringValue() {
        this.skipIgnored();
        if (this.text[this.position] !== '"') {
            const start = this.position;
            while (this.position < this.text.length && !/[\s,;=(){}<>]/.test(this.text[this.position])) this.position++;
            if (start === this.position) throw this.error("Expected a string");
            return this.text.slice(start, this.position);
        }

        this.position++;
        let output = "";
        while (this.position < this.text.length) {
            const character = this.text[this.position++];
            if (character === '"') return output;
            if (character !== "\\") {
                output += character;
                continue;
            }
            if (this.position >= this.text.length) throw this.error("Unclosed quoted string");
            const escape = this.text[this.position++];
            const simple = {n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", "\\": "\\", '"': '"'};
            if (Object.prototype.hasOwnProperty.call(simple, escape)) output += simple[escape];
            else if (escape === "U" || escape === "u") {
                const hex = this.text.slice(this.position, this.position + 4);
                if (!/^[\da-f]{4}$/i.test(hex)) throw this.error("Invalid Unicode escape");
                output += String.fromCharCode(parseInt(hex, 16));
                this.position += 4;
            } else if (/[0-7]/.test(escape)) {
                let octal = escape;
                while (octal.length < 3 && /[0-7]/.test(this.text[this.position] || "")) octal += this.text[this.position++];
                output += String.fromCharCode(parseInt(octal, 8));
            } else output += escape;
        }
        throw this.error("Unclosed quoted string");
    }
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function decodeTextPlist(bytes) {
    if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe)
        return new TextDecoder("utf-16le").decode(bytes.subarray(2));
    if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
        let output = "";
        for (let i = 2; i + 1 < bytes.length; i += 2) output += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
        return output;
    }
    const start = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
    const text = new TextDecoder("utf-8", {fatal: true}).decode(bytes.subarray(start));
    const encoding = text.match(/<\?xml[^>]*encoding=["']([^"']+)/i);
    if (encoding && !/^utf-?8$/i.test(encoding[1]))
        throw new OperationError(`Unsupported XML property list encoding: ${encoding[1]}.`);
    return text;
}

/**
 * Parses an Apple property list.
 *
 * @param {ArrayBuffer} input
 * @returns {Object}
 */
function parsePropertyList(input) {
    const bytes = new Uint8Array(input);
    if (!bytes.length) throw new OperationError("Property list input is empty.");
    const header = new TextDecoder("ascii").decode(bytes.subarray(0, 8));
    if (header.startsWith("bplist")) {
        return {format: "Binary", value: new BinaryPropertyListParser(bytes).parse()};
    }

    let text;
    try {
        text = decodeTextPlist(bytes);
    } catch (error) {
        if (error instanceof OperationError) throw error;
        throw new OperationError("Property list text is not valid UTF-8 or UTF-16.");
    }
    const trimmed = text.trimStart();
    if (/^(?:<\?xml|<!DOCTYPE|<plist)/i.test(trimmed))
        return {format: "XML", value: new XMLPropertyListParser(text).parse()};
    return {format: "OpenStep", value: new OpenStepPropertyListParser(text).parse()};
}

/**
 * @param {*} value
 * @returns {string}
 */
function valueType(value) {
    if (value && typeof value === "object" && value.$plistType) return value.$plistType;
    if (Array.isArray(value)) return "array";
    if (value === null) return "null";
    if (typeof value === "object") return "dictionary";
    return typeof value;
}

/**
 * @param {*} value
 * @returns {string|number|boolean}
 */
function scalarValue(value) {
    if (value && value.$plistType === "data") return value.base64;
    if (value && value.$plistType) return value.value;
    if (value === null) return "";
    return value;
}

/**
 * @param {*} value
 * @param {string} path
 * @param {Array[]} rows
 */
function flattenPropertyList(value, path, rows) {
    const type = valueType(value);
    if (type === "array") {
        rows.push([path, type, value.length]);
        value.forEach((item, index) => flattenPropertyList(item, `${path}[${index}]`, rows));
    } else if (type === "dictionary") {
        const keys = Object.keys(value);
        rows.push([path, type, keys.length]);
        keys.forEach(key => {
            const childPath = /^[A-Za-z_$][\w$]*$/.test(key) ? `${path}.${key}` : `${path}[${JSON.stringify(key)}]`;
            flattenPropertyList(value[key], childPath, rows);
        });
    } else {
        rows.push([path, type, scalarValue(value)]);
    }
}

/**
 * Formats a parsed property list.
 *
 * @param {Object} parsed
 * @param {string} outputFormat
 * @returns {string}
 */
function formatPropertyList(parsed, outputFormat) {
    if (outputFormat !== "CSV") return JSON.stringify(parsed.value, null, 4);
    const rows = [["path", "type", "value"]];
    flattenPropertyList(parsed.value, "$", rows);
    return rowsToCSV(rows);
}

export {
    formatPropertyList,
    parsePropertyList,
};
