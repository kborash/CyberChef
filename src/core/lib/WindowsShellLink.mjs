/**
 * Microsoft Shell Link (.LNK) parser.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";
import {rowsToCSV} from "./DFIRStructuredOutput.mjs";

const SHELL_LINK_CLSID = "00021401-0000-0000-c000-000000000046";
const LINK_FLAGS = {
    0x00000001: "HasLinkTargetIDList",
    0x00000002: "HasLinkInfo",
    0x00000004: "HasName",
    0x00000008: "HasRelativePath",
    0x00000010: "HasWorkingDir",
    0x00000020: "HasArguments",
    0x00000040: "HasIconLocation",
    0x00000080: "IsUnicode",
    0x00000100: "ForceNoLinkInfo",
    0x00000200: "HasExpString",
    0x00000400: "RunInSeparateProcess",
    0x00001000: "HasDarwinID",
    0x00002000: "RunAsUser",
    0x00004000: "HasExpIcon",
    0x00008000: "NoPidlAlias",
    0x00020000: "RunWithShimLayer",
    0x00040000: "ForceNoLinkTrack",
    0x00080000: "EnableTargetMetadata",
    0x00100000: "DisableLinkPathTracking",
    0x00200000: "DisableKnownFolderTracking",
    0x00400000: "DisableKnownFolderAlias",
    0x00800000: "AllowLinkToLink",
    0x01000000: "UnaliasOnSave",
    0x02000000: "PreferEnvironmentPath",
    0x04000000: "KeepLocalIDListForUNCTarget",
};

const FILE_ATTRIBUTES = {
    0x00000001: "ReadOnly",
    0x00000002: "Hidden",
    0x00000004: "System",
    0x00000010: "Directory",
    0x00000020: "Archive",
    0x00000040: "Device",
    0x00000080: "Normal",
    0x00000100: "Temporary",
    0x00000200: "SparseFile",
    0x00000400: "ReparsePoint",
    0x00000800: "Compressed",
    0x00001000: "Offline",
    0x00002000: "NotContentIndexed",
    0x00004000: "Encrypted",
};

const EXTRA_SIGNATURES = {
    0xa0000001: "EnvironmentVariableDataBlock",
    0xa0000002: "ConsoleDataBlock",
    0xa0000003: "TrackerDataBlock",
    0xa0000004: "ConsoleFEDataBlock",
    0xa0000005: "SpecialFolderDataBlock",
    0xa0000006: "DarwinDataBlock",
    0xa0000007: "IconEnvironmentDataBlock",
    0xa0000008: "ShimDataBlock",
    0xa0000009: "PropertyStoreDataBlock",
    0xa000000b: "KnownFolderDataBlock",
    0xa000000c: "VistaAndAboveIDListDataBlock",
};

const DRIVE_TYPES = ["Unknown", "NoRootDirectory", "Removable", "Fixed", "Remote", "CDROM", "RAMDisk"];

/**
 * @param {number} value
 * @returns {string}
 */
function hex32(value) {
    return `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {number} value
 * @param {Object} definitions
 * @returns {Object}
 */
function decodeFlags(value, definitions) {
    return {
        value: hex32(value),
        names: Object.keys(definitions)
            .map(Number)
            .filter(bit => (value & bit) !== 0)
            .map(bit => definitions[bit]),
    };
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function littleEndianBytesToDecimal(bytes) {
    let decimal = "0";
    for (let byteIndex = bytes.length - 1; byteIndex >= 0; byteIndex--) {
        let carry = bytes[byteIndex];
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
 * @returns {string}
 */
function guidFromBytes(bytes) {
    if (bytes.length !== 16) return null;
    return [
        toHex(bytes.subarray(0, 4).slice().reverse()),
        toHex(bytes.subarray(4, 6).slice().reverse()),
        toHex(bytes.subarray(6, 8).slice().reverse()),
        toHex(bytes.subarray(8, 10)),
        toHex(bytes.subarray(10, 16)),
    ].join("-");
}

/**
 * Parser for the Shell Link Binary File Format.
 */
class WindowsShellLinkParser {

    /**
     * @param {ArrayBuffer} input
     * @param {string} ansiEncoding
     */
    constructor(input, ansiEncoding) {
        this.bytes = new Uint8Array(input);
        this.view = new DataView(input);
        try {
            this.ansiDecoder = new TextDecoder(ansiEncoding || "windows-1252", {fatal: false});
        } catch (error) {
            throw new OperationError(`Unsupported ANSI encoding: ${ansiEncoding}.`);
        }
    }

    /**
     * @returns {Object}
     */
    parse() {
        this.requireRange(0, 76, "ShellLinkHeader");
        if (this.u32(0) !== 0x4c) throw new OperationError("Invalid LNK header size; expected 0x0000004c.");
        const clsid = guidFromBytes(this.bytes.subarray(4, 20));
        if (clsid !== SHELL_LINK_CLSID) throw new OperationError(`Invalid LNK class identifier: ${clsid}.`);

        const flagsValue = this.u32(20);
        const attributesValue = this.u32(24);
        const header = {
            headerSize: 76,
            clsid,
            linkFlags: decodeFlags(flagsValue, LINK_FLAGS),
            fileAttributes: decodeFlags(attributesValue, FILE_ATTRIBUTES),
            creationTime: this.filetime(28),
            accessTime: this.filetime(36),
            writeTime: this.filetime(44),
            fileSize: this.u32(52),
            iconIndex: this.view.getInt32(56, true),
            showCommand: this.showCommand(this.u32(60)),
            hotKey: this.hotKey(this.u16(64)),
        };

        let cursor = 76;
        let targetIdList = null;
        let linkInfo = null;
        if (flagsValue & 0x01) {
            this.requireRange(cursor, 2, "LinkTargetIDList size");
            const size = this.u16(cursor);
            this.requireRange(cursor + 2, size, "LinkTargetIDList");
            targetIdList = this.parseIdList(cursor + 2, size);
            cursor += 2 + size;
        }
        if (flagsValue & 0x02) {
            linkInfo = this.parseLinkInfo(cursor);
            cursor += linkInfo.size;
        }

        const stringData = Object.create(null);
        const stringFields = [
            [0x04, "name"],
            [0x08, "relativePath"],
            [0x10, "workingDirectory"],
            [0x20, "commandLineArguments"],
            [0x40, "iconLocation"],
        ];
        for (const [bit, field] of stringFields) {
            if (!(flagsValue & bit)) continue;
            const parsed = this.readCountedString(cursor, Boolean(flagsValue & 0x80));
            stringData[field] = parsed.value;
            cursor = parsed.nextOffset;
        }

        const extraData = [];
        let terminalBlockFound = false;
        while (cursor + 4 <= this.bytes.length) {
            const size = this.u32(cursor);
            if (size === 0) {
                cursor += 4;
                terminalBlockFound = true;
                break;
            }
            if (size < 8) throw new OperationError("Invalid LNK ExtraData block size.");
            this.requireRange(cursor, size, "ExtraData block");
            extraData.push(this.parseExtraData(cursor, size));
            cursor += size;
        }
        if (!terminalBlockFound)
            throw new OperationError("Missing or truncated LNK ExtraData terminal block.");

        const result = {
            format: "Windows Shell Link",
            header,
            targetIdList,
            linkInfo,
            stringData,
            extraData,
            trailingBytes: cursor < this.bytes.length ? toHex(this.bytes.subarray(cursor)) : "",
        };
        result.summary = this.buildSummary(result);
        return result;
    }

    /**
     * @param {number} offset
     * @param {number} length
     * @param {string} structure
     */
    requireRange(offset, length, structure) {
        if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > this.bytes.length)
            throw new OperationError(`Truncated or invalid ${structure}.`);
    }

    /** @param {number} offset @returns {number} */
    u16(offset) {
        this.requireRange(offset, 2, "16-bit value");
        return this.view.getUint16(offset, true);
    }

    /** @param {number} offset @returns {number} */
    u32(offset) {
        this.requireRange(offset, 4, "32-bit value");
        return this.view.getUint32(offset, true);
    }

    /**
     * @param {number} offset
     * @returns {Object|null}
     */
    filetime(offset) {
        this.requireRange(offset, 8, "FILETIME");
        const data = this.bytes.subarray(offset, offset + 8);
        if (data.every(byte => byte === 0)) return null;
        const low = this.view.getUint32(offset, true);
        const high = this.view.getUint32(offset + 4, true);
        const milliseconds = Math.floor((high * 0x100000000 + low) / 10000 - 11644473600000);
        const iso = milliseconds >= -8640000000000000 && milliseconds <= 8640000000000000 ? new Date(milliseconds).toISOString() : null;
        return {iso, raw: littleEndianBytesToDecimal(data)};
    }

    /**
     * @param {number} value
     * @returns {Object}
     */
    showCommand(value) {
        const names = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"};
        return {value, name: names[value] || "SW_SHOWNORMAL"};
    }

    /**
     * @param {number} value
     * @returns {Object|null}
     */
    hotKey(value) {
        if (!value) return null;
        const modifiers = [];
        const high = value >>> 8;
        if (high & 1) modifiers.push("SHIFT");
        if (high & 2) modifiers.push("CTRL");
        if (high & 4) modifiers.push("ALT");
        return {value: `0x${value.toString(16).padStart(4, "0")}`, key: value & 0xff, modifiers};
    }

    /**
     * @param {number} offset
     * @param {number} length
     * @returns {string}
     */
    ansiString(offset, length) {
        this.requireRange(offset, length, "ANSI string");
        const data = this.bytes.subarray(offset, offset + length);
        const terminator = data.indexOf(0);
        return this.ansiDecoder.decode(terminator < 0 ? data : data.subarray(0, terminator));
    }

    /**
     * @param {number} offset
     * @param {number} length
     * @returns {string}
     */
    unicodeString(offset, length) {
        this.requireRange(offset, length, "Unicode string");
        const data = this.bytes.subarray(offset, offset + length);
        let output = "";
        for (let i = 0; i + 1 < data.length; i += 2) {
            const code = data[i] | (data[i + 1] << 8);
            if (!code) break;
            output += String.fromCharCode(code);
        }
        return output;
    }

    /**
     * @param {number} offset
     * @param {boolean} unicode
     * @returns {Object}
     */
    readCountedString(offset, unicode) {
        const characterCount = this.u16(offset);
        const byteLength = characterCount * (unicode ? 2 : 1);
        this.requireRange(offset + 2, byteLength, "StringData string");
        return {
            value: unicode ? this.unicodeString(offset + 2, byteLength) : this.ansiString(offset + 2, byteLength),
            nextOffset: offset + 2 + byteLength,
        };
    }

    /**
     * @param {number} offset
     * @param {number} length
     * @returns {Object}
     */
    parseIdList(offset, length) {
        const end = offset + length;
        const items = [];
        let cursor = offset;
        let terminalFound = false;
        while (cursor + 2 <= end) {
            const size = this.u16(cursor);
            if (size === 0) {
                terminalFound = true;
                cursor += 2;
                break;
            }
            if (size < 2 || cursor + size > end) throw new OperationError("Invalid Shell Item size in LinkTargetIDList.");
            items.push(this.parseShellItem(cursor, size));
            cursor += size;
        }
        if (!terminalFound) throw new OperationError("LinkTargetIDList is missing its terminal item.");
        return {size: length, items, unusedBytes: cursor < end ? toHex(this.bytes.subarray(cursor, end)) : ""};
    }

    /**
     * @param {number} offset
     * @param {number} size
     * @returns {Object}
     */
    parseShellItem(offset, size) {
        const data = this.bytes.subarray(offset + 2, offset + size);
        const classType = data[0] || 0;
        const family = classType & 0x70;
        const item = {
            offset,
            size,
            classType: `0x${classType.toString(16).padStart(2, "0")}`,
            type: "Unknown",
            rawHex: toHex(data),
        };
        if (family === 0x10 && data.length >= 18) {
            item.type = "RootFolder";
            item.sortIndex = data[1];
            item.folderId = guidFromBytes(data.subarray(2, 18));
        } else if (family === 0x20) {
            item.type = "Volume";
            item.name = this.decodeNullTerminatedData(data.subarray(1));
        } else if (family === 0x30 && data.length >= 14) {
            item.type = "FileEntry";
            const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
            item.fileSize = dataView.getUint32(2, true);
            item.modifiedTime = this.dosDateTime(dataView.getUint32(6, true));
            item.fileAttributes = decodeFlags(dataView.getUint16(10, true), FILE_ATTRIBUTES);
            item.name = this.decodeNullTerminatedData(data.subarray(12));
        } else if (family === 0x40) {
            item.type = "NetworkLocation";
            item.location = this.decodeNullTerminatedData(data.subarray(1));
        }
        return item;
    }

    /**
     * @param {Uint8Array} data
     * @returns {string}
     */
    decodeNullTerminatedData(data) {
        const terminator = data.indexOf(0);
        return this.ansiDecoder.decode(terminator < 0 ? data : data.subarray(0, terminator));
    }

    /**
     * @param {number} value
     * @returns {string|null}
     */
    dosDateTime(value) {
        if (!value) return null;
        const time = value & 0xffff;
        const date = value >>> 16;
        const year = 1980 + (date >>> 9);
        const month = (date >>> 5) & 15;
        const day = date & 31;
        const hour = time >>> 11;
        const minute = (time >>> 5) & 63;
        const second = (time & 31) * 2;
        if (!month || !day) return null;
        return new Date(Date.UTC(year, month - 1, day, hour, minute, second)).toISOString();
    }

    /**
     * @param {number} offset
     * @returns {Object}
     */
    parseLinkInfo(offset) {
        this.requireRange(offset, 28, "LinkInfo");
        const size = this.u32(offset);
        const headerSize = this.u32(offset + 4);
        if (size < 28 || headerSize < 28 || headerSize > size) throw new OperationError("Invalid LNK LinkInfo size.");
        this.requireRange(offset, size, "LinkInfo");
        const flags = this.u32(offset + 8);
        const volumeOffset = this.u32(offset + 12);
        const localPathOffset = this.u32(offset + 16);
        const networkOffset = this.u32(offset + 20);
        const suffixOffset = this.u32(offset + 24);
        const localUnicodeOffset = headerSize >= 36 ? this.u32(offset + 28) : 0;
        const suffixUnicodeOffset = headerSize >= 36 ? this.u32(offset + 32) : 0;
        const result = {
            size,
            headerSize,
            flags: {
                value: hex32(flags),
                volumeIdAndLocalBasePath: Boolean(flags & 1),
                commonNetworkRelativeLinkAndPathSuffix: Boolean(flags & 2),
            },
            volume: volumeOffset ? this.parseVolumeId(offset, size, volumeOffset) : null,
            localBasePath: this.relativeAnsiString(offset, size, localPathOffset),
            localBasePathUnicode: this.relativeUnicodeString(offset, size, localUnicodeOffset),
            commonNetworkRelativeLink: networkOffset ? this.parseNetworkLink(offset, size, networkOffset) : null,
            commonPathSuffix: this.relativeAnsiString(offset, size, suffixOffset),
            commonPathSuffixUnicode: this.relativeUnicodeString(offset, size, suffixUnicodeOffset),
        };
        const base = result.localBasePathUnicode || result.localBasePath ||
            (result.commonNetworkRelativeLink && (result.commonNetworkRelativeLink.netNameUnicode || result.commonNetworkRelativeLink.netName));
        const suffix = result.commonPathSuffixUnicode || result.commonPathSuffix;
        result.resolvedPath = this.joinWindowsPath(base, suffix);
        return result;
    }

    /**
     * @param {number} base
     * @param {number} size
     * @param {number} relativeOffset
     * @returns {string|null}
     */
    relativeAnsiString(base, size, relativeOffset) {
        if (!relativeOffset) return null;
        if (relativeOffset >= size) throw new OperationError("LNK LinkInfo ANSI string offset is outside LinkInfo.");
        return this.ansiString(base + relativeOffset, size - relativeOffset);
    }

    /**
     * @param {number} base
     * @param {number} size
     * @param {number} relativeOffset
     * @returns {string|null}
     */
    relativeUnicodeString(base, size, relativeOffset) {
        if (!relativeOffset) return null;
        if (relativeOffset >= size) throw new OperationError("LNK LinkInfo Unicode string offset is outside LinkInfo.");
        return this.unicodeString(base + relativeOffset, size - relativeOffset);
    }

    /**
     * @param {number} base
     * @param {number} linkInfoSize
     * @param {number} relativeOffset
     * @returns {Object}
     */
    parseVolumeId(base, linkInfoSize, relativeOffset) {
        if (relativeOffset + 16 > linkInfoSize) throw new OperationError("Invalid LNK VolumeID offset.");
        const offset = base + relativeOffset;
        const size = this.u32(offset);
        if (size < 16 || relativeOffset + size > linkInfoSize) throw new OperationError("Invalid LNK VolumeID size.");
        const driveTypeValue = this.u32(offset + 4);
        const labelOffset = this.u32(offset + 12);
        let label = null;
        if (labelOffset === 0x14 && size >= 20) label = this.relativeUnicodeString(offset, size, this.u32(offset + 16));
        else label = this.relativeAnsiString(offset, size, labelOffset);
        return {
            driveType: {value: driveTypeValue, name: DRIVE_TYPES[driveTypeValue] || "Unknown"},
            driveSerialNumber: `0x${this.u32(offset + 8).toString(16).padStart(8, "0")}`,
            volumeLabel: label,
        };
    }

    /**
     * @param {number} base
     * @param {number} linkInfoSize
     * @param {number} relativeOffset
     * @returns {Object}
     */
    parseNetworkLink(base, linkInfoSize, relativeOffset) {
        if (relativeOffset + 20 > linkInfoSize) throw new OperationError("Invalid CommonNetworkRelativeLink offset.");
        const offset = base + relativeOffset;
        const size = this.u32(offset);
        if (size < 20 || relativeOffset + size > linkInfoSize) throw new OperationError("Invalid CommonNetworkRelativeLink size.");
        const flags = this.u32(offset + 4);
        const netNameOffset = this.u32(offset + 8);
        const deviceNameOffset = this.u32(offset + 12);
        const providerType = this.u32(offset + 16);
        let netNameUnicode = null;
        let deviceNameUnicode = null;
        if (netNameOffset > 20 && size >= 28) {
            netNameUnicode = this.relativeUnicodeString(offset, size, this.u32(offset + 20));
            deviceNameUnicode = this.relativeUnicodeString(offset, size, this.u32(offset + 24));
        }
        return {
            flags: hex32(flags),
            netName: this.relativeAnsiString(offset, size, netNameOffset),
            deviceName: this.relativeAnsiString(offset, size, deviceNameOffset),
            networkProviderType: hex32(providerType),
            netNameUnicode,
            deviceNameUnicode,
        };
    }

    /**
     * @param {string|null} base
     * @param {string|null} suffix
     * @returns {string|null}
     */
    joinWindowsPath(base, suffix) {
        if (!base) return suffix || null;
        if (!suffix) return base;
        if (base.toLowerCase().endsWith(suffix.toLowerCase())) return base;
        return `${base.replace(/[\\/]+$/, "")}\\${suffix.replace(/^[\\/]+/, "")}`;
    }

    /**
     * @param {number} offset
     * @param {number} size
     * @returns {Object}
     */
    parseExtraData(offset, size) {
        if (size < 8) throw new OperationError("Invalid LNK ExtraData block size.");
        const signature = this.u32(offset + 4);
        const block = {
            type: EXTRA_SIGNATURES[signature] || "UnknownDataBlock",
            signature: hex32(signature),
            size,
            rawHex: toHex(this.bytes.subarray(offset, offset + size)),
        };
        if ((signature === 0xa0000001 || signature === 0xa0000006 || signature === 0xa0000007) && size >= 788) {
            block.targetAnsi = this.ansiString(offset + 8, 260);
            block.targetUnicode = this.unicodeString(offset + 268, 520);
        } else if (signature === 0xa0000003 && size >= 96) {
            block.length = this.u32(offset + 8);
            block.version = this.u32(offset + 12);
            block.machineId = this.ansiString(offset + 16, 16);
            block.droidVolumeId = guidFromBytes(this.bytes.subarray(offset + 32, offset + 48));
            block.droidFileId = guidFromBytes(this.bytes.subarray(offset + 48, offset + 64));
            block.birthDroidVolumeId = guidFromBytes(this.bytes.subarray(offset + 64, offset + 80));
            block.birthDroidFileId = guidFromBytes(this.bytes.subarray(offset + 80, offset + 96));
        } else if (signature === 0xa0000004 && size >= 12) {
            block.codePage = this.u32(offset + 8);
        } else if (signature === 0xa0000005 && size >= 16) {
            block.specialFolderId = this.u32(offset + 8);
            block.offset = this.u32(offset + 12);
        } else if (signature === 0xa0000008 && size > 8) {
            block.layerName = this.unicodeString(offset + 8, size - 8);
        } else if (signature === 0xa000000b && size >= 28) {
            block.knownFolderId = guidFromBytes(this.bytes.subarray(offset + 8, offset + 24));
            block.offset = this.u32(offset + 24);
        } else if (signature === 0xa000000c && size >= 10) {
            block.idList = this.parseIdList(offset + 8, size - 8);
        } else if (signature === 0xa0000002 && size >= 0xcc) {
            block.fillAttributes = this.u16(offset + 8);
            block.popupFillAttributes = this.u16(offset + 10);
            block.fontFamily = this.u32(offset + 36);
            block.fontWeight = this.u32(offset + 40);
            block.faceName = this.unicodeString(offset + 44, 64);
        }
        return block;
    }

    /**
     * @param {Object} result
     * @returns {Object}
     */
    buildSummary(result) {
        const tracker = result.extraData.find(block => block.type === "TrackerDataBlock") || {};
        const environment = result.extraData.find(block => block.type === "EnvironmentVariableDataBlock") || {};
        const linkInfo = result.linkInfo || {};
        const network = linkInfo.commonNetworkRelativeLink || {};
        const volume = linkInfo.volume || {};
        return {
            targetPath: linkInfo.resolvedPath || environment.targetUnicode || environment.targetAnsi || result.stringData.relativePath || null,
            localBasePath: linkInfo.localBasePathUnicode || linkInfo.localBasePath || null,
            commonPathSuffix: linkInfo.commonPathSuffixUnicode || linkInfo.commonPathSuffix || null,
            networkPath: network.netNameUnicode || network.netName || null,
            relativePath: result.stringData.relativePath || null,
            workingDirectory: result.stringData.workingDirectory || null,
            commandLineArguments: result.stringData.commandLineArguments || null,
            description: result.stringData.name || null,
            iconLocation: result.stringData.iconLocation || null,
            creationTime: result.header.creationTime && result.header.creationTime.iso,
            accessTime: result.header.accessTime && result.header.accessTime.iso,
            writeTime: result.header.writeTime && result.header.writeTime.iso,
            fileSize: result.header.fileSize,
            fileAttributes: result.header.fileAttributes.names.join("|"),
            driveType: volume.driveType && volume.driveType.name,
            volumeSerialNumber: volume.driveSerialNumber || null,
            volumeLabel: volume.volumeLabel || null,
            machineId: tracker.machineId || null,
            droidVolumeId: tracker.droidVolumeId || null,
            droidFileId: tracker.droidFileId || null,
            birthDroidVolumeId: tracker.birthDroidVolumeId || null,
            birthDroidFileId: tracker.birthDroidFileId || null,
        };
    }
}

/**
 * @param {ArrayBuffer} input
 * @param {string} ansiEncoding
 * @returns {Object}
 */
function parseWindowsShellLink(input, ansiEncoding) {
    return new WindowsShellLinkParser(input, ansiEncoding).parse();
}

/**
 * @param {Object} parsed
 * @param {string} outputFormat
 * @returns {string}
 */
function formatWindowsShellLink(parsed, outputFormat) {
    if (outputFormat !== "CSV") return JSON.stringify(parsed, null, 4);
    const headers = Object.keys(parsed.summary);
    return rowsToCSV([headers, headers.map(header => parsed.summary[header])]);
}

export {
    formatWindowsShellLink,
    parseWindowsShellLink,
};
