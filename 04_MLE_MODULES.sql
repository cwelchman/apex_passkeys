CREATE OR REPLACE MLE MODULE "MLE_PASSKEY_CORE"
   LANGUAGE JAVASCRIPT AS
// CBOR Decoder for parsing WebAuthn attestation objects
const CBORDecoder = (function() {
    class Decoder {
        constructor(data) {
            this.data = new Uint8Array(data);
            this.offset = 0;
        }

        readByte() {
            return this.data[this.offset++];
        }

        readBytes(count) {
            const bytes = this.data.slice(this.offset, this.offset + count);
            this.offset += count;
            return bytes;
        }

        readLength(additionalInfo) {
            if (additionalInfo < 24) return additionalInfo;
            if (additionalInfo === 24) return this.readByte();
            if (additionalInfo === 25) {
                const b = this.readBytes(2);
                return (b[0] << 8) | b[1];
            }
            if (additionalInfo === 26) {
                const b = this.readBytes(4);
                return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
            }
            return -1;
        }

        decode() {
            const ib = this.readByte();
            const mt = ib >> 5;
            const ai = ib & 0x1f;

            switch (mt) {
                case 0: return this.readLength(ai);
                case 1: return -1 - this.readLength(ai);
                case 2: return this.readBytes(this.readLength(ai));
                case 3: {
                    const b = this.readBytes(this.readLength(ai));
                    return new TextDecoder().decode(b);
                }
                case 4: {
                    const len = this.readLength(ai);
                    const arr = [];
                    for (let i = 0; i < len; i++) arr.push(this.decode());
                    return arr;
                }
                case 5: {
                    const len = this.readLength(ai);
                    const map = {};
                    for (let i = 0; i < len; i++) {
                        map[this.decode()] = this.decode();
                    }
                    return map;
                }
                case 7:
                    if (ai === 20) return false;
                    if (ai === 21) return true;
                    if (ai === 22) return null;
                    return ai;
                default:
                    return null;
            }
        }
    }
    return { decode: (d) => new Decoder(d).decode() };
})();

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Extract public key from CBOR-encoded attestation object.
 * Returns JSON: {x, y, alg, aaguid, credentialId, fmt} or {error}
 */
export function extractPublicKey(attestationHex) {
    try {
        const bytes = hexToBytes(attestationHex);
        const decoded = CBORDecoder.decode(bytes);

        if (!decoded || !decoded.authData) {
            return JSON.stringify({error: 'No authData'});
        }

        const authData = decoded.authData instanceof Uint8Array
            ? decoded.authData
            : hexToBytes(decoded.authData);

        // Parse authenticator data
        let offset = 37; // Skip rpIdHash(32) + flags(1) + signCount(4)

        // AAGUID (16 bytes)
        const aaguid = bytesToHex(authData.slice(offset, offset + 16));
        offset += 16;

        // Credential ID length (2 bytes)
        const credIdLen = (authData[offset] << 8) | authData[offset + 1];
        offset += 2;

        // Credential ID
        const credentialId = bytesToHex(authData.slice(offset, offset + credIdLen));
        offset += credIdLen;

        // COSE public key (CBOR)
        const pubKeyBytes = authData.slice(offset);
        const pubKey = CBORDecoder.decode(pubKeyBytes);

        // Extract x and y coordinates (keys -2 and -3 in COSE)
        const x = pubKey[-2] ? bytesToHex(pubKey[-2]) : null;
        const y = pubKey[-3] ? bytesToHex(pubKey[-3]) : null;
        const alg = pubKey[3] || -7;
        const fmt = decoded.fmt || 'none';

        return JSON.stringify({
            x: x,
            y: y,
            alg: alg,
            aaguid: aaguid,
            credentialId: credentialId,
            fmt: fmt
        });
    } catch (e) {
        return JSON.stringify({error: e.message});
    }
}

/**
 * Parse authenticator data buffer.
 * Returns JSON: {rpIdHash, flags:{up,uv,at,ed}, signCount, aaguid?, credentialId?} or {error}
 */
export function parseAuthData(authDataHex) {
    try {
        const authData = hexToBytes(authDataHex);

        const rpIdHash = bytesToHex(authData.slice(0, 32));
        const flags = authData[32];
        const signCount = (authData[33] << 24) | (authData[34] << 16) |
                          (authData[35] << 8) | authData[36];

        const result = {
            rpIdHash: rpIdHash,
            flags: {
                up: !!(flags & 0x01),
                uv: !!(flags & 0x04),
                at: !!(flags & 0x40),
                ed: !!(flags & 0x80)
            },
            signCount: signCount
        };

        // If AT flag set, extract credential data
        if (result.flags.at && authData.length > 37) {
            let offset = 37;
            result.aaguid = bytesToHex(authData.slice(offset, offset + 16));
            offset += 16;

            const credIdLen = (authData[offset] << 8) | authData[offset + 1];
            offset += 2;

            result.credentialId = bytesToHex(authData.slice(offset, offset + credIdLen));
        }

        return JSON.stringify(result);
    } catch (e) {
        return JSON.stringify({error: e.message});
    }
}

/**
 * Convert ASN.1 DER-encoded ECDSA signature to raw 64-byte r||s format.
 * Returns hex string of 64 bytes, or empty string on error.
 */
export function derToRaw(derSigHex) {
    try {
        const sig = hexToBytes(derSigHex);
        let offset = 0;

        if (sig[offset++] !== 0x30) return '';
        offset++; // Skip length

        if (sig[offset++] !== 0x02) return '';
        let rLen = sig[offset++];
        let r = sig.slice(offset, offset + rLen);
        offset += rLen;

        if (sig[offset++] !== 0x02) return '';
        let sLen = sig[offset++];
        let s = sig.slice(offset, offset + sLen);

        // Normalize to 32 bytes
        while (r.length > 32 && r[0] === 0) r = r.slice(1);
        while (s.length > 32 && s[0] === 0) s = s.slice(1);

        const raw = new Uint8Array(64);
        raw.set(r.length <= 32 ? r : r.slice(-32), 32 - Math.min(r.length, 32));
        raw.set(s.length <= 32 ? s : s.slice(-32), 64 - Math.min(s.length, 32));

        return bytesToHex(raw);
    } catch (e) {
        return '';
    }
}
/
