// Tab Switching
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById(tabId).classList.add('active');
    
    // Update button states
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
        if (btn.getAttribute('onclick').includes(tabId)) {
            btn.classList.add('active');
        }
    });
}

// IP Utilities (v4 & v6 with BigInt)
const IPv4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPv6_PATTERN = /^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$|^:((:[\da-fA-F]{1,4}){1,7}|:)$|^[\da-fA-F]{1,4}:((:[\da-fA-F]{1,4}){1,6})|:((:[\da-fA-F]{1,4}){1,7}|:)$|^([\da-fA-F]{1,4}:){1,7}:$/; // Simplified check, rely on parsing
// A more robust IPv6 regex or just try-parse is better.
// Let's use a helper to detect version.

function getIPVersion(ip) {
    if (!ip) return 0;
    if (ip.includes('.')) return 4;
    if (ip.includes(':')) return 6;
    return 0;
}

function isValidIPv4(ip) {
    if (!IPv4_PATTERN.test(ip)) return false;
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

function isValidIPv6(ip) {
    // Basic structural check
    if (!ip || typeof ip !== 'string') return false;
    // Handle compressed ::
    const parts = ip.split('::');
    if (parts.length > 2) return false; // Multiple ::
    
    let segments = [];
    if (parts.length === 2) {
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        if (left.length + right.length > 7) return false; // Too many parts
        // Check segments
        segments = [...left, ...right];
    } else {
        segments = ip.split(':');
        if (segments.length !== 8) return false;
    }
    
    return segments.every(seg => /^[0-9a-fA-F]{1,4}$/.test(seg));
}

function ipToBigInt(ip) {
    const version = getIPVersion(ip);
    if (version === 4) {
        if (!isValidIPv4(ip)) return null;
        const parts = ip.split('.').map(Number);
        return (BigInt(parts[0]) << 24n) | (BigInt(parts[1]) << 16n) | (BigInt(parts[2]) << 8n) | BigInt(parts[3]);
    } else if (version === 6) {
        if (!isValidIPv6(ip)) return null;
        let parts = ip.split('::');
        let left = parts[0] ? parts[0].split(':') : [];
        let right = parts.length > 1 ? (parts[1] ? parts[1].split(':') : []) : [];
        
        // Expand ::
        let expanded = [...left];
        const missing = 8 - (left.length + right.length);
        for (let i = 0; i < missing; i++) expanded.push('0');
        expanded = [...expanded, ...right];
        
        let value = 0n;
        for (let i = 0; i < 8; i++) {
            value = (value << 16n) | BigInt(parseInt(expanded[i], 16));
        }
        return value;
    }
    return null;
}

function bigIntToIPv4(bigint) {
    return [
        (bigint >> 24n) & 0xFFn,
        (bigint >> 16n) & 0xFFn,
        (bigint >> 8n) & 0xFFn,
        bigint & 0xFFn
    ].join('.');
}

function bigIntToIPv6(bigint) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
        parts.unshift(((bigint >> BigInt(i * 16)) & 0xFFFFn).toString(16));
    }
    // Simple compression: find longest run of '0'
    // For now, let's just return full expanded or simple compression?
    // User probably wants standard representation.
    // Let's implement full standard representation logic later if needed.
    // For now, return full address.
    return parts.join(':');
    
    // Actually, let's do a simple compression for better UX
    // Find longest sequence of "0"
    /*
    let bestStart = -1, bestLen = 0;
    let currentStart = -1, currentLen = 0;
    for(let i=0; i<8; i++) {
        if(parts[i] === '0') {
            if(currentStart === -1) currentStart = i;
            currentLen++;
        } else {
            if(currentLen > bestLen) {
                bestLen = currentLen;
                bestStart = currentStart;
            }
            currentStart = -1;
            currentLen = 0;
        }
    }
    if(currentLen > bestLen) {
        bestLen = currentLen;
        bestStart = currentStart;
    }
    
    if(bestLen > 1) {
        // Compress
        const left = parts.slice(0, bestStart).join(':');
        const right = parts.slice(bestStart + bestLen).join(':');
        return `${left}::${right}`;
    }
    */
}

function isValidCIDR(cidr) {
    if (!cidr) return false;
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    
    const version = getIPVersion(parts[0]);
    if (version === 4) {
        if (!isValidIPv4(parts[0])) return false;
        const mask = parseInt(parts[1], 10);
        return !isNaN(mask) && mask >= 0 && mask <= 32;
    } else if (version === 6) {
        if (!isValidIPv6(parts[0])) return false;
        const mask = parseInt(parts[1], 10);
        return !isNaN(mask) && mask >= 0 && mask <= 128;
    }
    return false;
}

// Logic: CIDR -> Range
function getCIDRRange(cidr) {
    const [ip, maskStr] = cidr.split('/');
    const mask = parseInt(maskStr, 10);
    const ipVal = ipToBigInt(ip);
    const version = getIPVersion(ip);
    
    const bits = (version === 4) ? 32n : 128n;
    const maskBig = BigInt(mask);
    
    // Network Mask
    // In BigInt: (1n << bits) - 1n gives all 1s.
    // But standard way: ~((1n << (bits - maskBig)) - 1n)
    // Or simpler: (start with all 1s) << (bits - mask)
    
    // (1 << 128) is too big for shift if 1 is Number? No, 1n is BigInt.
    // Mask logic:
    // 1. All ones: (1n << bits) - 1n
    // 2. Shift right by (bits - mask), then shift left back? No, that clears lower bits.
    
    const offset = bits - maskBig;
    const allOnes = (1n << bits) - 1n;
    const networkMask = (allOnes >> offset) << offset; // Clear lower 'offset' bits
    // Wait, (allOnes >> offset) leaves upper 'mask' bits. Then << offset puts them back.
    // Correct.
    
    const networkAddress = ipVal & networkMask;
    const broadcastAddress = networkAddress | (allOnes ^ networkMask); // Invert mask for host part
    
    return {
        start: networkAddress,
        end: broadcastAddress,
        mask: mask,
        version: version
    };
}

// Logic: Range Splitting for Exclusions (Generic BigInt)
function splitRange(start, end, excludeIPs) {
    let ranges = [{start: start, end: end}];
    
    // excludeIPs should be a sorted Array of unique BigInts
    // Convert to set to unique, then sort
    // BigInt sort needs explicit comparator
    const sortedExcludes = Array.from(new Set(excludeIPs)).sort((a, b) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
    });
    
    sortedExcludes.forEach(exclude => {
        const newRanges = [];
        ranges.forEach(range => {
            if (exclude >= range.start && exclude <= range.end) {
                // Split logic
                // 1. Left part: range.start to exclude - 1
                if (range.start <= exclude - 1n) {
                    newRanges.push({start: range.start, end: exclude - 1n});
                }
                // 2. Right part: exclude + 1 to range.end
                if (exclude + 1n <= range.end) {
                    newRanges.push({start: exclude + 1n, end: range.end});
                }
            } else {
                // Keep original
                newRanges.push(range);
            }
        });
        ranges = newRanges;
    });
    
    return ranges;
}

// Logic: Range -> CIDR List (Generic BigInt)
function rangeToCIDR(startIp, endIp) {
    let start, end, version;
    
    // Handle inputs
    if (typeof startIp === 'bigint') {
        start = startIp;
        // Assume version if passed as bigint? No, need explicit version or heuristics.
        // Let's assume caller handles version context or we infer from value range?
        // Actually, rangeToCIDR needs to know the bit length (32 or 128) to know max mask.
        // So we should pass version or infer from inputs if strings.
        return []; // Should not happen with current usage
    } else {
        version = getIPVersion(startIp);
        start = ipToBigInt(startIp);
        end = ipToBigInt(endIp);
    }
    
    if (start === null || end === null || start > end) {
        return []; 
    }

    const cidrs = [];
    const maxBits = (version === 4) ? 32n : 128n;
    const maxBitsNum = (version === 4) ? 32 : 128;

    while (start <= end) {
        let n = 0;
        
        // Find largest power of 2 block that fits
        // 1. Alignment: trailing zeros of 'start'
        // 2. Size: must be <= (end - start + 1)
        
        // Count trailing zeros
        let alignmentBits = 0;
        let temp = start;
        if (temp === 0n) {
            alignmentBits = maxBitsNum;
        } else {
            while ((temp & 1n) === 0n && alignmentBits < maxBitsNum) {
                temp >>= 1n;
                alignmentBits++;
            }
        }
        
        // Calculate range size
        const rangeSize = end - start + 1n;
        
        // Find max n such that 2^n <= rangeSize AND n <= alignmentBits
        // Loop n from maxBitsNum down to 0
        // Optimization: Start from min(alignmentBits, floor(log2(rangeSize)))
        
        // Since rangeSize can be huge (128-bit), we can't use simple Math.log2
        // Just iterate down is fine for 128 iterations max.
        
        for (let i = alignmentBits; i >= 0; i--) {
            const blockSize = 1n << BigInt(i);
            if (blockSize <= rangeSize) {
                n = i;
                break;
            }
        }
        
        const mask = maxBitsNum - n;
        const ipStr = (version === 4) ? bigIntToIPv4(start) : bigIntToIPv6(start);
        cidrs.push(ipStr + '/' + mask);
        
        start += (1n << BigInt(n));
    }
    
    return cidrs;
}

// Main Conversion Functions
function convertCIDRToIP() {
    const input = document.getElementById('cidr-input').value;
    const excludeNetwork = document.getElementById('exclude-network').checked;
    const excludeBroadcast = document.getElementById('exclude-broadcast').checked;
    const excludeGateway = document.getElementById('exclude-gateway').checked;
    const customExcludeInput = document.getElementById('custom-exclude').value;
    
    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    
    // Parse Custom Excludes
    const customExcludesV4 = [];
    const customExcludesV6 = [];
    
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        const v = getIPVersion(l);
        if (v === 4 && isValidIPv4(l)) customExcludesV4.push(ipToBigInt(l));
        if (v === 6 && isValidIPv6(l)) customExcludesV6.push(ipToBigInt(l));
    });

    lines.forEach(line => {
        if (!isValidCIDR(line)) {
            if (line) results.push(`Error: Invalid CIDR ${line}`);
            return;
        }
        
        const range = getCIDRRange(line);
        const rangeExcludes = [];
        const isV4 = (range.version === 4);
        
        // Select appropriate custom excludes
        const relevantCustom = isV4 ? customExcludesV4 : customExcludesV6;

        // Network Address
        if (excludeNetwork) {
            rangeExcludes.push(range.start);
        }
        
        // Broadcast Address
        if (excludeBroadcast) {
            rangeExcludes.push(range.end);
        }
        
        // Gateway: Network + 1
        if (excludeGateway) {
            rangeExcludes.push(range.start + 1n);
        }

        // Custom Excludes
        relevantCustom.forEach(ip => {
            if (ip >= range.start && ip <= range.end) {
                rangeExcludes.push(ip);
            }
        });

        // Apply splitting
        const finalRanges = splitRange(range.start, range.end, rangeExcludes);
        
        if (finalRanges.length === 0) {
            results.push(`${line}: No IPs left (Empty Range)`);
        } else {
            finalRanges.forEach(r => {
                const startStr = isV4 ? bigIntToIPv4(r.start) : bigIntToIPv6(r.start);
                const endStr = isV4 ? bigIntToIPv4(r.end) : bigIntToIPv6(r.end);
                
                if (r.start === r.end) {
                    results.push(startStr);
                } else {
                    results.push(`${startStr} - ${endStr}`);
                }
            });
        }
    });
    
    document.getElementById('cidr-output').value = results.join('\n');
    document.getElementById('cidr-stats').innerText = `Total Ranges: ${results.length}`;
}

function convertIPToCIDR() {
    const input = document.getElementById('ip-input').value;
    const excludeNetwork = document.getElementById('ip-exclude-network').checked;
    const excludeBroadcast = document.getElementById('ip-exclude-broadcast').checked;
    const excludeGateway = document.getElementById('ip-exclude-gateway').checked;
    const customExcludeInput = document.getElementById('ip-custom-exclude').value;

    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    
    // Parse Custom Excludes
    const customExcludesV4 = [];
    const customExcludesV6 = [];
    
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        const v = getIPVersion(l);
        if (v === 4 && isValidIPv4(l)) customExcludesV4.push(ipToBigInt(l));
        if (v === 6 && isValidIPv6(l)) customExcludesV6.push(ipToBigInt(l));
    });
    
    lines.forEach(line => {
        let start = null;
        let end = null;
        let isValid = false;
        let version = 0;

        // Handle "IP - IP" format
        if (line.includes('-')) {
            const parts = line.split('-').map(s => s.trim());
            if (parts.length === 2) {
                const v1 = getIPVersion(parts[0]);
                const v2 = getIPVersion(parts[1]);
                if (v1 === v2 && v1 !== 0) {
                    if (v1 === 4 && isValidIPv4(parts[0]) && isValidIPv4(parts[1])) {
                        start = ipToBigInt(parts[0]);
                        end = ipToBigInt(parts[1]);
                        version = 4;
                        isValid = true;
                    } else if (v1 === 6 && isValidIPv6(parts[0]) && isValidIPv6(parts[1])) {
                        start = ipToBigInt(parts[0]);
                        end = ipToBigInt(parts[1]);
                        version = 6;
                        isValid = true;
                    }
                }
            }
        } 
        // Handle Single IP
        else {
            const v = getIPVersion(line);
            if (v === 4 && isValidIPv4(line)) {
                start = ipToBigInt(line);
                end = start;
                version = 4;
                isValid = true;
            } else if (v === 6 && isValidIPv6(line)) {
                start = ipToBigInt(line);
                end = start;
                version = 6;
                isValid = true;
            }
        }

        if (isValid && start !== null && end !== null) {
             if (start > end) {
                 results.push(`Error: Invalid Range ${line} (Start > End)`);
                 return;
             }

             const rangeExcludes = [];
             const isV4 = (version === 4);
             const relevantCustom = isV4 ? customExcludesV4 : customExcludesV6;

             // Apply Exclusions
             if (excludeNetwork) {
                 rangeExcludes.push(start);
             }
             if (excludeBroadcast) {
                 rangeExcludes.push(end);
             }
             if (excludeGateway) {
                 rangeExcludes.push(start + 1n);
             }
             
             // Custom Excludes
             relevantCustom.forEach(ip => {
                 if (ip >= start && ip <= end) {
                     rangeExcludes.push(ip);
                 }
             });

             // Split Range
             const finalRanges = splitRange(start, end, rangeExcludes);

             if (finalRanges.length === 0) {
                 results.push(`${line}: No IPs left`);
             } else {
                 finalRanges.forEach(r => {
                     // Convert each sub-range to CIDR
                     // rangeToCIDR needs strings for version detection in current impl, 
                     // or we refactor it to accept BigInts + Version.
                     // Refactoring rangeToCIDR above to accept strings is cleaner for external calls,
                     // but here we have BigInts.
                     // Let's change rangeToCIDR to handle BigInts internally properly.
                     
                     // Helper for internal use
                     const cidrs = rangeToCIDRBigInt(r.start, r.end, version);
                     results.push(...cidrs);
                 });
             }

        } else {
            results.push(`Error: Invalid Input ${line}`);
        }
    });
    
    document.getElementById('ip-output').value = results.join('\n');
    document.getElementById('ip-stats').innerText = `Total CIDRs: ${results.length}`;
}

// Internal Helper for rangeToCIDR with BigInts
function rangeToCIDRBigInt(start, end, version) {
    const cidrs = [];
    const maxBitsNum = (version === 4) ? 32 : 128;
    
    while (start <= end) {
        let n = 0;
        let alignmentBits = 0;
        let temp = start;
        if (temp === 0n) {
            alignmentBits = maxBitsNum;
        } else {
            while ((temp & 1n) === 0n && alignmentBits < maxBitsNum) {
                temp >>= 1n;
                alignmentBits++;
            }
        }
        
        const rangeSize = end - start + 1n;
        
        for (let i = alignmentBits; i >= 0; i--) {
            const blockSize = 1n << BigInt(i);
            if (blockSize <= rangeSize) {
                n = i;
                break;
            }
        }
        
        const mask = maxBitsNum - n;
        const ipStr = (version === 4) ? bigIntToIPv4(start) : bigIntToIPv6(start);
        cidrs.push(ipStr + '/' + mask);
        
        start += (1n << BigInt(n));
    }
    return cidrs;
}

// Copy to Clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    
    const btn = document.querySelector(`button[onclick="copyToClipboard('${elementId}')"]`);
    const originalText = btn.innerText;
    btn.innerText = '已复制!';
    setTimeout(() => {
        btn.innerText = originalText;
    }, 2000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    switchTab('cidr-to-ip');
});
