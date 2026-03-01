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
const IPv6_PATTERN = /^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$|^:((:[\da-fA-F]{1,4}){1,7}|:)$|^[\da-fA-F]{1,4}:((:[\da-fA-F]{1,4}){1,6})|:((:[\da-fA-F]{1,4}){1,7}|:)$|^([\da-fA-F]{1,4}:){1,7}:$/;

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
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.split('::');
    if (parts.length > 2) return false;
    
    let segments = [];
    if (parts.length === 2) {
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        if (left.length + right.length > 7) return false;
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
    return parts.join(':');
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
    
    const offset = bits - maskBig;
    const allOnes = (1n << bits) - 1n;
    const networkMask = (allOnes >> offset) << offset; 
    
    const networkAddress = ipVal & networkMask;
    const broadcastAddress = networkAddress | (allOnes ^ networkMask);
    
    return {
        start: networkAddress,
        end: broadcastAddress,
        mask: mask,
        version: version
    };
}

// Logic: Range Splitting for Exclusions
function splitRange(start, end, excludeIPs) {
    let ranges = [{start: start, end: end}];
    
    const sortedExcludes = Array.from(new Set(excludeIPs)).sort((a, b) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
    });
    
    sortedExcludes.forEach(exclude => {
        const newRanges = [];
        ranges.forEach(range => {
            if (exclude >= range.start && exclude <= range.end) {
                if (range.start <= exclude - 1n) {
                    newRanges.push({start: range.start, end: exclude - 1n});
                }
                if (exclude + 1n <= range.end) {
                    newRanges.push({start: exclude + 1n, end: range.end});
                }
            } else {
                newRanges.push(range);
            }
        });
        ranges = newRanges;
    });
    
    return ranges;
}

// Logic: Merge Overlapping Ranges (Aggregation)
function mergeRanges(ranges) {
    if (ranges.length <= 1) return ranges;
    
    // Sort by start
    ranges.sort((a, b) => {
        if (a.start < b.start) return -1;
        if (a.start > b.start) return 1;
        return 0;
    });
    
    const merged = [];
    let current = ranges[0];
    
    for (let i = 1; i < ranges.length; i++) {
        const next = ranges[i];
        
        // Check for overlap or adjacency
        // Adjacency: current.end + 1 == next.start
        if (current.end >= next.start - 1n) {
            // Merge
            if (next.end > current.end) {
                current.end = next.end;
            }
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    return merged;
}

// Logic: Range -> CIDR List (Generic BigInt)
function rangeToCIDR(startIp, endIp) {
    let start, end, version;
    
    if (typeof startIp === 'bigint') {
        start = startIp;
        return []; 
    } else {
        version = getIPVersion(startIp);
        start = ipToBigInt(startIp);
        end = ipToBigInt(endIp);
    }
    
    if (start === null || end === null || start > end) return []; 

    return rangeToCIDRBigInt(start, end, version);
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

// ==========================================
// Tab 1: CIDR to IP (Range or List)
// ==========================================
function convertCIDRToIP() {
    const input = document.getElementById('cidr-input').value;
    const outputFormat = document.querySelector('input[name="cidr-output-format"]:checked').value;
    const excludeNetwork = document.getElementById('exclude-network').checked;
    const excludeBroadcast = document.getElementById('exclude-broadcast').checked;
    const excludeGateway = document.getElementById('exclude-gateway').checked;
    const customExcludeInput = document.getElementById('custom-exclude').value;
    
    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    const MAX_IPS = 10000;
    let currentTotal = 0;
    
    // Parse Custom Excludes
    const customExcludesV4 = [];
    const customExcludesV6 = [];
    
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        const v = getIPVersion(l);
        if (v === 4 && isValidIPv4(l)) customExcludesV4.push(ipToBigInt(l));
        if (v === 6 && isValidIPv6(l)) customExcludesV6.push(ipToBigInt(l));
    });

    for (let line of lines) {
        if (outputFormat === 'list' && currentTotal >= MAX_IPS) {
            results.push(`Warning: Limit reached (${MAX_IPS} IPs). Stopping.`);
            break;
        }

        if (!isValidCIDR(line)) {
            if (line) results.push(`Error: Invalid CIDR ${line}`);
            continue;
        }
        
        const range = getCIDRRange(line);
        const rangeExcludes = [];
        const isV4 = (range.version === 4);
        
        const relevantCustom = isV4 ? customExcludesV4 : customExcludesV6;

        if (excludeNetwork) rangeExcludes.push(range.start);
        if (excludeBroadcast) rangeExcludes.push(range.end);
        if (excludeGateway) rangeExcludes.push(range.start + 1n);

        relevantCustom.forEach(ip => {
            if (ip >= range.start && ip <= range.end) rangeExcludes.push(ip);
        });

        const finalRanges = splitRange(range.start, range.end, rangeExcludes);
        
        if (finalRanges.length === 0) {
            results.push(`${line}: No IPs left (Empty Range)`);
        } else {
            finalRanges.forEach(r => {
                const startStr = isV4 ? bigIntToIPv4(r.start) : bigIntToIPv6(r.start);
                const endStr = isV4 ? bigIntToIPv4(r.end) : bigIntToIPv6(r.end);
                
                if (outputFormat === 'range') {
                    if (r.start === r.end) {
                        results.push(startStr);
                    } else {
                        results.push(`${startStr} - ${endStr}`);
                    }
                } else {
                    // List Mode
                    let current = r.start;
                    while (current <= r.end) {
                        if (currentTotal >= MAX_IPS) break;
                        results.push(isV4 ? bigIntToIPv4(current) : bigIntToIPv6(current));
                        current++;
                        currentTotal++;
                    }
                }
            });
        }
    }
    
    document.getElementById('cidr-output').value = results.join('\n');
    const countLabel = outputFormat === 'range' ? 'Total Ranges' : 'Total IPs';
    const countVal = outputFormat === 'range' ? results.length : currentTotal;
    document.getElementById('cidr-stats').innerText = `${countLabel}: ${countVal}${outputFormat === 'list' && currentTotal >= MAX_IPS ? ' (Limit Reached)' : ''}`;
}

// ==========================================
// Tab 2: IP/Range/List to CIDR (Aggregation)
// ==========================================
function convertIPToCIDR() {
    const input = document.getElementById('ip-input').value;
    const outputFormat = document.querySelector('input[name="ip-output-format"]:checked').value;
    const excludeNetwork = document.getElementById('ip-exclude-network').checked;
    const excludeBroadcast = document.getElementById('ip-exclude-broadcast').checked;
    const excludeGateway = document.getElementById('ip-exclude-gateway').checked;
    const customExcludeInput = document.getElementById('ip-custom-exclude').value;

    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    
    const customExcludesV4 = [];
    const customExcludesV6 = [];
    
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        const v = getIPVersion(l);
        if (v === 4 && isValidIPv4(l)) customExcludesV4.push(ipToBigInt(l));
        if (v === 6 && isValidIPv6(l)) customExcludesV6.push(ipToBigInt(l));
    });
    
    // 1. Collect all raw ranges
    const rawRangesV4 = [];
    const rawRangesV6 = [];

    lines.forEach(line => {
        let start = null;
        let end = null;
        let version = 0;

        if (isValidCIDR(line)) {
            const r = getCIDRRange(line);
            start = r.start;
            end = r.end;
            version = r.version;
        } else if (line.includes('-')) {
            const parts = line.split('-').map(s => s.trim());
            if (parts.length === 2) {
                const v1 = getIPVersion(parts[0]);
                const v2 = getIPVersion(parts[1]);
                if (v1 === v2 && v1 !== 0) {
                    if (v1 === 4 && isValidIPv4(parts[0]) && isValidIPv4(parts[1])) {
                        start = ipToBigInt(parts[0]);
                        end = ipToBigInt(parts[1]);
                        version = 4;
                    } else if (v1 === 6 && isValidIPv6(parts[0]) && isValidIPv6(parts[1])) {
                        start = ipToBigInt(parts[0]);
                        end = ipToBigInt(parts[1]);
                        version = 6;
                    }
                }
            }
        } else {
            const v = getIPVersion(line);
            if (v === 4 && isValidIPv4(line)) {
                start = ipToBigInt(line);
                end = start;
                version = 4;
            } else if (v === 6 && isValidIPv6(line)) {
                start = ipToBigInt(line);
                end = start;
                version = 6;
            }
        }

        if (start !== null && end !== null && start <= end) {
            if (version === 4) rawRangesV4.push({start, end});
            if (version === 6) rawRangesV6.push({start, end});
        } else {
            // Ignore invalid lines silently or log?
            // For aggregation, partial valid input is better than full failure.
            // Maybe add error lines to output? But we are aggregating...
            // Let's skip invalid for now.
        }
    });

    // 2. Merge Ranges
    const mergedV4 = mergeRanges(rawRangesV4);
    const mergedV6 = mergeRanges(rawRangesV6);

    // 3. Process Merged Ranges (Exclusions & Formatting)
    const processRanges = (ranges, version) => {
        const isV4 = (version === 4);
        const relevantCustom = isV4 ? customExcludesV4 : customExcludesV6;

        ranges.forEach(range => {
            const rangeExcludes = [];
            
            // Apply Exclusions
            // Note: Exclusions apply to the AGGREGATED range.
            // E.g. if we aggregated 192.168.1.0-255 (/24).
            // Exclude Network means exclude .0.
            // Exclude Broadcast means exclude .255.
            if (excludeNetwork) rangeExcludes.push(range.start);
            if (excludeBroadcast) rangeExcludes.push(range.end);
            if (excludeGateway) rangeExcludes.push(range.start + 1n);
            
            relevantCustom.forEach(ip => {
                if (ip >= range.start && ip <= range.end) rangeExcludes.push(ip);
            });

            const finalRanges = splitRange(range.start, range.end, rangeExcludes);

            finalRanges.forEach(r => {
                if (outputFormat === 'cidr') {
                    const cidrs = rangeToCIDRBigInt(r.start, r.end, version);
                    results.push(...cidrs);
                } else {
                    // Range Format
                    const startStr = isV4 ? bigIntToIPv4(r.start) : bigIntToIPv6(r.start);
                    const endStr = isV4 ? bigIntToIPv4(r.end) : bigIntToIPv6(r.end);
                    if (r.start === r.end) {
                        results.push(startStr);
                    } else {
                        results.push(`${startStr} - ${endStr}`);
                    }
                }
            });
        });
    };

    if (mergedV4.length > 0) processRanges(mergedV4, 4);
    if (mergedV6.length > 0) processRanges(mergedV6, 6);

    if (results.length === 0 && lines.length > 0) {
        results.push("No valid IP data found to convert.");
    }
    
    document.getElementById('ip-output').value = results.join('\n');
    document.getElementById('ip-stats').innerText = `Total Rows: ${results.length}`;
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
