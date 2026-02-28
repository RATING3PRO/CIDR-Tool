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

// IP Utilities
function ipToLong(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    return ((parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) | (parseInt(parts[2]) << 8) | parseInt(parts[3])) >>> 0;
}

function longToIp(long) {
    return [
        (long >>> 24) & 0xFF,
        (long >>> 16) & 0xFF,
        (long >>> 8) & 0xFF,
        long & 0xFF
    ].join('.');
}

function isValidIP(ip) {
    if (!ip) return false;
    const pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!pattern.test(ip)) return false;
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part);
        return num >= 0 && num <= 255;
    });
}

function isValidCIDR(cidr) {
    if (!cidr) return false;
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    if (!isValidIP(parts[0])) return false;
    const mask = parseInt(parts[1]);
    return !isNaN(mask) && mask >= 0 && mask <= 32;
}

// Logic: CIDR -> Range
function getCIDRRange(cidr) {
    const [ip, maskStr] = cidr.split('/');
    const mask = parseInt(maskStr);
    const ipLong = ipToLong(ip);
    
    const offset = 32 - mask;
    const networkMask = (0xFFFFFFFF << offset) >>> 0;
    const networkAddress = (ipLong & networkMask) >>> 0;
    const broadcastAddress = (networkAddress | (~networkMask >>> 0)) >>> 0;
    
    return {
        start: networkAddress,
        end: broadcastAddress,
        mask: mask
    };
}

// Logic: Range Splitting for Exclusions
function splitRange(start, end, excludeIPs) {
    let ranges = [{start: start, end: end}];
    
    // excludeIPs should be a sorted Set or Array of unique integers
    const sortedExcludes = Array.from(new Set(excludeIPs)).sort((a, b) => a - b);
    
    sortedExcludes.forEach(exclude => {
        const newRanges = [];
        ranges.forEach(range => {
            if (exclude >= range.start && exclude <= range.end) {
                // Split logic
                // 1. Left part: range.start to exclude - 1
                if (range.start <= exclude - 1) {
                    newRanges.push({start: range.start, end: exclude - 1});
                }
                // 2. Right part: exclude + 1 to range.end
                if (exclude + 1 <= range.end) {
                    newRanges.push({start: exclude + 1, end: range.end});
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

// Logic: Range -> CIDR List
function rangeToCIDR(startIp, endIp) {
    let start;
    let end;
    
    // Support numeric input or string input
    if (typeof startIp === 'number') start = startIp;
    else start = ipToLong(startIp);
    
    if (typeof endIp === 'number') end = endIp;
    else end = ipToLong(endIp);

    const cidrs = [];
    
    if (start === null || end === null || start > end) {
        // If passed as numbers, they might be valid but start > end
        // If passed as strings and invalid, ipToLong returns null
        return []; 
    }

    while (start <= end) {
        let maxBlockSize = 1;
        let temp = start;
        let alignmentBits = 0;
        
        if (start === 0) {
            alignmentBits = 32;
        } else {
            while ((temp & 1) === 0 && alignmentBits < 32) {
                temp >>>= 1;
                alignmentBits++;
            }
        }
        
        const rangeSize = end - start + 1;
        let n = 0;
        
        for (let i = 32; i >= 0; i--) {
            const blockSize = Math.pow(2, i);
            if (blockSize <= rangeSize && i <= alignmentBits) {
                n = i;
                break;
            }
        }
        
        const mask = 32 - n;
        cidrs.push(longToIp(start) + '/' + mask);
        start += Math.pow(2, n);
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
    const customExcludes = [];
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        if (isValidIP(l)) {
            customExcludes.push(ipToLong(l));
        }
    });

    lines.forEach(line => {
        if (!isValidCIDR(line)) {
            if (line) results.push(`Error: Invalid CIDR ${line}`);
            return;
        }
        
        const range = getCIDRRange(line);
        const rangeExcludes = [];

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
            rangeExcludes.push(range.start + 1);
        }

        // Custom Excludes
        customExcludes.forEach(ip => {
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
                if (r.start === r.end) {
                    results.push(longToIp(r.start));
                } else {
                    results.push(`${longToIp(r.start)} - ${longToIp(r.end)}`);
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
    const customExcludes = [];
    const customLines = customExcludeInput.split('\n').map(l => l.trim()).filter(l => l);
    customLines.forEach(l => {
        if (isValidIP(l)) {
            customExcludes.push(ipToLong(l));
        }
    });
    
    lines.forEach(line => {
        let start = null;
        let end = null;
        let isValid = false;

        // Handle "IP - IP" format
        if (line.includes('-')) {
            const parts = line.split('-').map(s => s.trim());
            if (parts.length === 2 && isValidIP(parts[0]) && isValidIP(parts[1])) {
                start = ipToLong(parts[0]);
                end = ipToLong(parts[1]);
                isValid = true;
            }
        } 
        // Handle Single IP
        else if (isValidIP(line)) {
            start = ipToLong(line);
            end = start;
            isValid = true;
        }

        if (isValid && start !== null && end !== null) {
             if (start > end) {
                 results.push(`Error: Invalid Range ${line} (Start > End)`);
                 return;
             }

             const rangeExcludes = [];

             // Apply Exclusions based on Range logic (Start/End)
             // Note: This applies to the *input range*, which might not be a CIDR block.
             if (excludeNetwork) {
                 rangeExcludes.push(start);
             }
             if (excludeBroadcast) {
                 rangeExcludes.push(end);
             }
             if (excludeGateway) {
                 rangeExcludes.push(start + 1);
             }
             
             // Custom Excludes
             customExcludes.forEach(ip => {
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
                     const cidrs = rangeToCIDR(r.start, r.end);
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
