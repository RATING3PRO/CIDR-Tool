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
    
    // Calculate network address
    // 0xFFFFFFFF is -1 in JS bitwise, so use >>> 0 to keep it unsigned
    const offset = 32 - mask;
    const networkMask = (0xFFFFFFFF << offset) >>> 0;
    const networkAddress = (ipLong & networkMask) >>> 0;
    
    // Calculate broadcast address
    // Invert mask and OR with network address
    const broadcastAddress = (networkAddress | (~networkMask >>> 0)) >>> 0;
    
    return {
        start: networkAddress,
        end: broadcastAddress,
        mask: mask
    };
}

// Logic: Range -> CIDR List
function rangeToCIDR(startIp, endIp) {
    let start = ipToLong(startIp);
    let end = ipToLong(endIp);
    const cidrs = [];
    
    // Validate
    if (start === null || end === null || start > end) {
        return [`Error: Invalid range ${startIp}-${endIp}`];
    }

    while (start <= end) {
        // Find the lowest set bit (alignment)
        // If start is 0, lowest set bit is conceptually 32 (can fit any mask)
        // But we are limited by the block size
        
        let maxBlockSize = 1;
        // Count trailing zeros to find max alignment
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
        
        // Max block size based on alignment is 2^alignmentBits
        // We also need block size <= (end - start + 1)
        // Find largest n such that 2^n <= (end - start + 1) AND n <= alignmentBits
        
        const rangeSize = end - start + 1;
        let n = 0;
        
        // Find largest power of 2 that fits in rangeSize
        // We can loop n from 32 down to 0
        for (let i = 32; i >= 0; i--) {
            // Check if 2^i <= rangeSize
            // 1 << 31 is negative, so be careful with large shifts
            // rangeSize can be up to 2^32
            const size = (i === 32) ? 0xFFFFFFFF + 1 : (1 << i) >>> 0; // JS numbers are doubles, so 2^32 is fine
            
            // Wait, bitwise operators in JS treat operands as 32-bit signed integers.
            // 1 << 31 is -2147483648.
            // Let's use Math.pow for safety with large numbers, or just rely on the fact that rangeSize is usually checked with small n.
            // Actually, we can just check if (start + size - 1) <= end
            
            const blockSize = Math.pow(2, i);
            if (blockSize <= rangeSize && i <= alignmentBits) {
                n = i;
                break;
            }
        }
        
        const mask = 32 - n;
        cidrs.push(longToIp(start) + '/' + mask);
        
        // Move start
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
    
    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    
    lines.forEach(line => {
        if (!isValidCIDR(line)) {
            if (line) results.push(`Error: Invalid CIDR ${line}`);
            return;
        }
        
        const range = getCIDRRange(line);
        let start = range.start;
        let end = range.end;
        
        // Logic for exclusions
        // Network Address: Always the first IP in the subnet block (start)
        if (excludeNetwork) {
            if (start === range.start) start++;
        }
        
        // Broadcast Address: Always the last IP in the subnet block (end)
        if (excludeBroadcast) {
            if (end === range.end) end--;
        }
        
        // Gateway: Usually the first usable IP (Network + 1)
        // If we already excluded Network, Start is now Network + 1.
        // If we want to exclude Gateway, we should skip Network + 1.
        if (excludeGateway) {
            const gateway = range.start + 1;
            // If our current start covers the gateway, move past it
            if (start <= gateway) {
                start = gateway + 1;
            }
            // Note: If gateway was the broadcast address (e.g. /31 or /32), this might push start > end
        }
        
        if (start > end) {
            results.push(`${line}: No IPs left (Empty Range)`);
        } else {
            // Output format: Start IP - End IP
            if (start === end) {
                results.push(longToIp(start));
            } else {
                results.push(`${longToIp(start)} - ${longToIp(end)}`);
            }
        }
    });
    
    document.getElementById('cidr-output').value = results.join('\n');
    document.getElementById('cidr-stats').innerText = `Total Rows: ${results.length}`;
}

function convertIPToCIDR() {
    const input = document.getElementById('ip-input').value;
    const lines = input.split('\n').map(l => l.trim()).filter(l => l);
    const results = [];
    
    lines.forEach(line => {
        // Handle "IP - IP" format
        if (line.includes('-')) {
            const parts = line.split('-').map(s => s.trim());
            if (parts.length === 2 && isValidIP(parts[0]) && isValidIP(parts[1])) {
                const cidrs = rangeToCIDR(parts[0], parts[1]);
                results.push(...cidrs);
            } else {
                results.push(`Error: Invalid Range ${line}`);
            }
        } 
        // Handle Single IP
        else if (isValidIP(line)) {
            results.push(`${line}/32`);
        } 
        // Handle invalid
        else {
            results.push(`Error: Invalid Input ${line}`);
        }
    });
    
    document.getElementById('ip-output').value = results.join('\n');
    document.getElementById('ip-stats').innerText = `Total CIDRs: ${results.length}`;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Set default tab
    switchTab('cidr-to-ip');
});

// Copy to Clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    
    // Feedback (optional, could use a toast)
    const btn = document.querySelector(`button[onclick="copyToClipboard('${elementId}')"]`);
    const originalText = btn.innerText;
    btn.innerText = '已复制!';
    setTimeout(() => {
        btn.innerText = originalText;
    }, 2000);
}
