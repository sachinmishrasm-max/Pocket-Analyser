/**
 * DPI Engine — Interactive JavaScript Simulator
 * Author: Sachin Mishra
 * Deep Packet Inspection Engine Web UI
 */

'use strict';

// ============================================================
// APP COLORS — for each application type
// ============================================================
const APP_COLORS = {
    'YouTube':    '#ef4444',
    'Netflix':    '#e50914',
    'TikTok':     '#69c9d0',
    'Facebook':   '#1877f2',
    'Instagram':  '#e1306c',
    'WhatsApp':   '#25d366',
    'Telegram':   '#0088cc',
    'Discord':    '#5865f2',
    'Zoom':       '#2d8cff',
    'Spotify':    '#1db954',
    'Twitter/X':  '#1d9bf0',
    'Google':     '#4285f4',
    'Microsoft':  '#00a4ef',
    'Apple':      '#a2aaad',
    'GitHub':     '#6e5494',
    'Amazon':     '#ff9900',
    'Cloudflare': '#f38020',
    'HTTPS':      '#6366f1',
    'HTTP':       '#f59e0b',
    'DNS':        '#10b981',
    'Unknown':    '#64748b',
};

// ============================================================
// SAMPLE TRAFFIC DATA  
// ============================================================
const SAMPLE_TRAFFIC = [
    { sni: 'www.youtube.com',       app: 'YouTube',    dst_ip: '142.250.185.110', dst_port: 443, protocol: 'TCP' },
    { sni: 'www.netflix.com',       app: 'Netflix',    dst_ip: '23.52.167.61',    dst_port: 443, protocol: 'TCP' },
    { sni: 'www.tiktok.com',        app: 'TikTok',     dst_ip: '99.86.0.100',     dst_port: 443, protocol: 'TCP' },
    { sni: 'www.facebook.com',      app: 'Facebook',   dst_ip: '157.240.1.35',    dst_port: 443, protocol: 'TCP' },
    { sni: 'www.instagram.com',     app: 'Instagram',  dst_ip: '157.240.1.174',   dst_port: 443, protocol: 'TCP' },
    { sni: 'web.whatsapp.com',      app: 'WhatsApp',   dst_ip: '157.240.1.50',    dst_port: 443, protocol: 'TCP' },
    { sni: 'web.telegram.org',      app: 'Telegram',   dst_ip: '35.186.227.140',  dst_port: 443, protocol: 'TCP' },
    { sni: 'discord.com',           app: 'Discord',    dst_ip: '104.16.85.20',    dst_port: 443, protocol: 'TCP' },
    { sni: 'zoom.us',               app: 'Zoom',       dst_ip: '35.186.224.25',   dst_port: 443, protocol: 'TCP' },
    { sni: 'open.spotify.com',      app: 'Spotify',    dst_ip: '35.186.224.47',   dst_port: 443, protocol: 'TCP' },
    { sni: 'twitter.com',           app: 'Twitter/X',  dst_ip: '104.244.42.65',   dst_port: 443, protocol: 'TCP' },
    { sni: 'www.google.com',        app: 'Google',     dst_ip: '142.250.185.206', dst_port: 443, protocol: 'TCP' },
    { sni: 'www.microsoft.com',     app: 'Microsoft',  dst_ip: '13.107.42.14',    dst_port: 443, protocol: 'TCP' },
    { sni: 'github.com',            app: 'GitHub',     dst_ip: '140.82.114.4',    dst_port: 443, protocol: 'TCP' },
    { sni: 'www.amazon.com',        app: 'Amazon',     dst_ip: '52.94.236.248',   dst_port: 443, protocol: 'TCP' },
    { sni: 'www.cloudflare.com',    app: 'Cloudflare', dst_ip: '192.0.78.24',     dst_port: 443, protocol: 'TCP' },
    { sni: 'example.com',           app: 'HTTP',       dst_ip: '93.184.216.34',   dst_port: 80,  protocol: 'TCP' },
    { sni: '',                       app: 'DNS',        dst_ip: '8.8.8.8',         dst_port: 53,  protocol: 'UDP' },
    { sni: 'httpbin.org',           app: 'HTTP',       dst_ip: '185.199.108.153', dst_port: 80,  protocol: 'TCP' },
    { sni: '',                       app: 'Unknown',    dst_ip: '192.0.2.1',       dst_port: 8080, protocol: 'TCP' },
];

// Random source IPs for simulation
const SRC_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102',
    '192.168.1.50',  '10.0.0.15',    '172.16.0.5'
];

// ============================================================
// STATE
// ============================================================
const state = {
    running: false,
    totalPackets: 0,
    forwarded: 0,
    dropped: 0,
    totalBytes: 0,
    flows: new Map(),
    sniMap: new Map(),
    appStats: new Map(),
    pktId: 0,
    blockedApps: new Set(),
    blockedDomains: [],
    blockedIPs: new Set(),
    speed: 200,
    batchSize: 15,
    fpStats: [0, 0, 0, 0],
    lbStats: [0, 0],
    intervals: [],
};

// ============================================================
// DOM REFS
// ============================================================
const $ = id => document.getElementById(id);
const packetFeed = $('packetFeed');
const chartBars = $('chartBars');
const sniList = $('sniList');
const flowList = $('flowList');
const threadGrid = $('threadGrid');

// ============================================================
// NAVBAR SCROLL EFFECT
// ============================================================
window.addEventListener('scroll', () => {
    const navbar = $('navbar');
    if (window.scrollY > 40) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// ============================================================
// ANIMATED COUNTER (hero stats)
// ============================================================
function animateCounter(el) {
    const target = parseInt(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    const duration = 1500;
    const start = performance.now();

    function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const value = Math.round(eased * target);
        el.textContent = value + suffix;
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

function initCounters() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.dataset.done) {
                entry.target.dataset.done = '1';
                animateCounter(entry.target);
            }
        });
    }, { threshold: 0.5 });

    document.querySelectorAll('[data-count]').forEach(el => observer.observe(el));
}

// ============================================================
// PACKET STREAM (hero decoration)
// ============================================================
function initPacketStream() {
    const container = $('packetStream');
    const packets = [
        { src: '192.168.1.100', dst: '142.250.x.x', app: 'YouTube', blocked: false },
        { src: '192.168.1.101', dst: '157.240.x.x', app: 'Facebook', blocked: true },
        { src: '10.0.0.15',    dst: '8.8.8.8',       app: 'DNS',     blocked: false },
        { src: '192.168.1.50', dst: '23.52.x.x',     app: 'Netflix', blocked: false },
        { src: '172.16.0.5',   dst: '104.16.x.x',    app: 'Discord', blocked: false },
        { src: '192.168.1.102',dst: '99.86.x.x',     app: 'TikTok',  blocked: true },
        { src: '192.168.1.100',dst: '35.186.x.x',    app: 'Zoom',    blocked: false },
        { src: '10.0.0.15',    dst: '140.82.x.x',    app: 'GitHub',  blocked: false },
    ];

    // Build duplicated stream
    const allPackets = [...packets, ...packets, ...packets];
    container.innerHTML = allPackets.map(p =>
        `<div class="stream-packet ${p.blocked ? 'blocked' : ''}">
            <span class="dot"></span>
            ${p.src} → ${p.dst} [${p.app}]
        </div>`
    ).join('');
}

// ============================================================
// TABS
// ============================================================
document.querySelectorAll('.doc-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.doc-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.doc-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        const panel = document.getElementById('tab-' + tab.dataset.tab);
        if (panel) panel.classList.add('active');
    });
});

// ============================================================
// COPY BUTTONS
// ============================================================
document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const text = btn.dataset.copy || btn.closest('.code-file').querySelector('.code-display').innerText;
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            btn.style.color = '#6ee7b7';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
        });
    });
});

// ============================================================
// DEMO CONTROLS
// ============================================================
// App toggles
document.querySelectorAll('.app-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
        btn.classList.toggle('active');
        const app = btn.dataset.app;
        if (btn.classList.contains('active')) {
            state.blockedApps.add(app);
        } else {
            state.blockedApps.delete(app);
        }
    });
});

// Domain input
const domainInput = $('domainInput');
const addDomainBtn = $('addDomainBtn');
const domainTagsEl = $('domainTags');

function addDomain(domain) {
    domain = domain.trim().toLowerCase();
    if (!domain || state.blockedDomains.includes(domain)) return;
    state.blockedDomains.push(domain);
    renderDomainTags();
}

addDomainBtn.addEventListener('click', () => {
    addDomain(domainInput.value);
    domainInput.value = '';
});

domainInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') { addDomain(domainInput.value); domainInput.value = ''; }
});

function renderDomainTags() {
    domainTagsEl.innerHTML = state.blockedDomains.map((d, i) =>
        `<div class="domain-tag">
            ${d}
            <button onclick="removeDomain(${i})">×</button>
        </div>`
    ).join('');
}

window.removeDomain = function(i) {
    state.blockedDomains.splice(i, 1);
    renderDomainTags();
};

// IP input
const ipInput = $('ipInput');
const addIpBtn = $('addIpBtn');
const ipTagsEl = $('ipTags');
const ipList = [];

addIpBtn.addEventListener('click', () => {
    const ip = ipInput.value.trim();
    if (!ip || ipList.includes(ip)) return;
    state.blockedIPs.add(ip);
    ipList.push(ip);
    renderIPTags();
    ipInput.value = '';
});

function renderIPTags() {
    ipTagsEl.innerHTML = ipList.map((ip, i) =>
        `<div class="domain-tag">
            ${ip}
            <button onclick="removeIP(${i})">×</button>
        </div>`
    ).join('');
}

window.removeIP = function(i) {
    state.blockedIPs.delete(ipList[i]);
    ipList.splice(i, 1);
    renderIPTags();
};

// Slider
const slider = $('packetSlider');
const countLabel = $('packetCount');
slider.addEventListener('input', () => {
    state.batchSize = parseInt(slider.value);
    countLabel.textContent = slider.value;
});

// Speed buttons
document.querySelectorAll('.speed-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.speed = parseInt(btn.dataset.speed);
        if (state.running) {
            stopSimulation();
            startSimulation();
        }
    });
});

// Start / Reset
$('startBtn').addEventListener('click', () => {
    if (state.running) {
        stopSimulation();
    } else {
        startSimulation();
    }
});

$('resetBtn').addEventListener('click', () => {
    stopSimulation();
    resetState();
});

// ============================================================
// THREAD GRID INIT
// ============================================================
function initThreadGrid() {
    threadGrid.innerHTML = `
        ${[0,1].map(i => `
            <div class="thread-node" id="lb${i}Node">
                <div class="thread-node-label">LB${i}</div>
                <div class="thread-bar-track"><div class="thread-bar-fill" id="lb${i}Bar" style="width:0%"></div></div>
                <div class="thread-count" id="lb${i}Count">0 pkts</div>
            </div>
        `).join('')}
        ${[0,1,2,3].map(i => `
            <div class="thread-node" id="fp${i}Node">
                <div class="thread-node-label">FP${i}</div>
                <div class="thread-bar-track"><div class="thread-bar-fill" id="fp${i}Bar" style="width:0%"></div></div>
                <div class="thread-count" id="fp${i}Count">0 pkts</div>
            </div>
        `).join('')}
    `;
}

// ============================================================
// SIMULATION ENGINE
// ============================================================
function startSimulation() {
    state.running = true;
    const btn = $('startBtn');
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Stop`;

    const liveDot = $('liveDot');
    liveDot.classList.add('active');

    // Clear empty message
    if (packetFeed.querySelector('.feed-empty')) {
        packetFeed.innerHTML = '';
    }

    function tick() {
        if (!state.running) return;
        const batchCount = Math.max(1, Math.floor(state.batchSize / 3));
        for (let i = 0; i < batchCount; i++) {
            processPacket();
        }
        updateUI();
        state.intervals[0] = setTimeout(tick, state.speed);
    }

    tick();
}

function stopSimulation() {
    state.running = false;
    clearTimeout(state.intervals[0]);
    const btn = $('startBtn');
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Start Analysis`;
    $('liveDot').classList.remove('active');
}

function resetState() {
    state.totalPackets = 0;
    state.forwarded = 0;
    state.dropped = 0;
    state.totalBytes = 0;
    state.flows.clear();
    state.sniMap.clear();
    state.appStats.clear();
    state.pktId = 0;
    state.fpStats = [0, 0, 0, 0];
    state.lbStats = [0, 0];
    packetFeed.innerHTML = `<div class="feed-empty">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" opacity="0.3">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.5"/>
        </svg>
        <p>Click "Start Analysis" to begin</p>
    </div>`;
    chartBars.innerHTML = '<div class="chart-empty">No data yet</div>';
    sniList.innerHTML = '<div class="sni-empty">Awaiting data...</div>';
    flowList.innerHTML = '<div class="flow-empty">No active flows</div>';
    updateStatsBar();
    initThreadGrid();
}

function processPacket() {
    // Pick random traffic sample
    const sample = SAMPLE_TRAFFIC[Math.floor(Math.random() * SAMPLE_TRAFFIC.length)];
    const srcIp = SRC_IPS[Math.floor(Math.random() * SRC_IPS.length)];
    const srcPort = 49152 + Math.floor(Math.random() * 16383);
    const pktSize = 64 + Math.floor(Math.random() * 1400);

    // Determine if blocked
    const isBlockedApp = state.blockedApps.has(sample.app);
    const isBlockedDomain = state.blockedDomains.some(d => sample.sni.includes(d));
    const isBlockedIP = state.blockedIPs.has(srcIp);
    const blocked = isBlockedApp || isBlockedDomain || isBlockedIP;

    // 5-tuple flow key
    const flowKey = `${srcIp}:${srcPort}-${sample.dst_ip}:${sample.dst_port}`;

    // Update flow table (max 20 flows displayed)
    if (!state.flows.has(flowKey)) {
        if (state.flows.size >= 20) {
            const firstKey = state.flows.keys().next().value;
            state.flows.delete(firstKey);
        }
        state.flows.set(flowKey, {
            app: sample.app,
            sni: sample.sni,
            packets: 0,
            bytes: 0,
            blocked,
            srcIp,
            dstIp: sample.dst_ip,
            protocol: sample.protocol,
        });
    }

    const flow = state.flows.get(flowKey);
    flow.packets++;
    flow.bytes += pktSize;
    if (blocked) flow.blocked = true;

    // Update SNI map
    if (sample.sni) {
        state.sniMap.set(sample.sni, { app: sample.app, blocked });
    }

    // Update app stats
    state.appStats.set(sample.app, (state.appStats.get(sample.app) || 0) + 1);

    // Update counters
    state.totalPackets++;
    state.totalBytes += pktSize;
    if (blocked) state.dropped++;
    else state.forwarded++;

    // Fake thread dispatch
    const lbIdx = Math.floor(Math.random() * 2);
    const fpIdx = Math.floor(Math.random() * 4);
    state.lbStats[lbIdx]++;
    state.fpStats[fpIdx]++;

    // Add to feed
    addFeedRow({
        id: ++state.pktId,
        srcIp,
        srcPort,
        dstIp: sample.dst_ip,
        dstPort: sample.dst_port,
        sni: sample.sni,
        app: sample.app,
        blocked,
        size: pktSize,
    });
}

function addFeedRow(pkt) {
    // Remove empty state
    const empty = packetFeed.querySelector('.feed-empty');
    if (empty) empty.remove();

    // Keep max 80 rows
    while (packetFeed.children.length >= 80) {
        packetFeed.removeChild(packetFeed.lastChild);
    }

    const appColor = APP_COLORS[pkt.app] || '#64748b';
    const row = document.createElement('div');
    row.className = `feed-row ${pkt.blocked ? 'blocked' : 'forwarded'}`;
    row.innerHTML = `
        <span class="feed-id">#${pkt.id}</span>
        <span class="feed-src">${pkt.srcIp}:${pkt.srcPort}</span>
        <span class="feed-dst">${pkt.dstIp}:${pkt.dstPort}</span>
        <span class="feed-sni">${pkt.sni || '—'}</span>
        <span class="feed-status ${pkt.blocked ? 'status-drop' : 'status-fwd'}">
            ${pkt.blocked ? '⛔ DROP' : '✓ FWD'}
        </span>
        <span class="feed-size">${pkt.size}B</span>
    `;
    packetFeed.insertBefore(row, packetFeed.firstChild);
}

// ============================================================
// UI UPDATES
// ============================================================
function updateUI() {
    updateStatsBar();
    updateChart();
    updateSNIList();
    updateFlowList();
    updateThreadNodes();
    updateArchDiagram();
}

function updateStatsBar() {
    $('statTotal').textContent = state.totalPackets.toLocaleString();
    $('statForwarded').textContent = state.forwarded.toLocaleString();
    $('statDropped').textContent = state.dropped.toLocaleString();
    $('statFlows').textContent = state.flows.size;
    const kb = (state.totalBytes / 1024).toFixed(1);
    $('statBytes').textContent = kb > 999 ? (kb / 1024).toFixed(1) + ' MB' : kb + ' KB';
}

const CHART_COLORS = [
    '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981',
    '#f59e0b', '#ef4444', '#ec4899', '#6366f1',
    '#14b8a6', '#f97316'
];

function updateChart() {
    if (state.appStats.size === 0) return;

    const sorted = [...state.appStats.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const total = state.totalPackets;

    chartBars.innerHTML = sorted.map(([app, count], i) => {
        const pct = total > 0 ? (count / total * 100) : 0;
        const color = APP_COLORS[app] || CHART_COLORS[i % CHART_COLORS.length];
        return `<div class="chart-bar-row">
            <span class="chart-bar-label">${app}</span>
            <div class="chart-bar-track">
                <div class="chart-bar-fill" style="width:${pct.toFixed(1)}%; background:${color}"></div>
            </div>
            <span class="chart-bar-value">${pct.toFixed(1)}%</span>
        </div>`;
    }).join('');
}

function updateSNIList() {
    if (state.sniMap.size === 0) return;

    const items = [...state.sniMap.entries()].slice(-15).reverse();

    if (sniList.querySelector('.sni-empty')) sniList.innerHTML = '';

    // Rebuild list (compact approach)
    sniList.innerHTML = items.map(([domain, info]) => {
        const color = APP_COLORS[info.app] || '#64748b';
        return `<div class="sni-item">
            <span class="sni-domain">${domain}</span>
            <span class="sni-app" style="background:${color}22; color:${color}">${info.app}</span>
        </div>`;
    }).join('');
}

function updateFlowList() {
    if (state.flows.size === 0) return;
    if (flowList.querySelector('.flow-empty')) flowList.innerHTML = '';

    const flows = [...state.flows.entries()].slice(-8).reverse();
    flowList.innerHTML = flows.map(([key, flow]) => {
        const color = APP_COLORS[flow.app] || '#64748b';
        return `<div class="flow-item">
            <div class="flow-tuple">${flow.srcIp} → ${flow.dstIp}</div>
            <div class="flow-meta">
                <span style="color:${color}">${flow.app}</span>
                <span>${flow.packets} pkts</span>
                <span>${(flow.bytes/1024).toFixed(1)}KB</span>
                ${flow.blocked ? '<span style="color:#fca5a5">BLOCKED</span>' : '<span style="color:#6ee7b7">OK</span>'}
            </div>
        </div>`;
    }).join('');
}

function updateThreadNodes() {
    const maxLB = Math.max(...state.lbStats, 1);
    const maxFP = Math.max(...state.fpStats, 1);

    state.lbStats.forEach((count, i) => {
        const bar = document.getElementById(`lb${i}Bar`);
        const countEl = document.getElementById(`lb${i}Count`);
        if (bar) bar.style.width = (count / maxLB * 100) + '%';
        if (countEl) countEl.textContent = count.toLocaleString() + ' pkts';
    });

    state.fpStats.forEach((count, i) => {
        const bar = document.getElementById(`fp${i}Bar`);
        const countEl = document.getElementById(`fp${i}Count`);
        if (bar) bar.style.width = (count / maxFP * 100) + '%';
        if (countEl) countEl.textContent = count.toLocaleString() + ' pkts';
    });
}

function updateArchDiagram() {
    const maxFP = Math.max(...state.fpStats, 1);
    state.fpStats.forEach((count, i) => {
        const bar = document.querySelector(`#archFP${i} .arch-bar-fill`);
        if (bar) bar.style.width = (count / maxFP * 100) + '%';
    });
}

// ============================================================
// MOBILE NAV TOGGLE
// ============================================================
$('navToggle').addEventListener('click', () => {
    const links = document.querySelector('.nav-links');
    if (links) {
        links.style.display = links.style.display === 'flex' ? 'none' : 'flex';
    }
});

// ============================================================
// SMOOTH SCROLL FOR NAV LINKS
// ============================================================
document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
        const target = document.querySelector(link.getAttribute('href'));
        if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// ============================================================
// INTERSECTION ANIMATIONS
// ============================================================
function initScrollAnimations() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });

    document.querySelectorAll('.feature-card, .arch-detail-card, .sidebar-section').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        observer.observe(el);
    });
}

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initCounters();
    initPacketStream();
    initThreadGrid();
    initScrollAnimations();
});
