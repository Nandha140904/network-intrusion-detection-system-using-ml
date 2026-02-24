// Dashboard JavaScript - Real-time Updates and Interactivity

// Initialize WebSocket connection
const socket = io();

// Chart instances
let trafficChart = null;
let attackChart = null;

// State
let isMonitoring = false;
let alertCount = 0;

// DOM Elements
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const refreshBtn = document.getElementById('refresh-btn');
const connectionStatus = document.getElementById('connection-status');
const monitoringStatus = document.getElementById('monitoring-status');
const totalPacketsEl = document.getElementById('total-packets');
const normalTrafficEl = document.getElementById('normal-traffic');
const attacksDetectedEl = document.getElementById('attacks-detected');
const attackRateEl = document.getElementById('attack-rate');
const alertCountEl = document.getElementById('alert-count');
const alertsContainer = document.getElementById('alerts-container');
const trafficFeedContainer = document.getElementById('traffic-feed-container');

// Initialize Charts
function initCharts() {
    // Traffic Classification Chart
    const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'doughnut',
        data: {
            labels: ['Normal Traffic', 'Attacks'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#10b981', '#ef4444'],
                borderColor: ['#059669', '#dc2626'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#f1f5f9', font: { size: 14 } }
                }
            }
        }
    });

    // Attack Distribution Chart
    const attackCtx = document.getElementById('attack-chart').getContext('2d');
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['DoS', 'Probe', 'R2L', 'U2R'],
            datasets: [{
                label: 'Attack Count',
                data: [0, 0, 0, 0],
                backgroundColor: '#8b5cf6',
                borderColor: '#7c3aed',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                },
                x: {
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#f1f5f9', font: { size: 14 } }
                }
            }
        }
    });
}

// WebSocket Event Handlers
socket.on('connect', () => {
    console.log('Connected to server');
    connectionStatus.textContent = 'Connected';
    connectionStatus.className = 'status-badge connected';
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    connectionStatus.textContent = 'Disconnected';
    connectionStatus.className = 'status-badge disconnected';
});

socket.on('stats_update', (data) => {
    updateStats(data);
});

socket.on('traffic_update', (data) => {
    addTrafficFeedItem(data);
});

socket.on('new_alert', (alert) => {
    addAlert(alert);
});

socket.on('alert_system_update', (alert) => {
    // Additional high-confidence alert from alert system - already shown, skip duplicate
    console.log('High-confidence alert:', alert);
});

// Update Statistics
function updateStats(stats) {
    totalPacketsEl.textContent = stats.total_packets || 0;
    normalTrafficEl.textContent = stats.normal_traffic || 0;
    attacksDetectedEl.textContent = stats.attacks_detected || 0;
    attackRateEl.textContent = (stats.attack_rate || 0).toFixed(2) + '%';

    // Update traffic chart
    if (trafficChart) {
        trafficChart.data.datasets[0].data = [
            stats.normal_traffic || 0,
            stats.attacks_detected || 0
        ];
        trafficChart.update();
    }
}

// Add Traffic Feed Item
function addTrafficFeedItem(data) {
    // Remove "no data" placeholder
    const noData = trafficFeedContainer.querySelector('.no-data');
    if (noData) noData.remove();

    const feedItem = document.createElement('div');
    const isAttack = data.prediction !== 'normal';
    feedItem.className = `feed-item ${isAttack ? 'attack' : 'normal'}`;

    const confPct = data.confidence_pct
        || ((data.confidence * 100).toFixed(1) + '%');
    const timeStr = data.time_str
        || new Date(data.timestamp * 1000).toLocaleTimeString();
    const srcIp = data.source_ip || '—';
    const dstIp = data.dest_ip || '—';
    const proto = data.protocol || '—';

    feedItem.innerHTML = `
        <div class="feed-row feed-top">
            <span class="feed-prediction ${isAttack ? 'attack' : 'normal'}">
                ${isAttack ? '🚨' : '✅'} ${data.prediction.toUpperCase()}
            </span>
            <span class="feed-time">${timeStr}</span>
        </div>
        <div class="feed-row feed-meta">
            <span class="feed-meta-item"><span class="feed-label">SRC</span>${srcIp}</span>
            <span class="feed-arrow">→</span>
            <span class="feed-meta-item"><span class="feed-label">DST</span>${dstIp}</span>
        </div>
        <div class="feed-row feed-bottom">
            <span class="feed-meta-item"><span class="feed-label">PROTO</span>${proto}</span>
            <span class="feed-confidence">${confPct} confidence</span>
        </div>
    `;

    trafficFeedContainer.insertBefore(feedItem, trafficFeedContainer.firstChild);

    // Keep only last 15 items
    while (trafficFeedContainer.children.length > 15) {
        trafficFeedContainer.removeChild(trafficFeedContainer.lastChild);
    }
}

// Add Alert
function addAlert(alert) {
    // Remove "no alerts" message
    const noAlerts = alertsContainer.querySelector('.no-alerts');
    if (noAlerts) noAlerts.remove();

    alertCount++;
    alertCountEl.textContent = alertCount;

    const alertItem = document.createElement('div');
    const severity = alert.severity || 'MEDIUM';
    alertItem.className = `alert-item severity-${severity.toLowerCase()}`;

    alertItem.innerHTML = `
        <div class="alert-header">
            <span class="alert-type">🚨 ${alert.attack_type || 'UNKNOWN ATTACK'}</span>
            <span class="alert-severity badge-${severity.toLowerCase()}">${severity}</span>
            <span class="alert-time">${alert.timestamp}</span>
        </div>
        <div class="alert-details">
            <div class="alert-detail"><strong>Confidence:</strong> ${alert.confidence}</div>
            <div class="alert-detail"><strong>Source IP:</strong> ${alert.source_ip || 'Unknown'}</div>
            <div class="alert-detail"><strong>Dest IP:</strong> ${alert.dest_ip || 'Unknown'}</div>
            <div class="alert-detail"><strong>Protocol:</strong> ${alert.protocol || 'Unknown'}</div>
        </div>
    `;

    alertsContainer.insertBefore(alertItem, alertsContainer.firstChild);

    // Keep only last 20 alerts
    while (alertsContainer.children.length > 20) {
        alertsContainer.removeChild(alertsContainer.lastChild);
    }
}

// Fetch and Display Alerts
async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();

        if (data.alerts && data.alerts.length > 0) {
            alertsContainer.innerHTML = '';
            data.alerts.slice(0, 10).forEach(alert => addAlert(alert));
        }

        // Update attack distribution chart
        if (data.stats && data.stats.attack_distribution && attackChart) {
            const dist = data.stats.attack_distribution;
            attackChart.data.datasets[0].data = [
                dist.DoS || 0,
                dist.Probe || 0,
                dist.R2L || 0,
                dist.U2R || 0
            ];
            attackChart.update();
        }
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

// Fetch and populate the Live Traffic Feed from history (on page load / refresh)
async function fetchTrafficFeed() {
    try {
        const response = await fetch('/api/traffic');
        const events = await response.json();
        if (events && events.length > 0) {
            // Clear existing placeholder
            trafficFeedContainer.innerHTML = '';
            // Add each event (already newest-first from server)
            events.forEach(ev => addTrafficFeedItem(ev));
        }
    } catch (error) {
        console.error('Error fetching traffic feed:', error);
    }
}

// Fetch Statistics
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStats(stats);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Start Monitoring
async function startMonitoring() {
    try {
        const response = await fetch('/api/start_monitoring', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        const data = await response.json();

        if (data.success) {
            isMonitoring = true;
            monitoringStatus.textContent = 'Monitoring Active';
            monitoringStatus.className = 'status-badge active';
            startBtn.disabled = true;
            stopBtn.disabled = false;
            console.log('Monitoring started');
        } else {
            alert('Failed to start monitoring: ' + data.message);
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        alert('Error: ' + error.message);
    }
}

// Stop Monitoring
async function stopMonitoring() {
    try {
        const response = await fetch('/api/stop_monitoring', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            isMonitoring = false;
            monitoringStatus.textContent = 'Monitoring Inactive';
            monitoringStatus.className = 'status-badge inactive';
            startBtn.disabled = false;
            stopBtn.disabled = true;
            console.log('Monitoring stopped');
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
    }
}

// Event Listeners
startBtn.addEventListener('click', startMonitoring);
stopBtn.addEventListener('click', stopMonitoring);
refreshBtn.addEventListener('click', () => {
    fetchStats();
    fetchAlerts();
    fetchTrafficFeed();
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    fetchStats();
    fetchAlerts();
    fetchTrafficFeed();

    // Refresh stats + alerts + traffic feed every 3 seconds
    setInterval(() => {
        fetchStats();
        fetchAlerts();
        fetchTrafficFeed();
    }, 3000);

    // Refresh hosts every 5 seconds
    setInterval(() => {
        fetchHosts();
    }, 5000);

    // Initial hosts fetch
    fetchHosts();
});

// Known Hosts Logic
const hostsTableBody = document.querySelector('#hosts-table tbody');
const refreshHostsBtn = document.getElementById('refresh-hosts-btn');

if (refreshHostsBtn) {
    refreshHostsBtn.addEventListener('click', fetchHosts);
}

async function fetchHosts() {
    try {
        const response = await fetch('/api/hosts');
        const hosts = await response.json();

        renderHosts(hosts);
    } catch (error) {
        console.error('Error fetching hosts:', error);
    }
}

function renderHosts(hosts) {
    if (!hostsTableBody) return;

    hostsTableBody.innerHTML = '';

    if (hosts.length === 0) {
        hostsTableBody.innerHTML = '<tr class="no-data-row"><td colspan="6">No hosts detected yet.</td></tr>';
        return;
    }

    hosts.forEach(host => {
        const row = document.createElement('tr');

        // Status class
        let statusClass = 'neutral';
        if (host.status === 'malicious') statusClass = 'malicious';
        else if (host.status === 'suspicious') statusClass = 'suspicious';

        // Format dates
        const firstSeen = new Date(host.first_seen).toLocaleString();
        const lastSeen = new Date(host.last_seen).toLocaleString();

        row.innerHTML = `
            <td>${host.ip}</td>
            <td><span class="status-badge ${statusClass}">${host.status.toUpperCase()}</span></td>
            <td>${host.packet_count}</td>
            <td>${host.alert_count}</td>
            <td>${firstSeen}</td>
            <td>${lastSeen}</td>
        `;

        hostsTableBody.appendChild(row);
    });
}
