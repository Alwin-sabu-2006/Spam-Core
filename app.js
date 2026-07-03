// SpamGuard Core - Main Application Logic

// Local State
let history = [];
let modelDetails = null;

// Tab Routing Configs
const panelInfo = {
    'panel-message': {
        title: 'Message Classifier',
        desc: 'Linguistic Natural Language Processing and statistical spam detection.'
    },
    'panel-link': {
        title: 'Link Threat Scanner',
        desc: 'Reputation scanning against Google Safe Browsing and link anomaly heuristics.'
    },
    'panel-news': {
        title: 'News Credibility Validator',
        desc: 'Verify fake news claims and article headlines against Google fact-check registries.'
    },
    'panel-dev': {
        title: 'Developer Console & Configurations',
        desc: 'Real-time security auditing console and active vocabulary probabilities.'
    }
};

// DOM Cache
const navItems = document.querySelectorAll('.nav-item');
const panels = document.querySelectorAll('.dashboard-panel');
const panelTitle = document.getElementById('active-panel-title');
const panelDesc = document.getElementById('active-panel-desc');

// Header elements
const headerVocab = document.getElementById('header-vocab-size');
const googleStatusBadge = document.getElementById('google-api-status');

// Console Log Element
const consoleLogs = document.getElementById('console-logs');

// Tab 1: Message Elements
const messageText = document.getElementById('message-text');
const charCountText = document.getElementById('text-char-count');
const wordCountText = document.getElementById('text-word-count');
const analyzeMsgBtn = document.getElementById('analyze-msg-btn');
const clearMsgBtn = document.getElementById('clear-msg-btn');
const fileUploader = document.getElementById('file-uploader');
const dropzone = document.getElementById('dropzone');

const classifierIdle = document.getElementById('classifier-idle');
const classifierLoading = document.getElementById('classifier-loading');
const classifierOutput = document.getElementById('classifier-output');

const verdictBanner = document.getElementById('verdict-banner');
const verdictIcon = document.getElementById('verdict-icon');
const verdictText = document.getElementById('verdict-text');
const verdictConfidencePct = document.getElementById('verdict-confidence-pct');
const resultThreatPercentage = document.getElementById('result-threat-percentage');
const resultThreatFill = document.getElementById('result-threat-fill');
const resultExplanation = document.getElementById('result-metric-explanation');
const highlightedOutputBox = document.getElementById('highlighted-output-box');

// Stats Counters
const statRatio = document.getElementById('stat-ratio');
const statUrgency = document.getElementById('stat-urgency');
const statDigits = document.getElementById('stat-digits');
const statCaps = document.getElementById('stat-caps');

// Table lists
const logsTableBody = document.querySelector('#logs-table tbody');
const historyExportBtn = document.getElementById('history-export-btn');
const historyClearBtn = document.getElementById('history-clear-btn');
const vocabProbTableBody = document.querySelector('#vocab-prob-table tbody');
const clearConsoleBtn = document.getElementById('clear-console-btn');

// Tab 2: Link Elements
const urlInput = document.getElementById('url-input');
const scanUrlBtn = document.getElementById('scan-url-btn');
const urlIdle = document.getElementById('url-idle');
const urlLoading = document.getElementById('url-loading');
const urlOutput = document.getElementById('url-output');

const urlVerdict = document.getElementById('url-verdict');
const urlVerdictIcon = document.getElementById('url-verdict-icon');
const urlVerdictText = document.getElementById('url-verdict-text');
const urlVerdictSource = document.getElementById('url-verdict-source');
const urlVerdictDetails = document.getElementById('url-verdict-details');
const urlFlagsLog = document.getElementById('url-flags-log');

// Tab 3: News Elements
const newsQuery = document.getElementById('news-query');
const checkNewsBtn = document.getElementById('check-news-btn');
const newsEngineSource = document.getElementById('news-engine-source');
const newsIdle = document.getElementById('news-idle');
const newsLoading = document.getElementById('news-loading');
const newsOutput = document.getElementById('news-output');
const newsCardsContainer = document.getElementById('news-cards-container');

// Auditing Modal Elements
const auditModal = document.getElementById('audit-details-modal');
const closeModalBtn = document.getElementById('close-modal-btn');
const modalMetaTime = document.getElementById('modal-meta-time');
const modalMetaBadge = document.getElementById('modal-meta-badge');
const modalTextContent = document.getElementById('modal-text-content');
const modalLogLikelihood = document.getElementById('modal-log-likelihood-calc');

// App Initialization
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initSystemMetrics();
    loadHistory();
    setupClassifierListeners();
    setupLinkListeners();
    setupNewsListeners();
    setupGeneralListeners();
    logToConsole('SYSTEM: SpamGuard Core successfully initialized.');
});

// Helper for Developer Terminal Logs
function logToConsole(message, type = 'sys') {
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    entry.innerHTML = `[${time}] ${message}`;
    consoleLogs.appendChild(entry);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

// System Config Metrics & API key status lookup on load
async function initSystemMetrics() {
    try {
        logToConsole('API: GET /api/system-status - Establishing backend handshake...', 'api');
        const response = await fetch('/api/system-status');
        if (!response.ok) throw new Error('System stats request returned bad status');
        
        const status = await response.json();
        logToConsole(`POST: /api/system-status - Connected. Model Trained: ${status.model_trained}, Vocab Size: ${status.vocab_size}`, 'post');
        
        // Update header UI
        headerVocab.textContent = status.vocab_size.toLocaleString();
        
        // Google Cloud API key indicator
        if (status.api_attached) {
            googleStatusBadge.innerHTML = '<span class="status-dot online"></span> ACTIVE';
            googleStatusBadge.className = 'status-value';
            logToConsole('SYSTEM: Google Cloud credentials attached in backend server.', 'sys');
        } else {
            googleStatusBadge.innerHTML = '<span class="status-dot offline"></span> SANDBOX';
            googleStatusBadge.className = 'status-value';
            logToConsole('SYSTEM: Google API key missing. Operating in Keyless Sandbox Mode.', 'sys');
        }
    } catch (e) {
        logToConsole(`ERROR: Backend connection failure: ${e.message}`, 'err');
        googleStatusBadge.innerHTML = '<span class="status-dot offline"></span> OFFLINE';
        googleStatusBadge.className = 'status-value';
    }
}

// 1. Sidebar Tabs Routing Manager
function initTabs() {
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-target');
            if (!target) return;
            
            // Toggle active classes
            navItems.forEach(n => n.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            
            item.classList.add('active');
            const targetPanel = document.getElementById(target);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }
            
            // Update Title Panel information
            const info = panelInfo[target];
            if (info) {
                panelTitle.textContent = info.title;
                panelDesc.textContent = info.desc;
            }
            
            logToConsole(`SYSTEM: Navigated to [${info ? info.title : target}] dashboard view.`, 'sys');
        });
    });
}

// 2. Setup Events
function setupClassifierListeners() {
    // Word/Character counts
    messageText.addEventListener('input', () => {
        const text = messageText.value;
        charCountText.textContent = `${text.length} character${text.length !== 1 ? 's' : ''}`;
        
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        wordCountText.textContent = `${words} word${words !== 1 ? 's' : ''}`;
    });

    // Execute Analysis
    analyzeMsgBtn.addEventListener('click', () => {
        const text = messageText.value.trim();
        if (text) {
            analyzeMessage(text);
        } else {
            alert('Please enter text content to analyze.');
        }
    });

    // Clear Text Sandbox
    clearMsgBtn.addEventListener('click', () => {
        messageText.value = '';
        charCountText.textContent = '0 characters';
        wordCountText.textContent = '0 words';
        resetClassifierUI();
        logToConsole('SYSTEM: Message sandbox input buffers flushed.', 'sys');
    });

    // File Drag/Drop
    dropzone.addEventListener('click', () => fileUploader.click());
    fileUploader.addEventListener('change', handleFileSelect);
    
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });
    
    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });
    
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });
}

function setupLinkListeners() {
    scanUrlBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (url) {
            scanLinkThreats(url);
        } else {
            alert('Please enter a URL link to scan.');
        }
    });
}

function setupNewsListeners() {
    checkNewsBtn.addEventListener('click', () => {
        const query = newsQuery.value.trim();
        if (query) {
            verifyNewsClaim(query);
        } else {
            alert('Please enter a news headline or query search string.');
        }
    });
}

function setupGeneralListeners() {
    historyClearBtn.addEventListener('click', clearAuditHistory);
    historyExportBtn.addEventListener('click', exportAuditLogsToCSV);
    clearConsoleBtn.addEventListener('click', () => {
        consoleLogs.innerHTML = '';
        logToConsole('SYSTEM: Dev Console logs cleared.', 'sys');
    });
    
    // Modal Close
    closeModalBtn.addEventListener('click', () => auditModal.classList.remove('active'));
    window.addEventListener('click', (e) => {
        if (e.target === auditModal) {
            auditModal.classList.remove('active');
        }
    });
}

function resetClassifierUI() {
    classifierIdle.classList.add('active');
    classifierLoading.classList.remove('active');
    classifierOutput.classList.remove('active');
    
    statRatio.textContent = '0.0%';
    statUrgency.textContent = 'None';
    statDigits.textContent = '0 digits';
    statCaps.textContent = '0 words';
    
    vocabProbTableBody.innerHTML = `
        <tr class="table-empty-row">
            <td colspan="5">Run a text message scan to view keyword breakdown.</td>
        </tr>
    `;
}

// 3. API - Message Classifier Service
async function analyzeMessage(text, saveLog = true) {
    classifierIdle.classList.remove('active');
    classifierLoading.classList.add('active');
    classifierOutput.classList.remove('active');
    
    logToConsole(`API: POST /api/analyze-text - Payload size: ${text.length} characters.`, 'api');
    
    try {
        const response = await fetch('/api/analyze-text', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: text})
        });
        
        if (!response.ok) throw new Error('API server request rejected');
        const data = await response.json();
        
        logToConsole(`POST: /api/analyze-text - Classified: ${data.isSpam ? 'SPAM' : 'HAM'} (Confidence: ${(data.confidence * 100).toFixed(2)}%)`, 'post');
        
        // Render Interface
        renderClassifierResults(data, text);
        
        if (saveLog) {
            const auditRecord = {
                id: Date.now(),
                timestamp: new Date().toLocaleString(),
                message: text,
                isSpam: data.isSpam,
                confidence: data.confidence,
                logSpam: data.logSpam,
                logHam: data.logHam,
                matched: data.matched,
                tokens: data.tokens
            };
            history.unshift(auditRecord);
            if (history.length > 50) history.pop();
            localStorage.setItem('spamguard_core_history', JSON.stringify(history));
            renderHistoryTable();
        }
        
        classifierLoading.classList.remove('active');
        classifierOutput.classList.add('active');
        
    } catch (e) {
        logToConsole(`ERROR: Classification failed: ${e.message}`, 'err');
        resetClassifierUI();
    }
}

function renderClassifierResults(data, originalText) {
    const isSpam = data.isSpam;
    const confidencePct = (data.confidence * 100).toFixed(1) + '%';
    
    // Update main verdict banner
    verdictBanner.className = `verdict-banner ${isSpam ? 'spam' : 'ham'}`;
    verdictIcon.className = isSpam ? 'fa-solid fa-triangle-exclamation' : 'fa-solid fa-check-double';
    verdictText.textContent = isSpam ? 'SPAM FLAGGED' : 'HAM (SAFE)';
    verdictConfidencePct.textContent = confidencePct;
    
    // Progress bar calculations
    const threatPct = isSpam ? (data.confidence * 100).toFixed(1) + '%' : ((1 - data.confidence) * 100).toFixed(1) + '%';
    resultThreatPercentage.textContent = threatPct;
    resultThreatFill.style.width = threatPct;
    resultThreatFill.style.backgroundColor = isSpam ? 'var(--color-danger)' : 'var(--color-safe)';
    
    resultExplanation.textContent = isSpam
        ? `Linguistic scanning maps high-risk indicators inside the message. Threat: ${threatPct}`
        : `Linguistic analysis returns secure communication scores. Safe: ${(data.confidence * 100).toFixed(1)}%`;
        
    // Text triggers mapping markup
    highlightedOutputBox.innerHTML = generateHighlighterHTML(originalText, data.matched);
    
    // Auxiliary Stats Calculations
    const stats = calculateLexicalStats(originalText, data.tokens, data.matched);
    statRatio.textContent = stats.density;
    statUrgency.textContent = stats.urgency;
    statDigits.textContent = stats.numeric;
    statCaps.textContent = stats.caps;
    
    // Render Active Vocabulary Math Table in panel 4
    renderVocabTable(data.matched);
}

function generateHighlighterHTML(text, matched) {
    let safeText = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const spamTokens = new Set(matched.filter(t => t.ratio > 1.5).map(t => t.word));
    
    const parts = safeText.split(/(\b\w+\b)/g);
    return parts.map(part => {
        const lower = part.toLowerCase();
        if (spamTokens.has(lower)) {
            return `<span class="highlight-word spam-token">${part}</span>`;
        }
        return part;
    }).join('');
}

function calculateLexicalStats(text, tokens, matched) {
    const spammyWords = matched.filter(t => t.ratio > 1.5).length;
    const density = tokens.length > 0 ? (spammyWords / tokens.length) * 100 : 0;
    
    const digits = (text.match(/\d/g) || []).length;
    
    const words = text.split(/\s+/);
    const capsWords = words.filter(w => {
        const clean = w.replace(/[^A-Za-z]/g, '');
        return clean.length >= 3 && clean === clean.toUpperCase();
    }).length;
    
    const urgency = [];
    if (text.includes('!')) urgency.push('!');
    if (/\$|£|€|rs\b/i.test(text)) urgency.push('Currency');
    if (/https?:\/\/\S+/i.test(text)) urgency.push('URL Link');
    if (/\b(free|win|prize|claim|urgent|cash|winner|selected|pin|atm)\b/i.test(text)) urgency.push('Threat Terms');
    
    return {
        density: density.toFixed(1) + '%',
        urgency: urgency.length > 0 ? urgency.join(', ') : 'None',
        numeric: `${digits} digit${digits !== 1 ? 's' : ''}`,
        caps: `${capsWords} word${capsWords !== 1 ? 's' : ''}`
    };
}

function renderVocabTable(matched) {
    if (!matched || matched.length === 0) {
        vocabProbTableBody.innerHTML = `
            <tr class="table-empty-row">
                <td colspan="5">No known vocabulary keywords found in this message.</td>
            </tr>
        `;
        return;
    }
    
    // Sort by ratio desc
    const sorted = [...matched].sort((a, b) => b.ratio - a.ratio);
    vocabProbTableBody.innerHTML = sorted.map(item => {
        let tagClass = 'ham';
        let tagName = 'Safe Ham';
        if (item.ratio > 2.0) {
            tagClass = 'spam';
            tagName = 'Spam Trigger';
        } else if (item.ratio >= 0.5 && item.ratio <= 2.0) {
            tagClass = 'suspicious';
            tagName = 'Neutral';
        }
        
        return `
            <tr>
                <td><strong>${item.word}</strong></td>
                <td class="text-danger">${item.pSpam.toExponential(3)}</td>
                <td class="text-safe">${item.pHam.toExponential(3)}</td>
                <td>${item.ratio.toFixed(2)}x</td>
                <td><span class="badge ${tagClass}">${tagName}</span></td>
            </tr>
        `;
    }).join('');
}

// 4. API - Link Threat Scanner Service
async function scanLinkThreats(url) {
    urlIdle.classList.remove('active');
    urlLoading.classList.add('active');
    urlOutput.classList.remove('active');
    
    logToConsole(`API: POST /api/scan-link - Target URL: "${url}"`, 'api');
    
    try {
        const response = await fetch('/api/scan-link', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        
        if (!response.ok) throw new Error('API server request rejected');
        const data = await response.json();
        
        logToConsole(`POST: /api/scan-link - Result status: ${data.status} via ${data.source}`, 'post');
        
        // Update Link results UI
        renderLinkResults(data);
        
        urlLoading.classList.remove('active');
        urlOutput.classList.add('active');
    } catch (e) {
        logToConsole(`ERROR: Link scan failed: ${e.message}`, 'err');
        urlIdle.classList.add('active');
        urlLoading.classList.remove('active');
        urlOutput.classList.remove('active');
    }
}

function renderLinkResults(data) {
    const stat = data.status.toLowerCase();
    
    // Set banner classes
    urlVerdict.className = `verdict-banner ${stat}`;
    urlVerdictText.textContent = data.status + ' VERDICT';
    urlVerdictSource.textContent = data.source;
    
    if (stat === 'safe') {
        urlVerdictIcon.className = 'fa-solid fa-shield-check';
        urlVerdictDetails.textContent = data.details;
        urlFlagsLog.innerHTML = 'All threat metrics safe.<br>[x] DNS blacklist clean<br>[x] Subdomain brand impersonation clean<br>[x] Heuristic anomaly indicators clean';
    } else if (stat === 'suspicious') {
        urlVerdictIcon.className = 'fa-solid fa-triangle-exclamation';
        urlVerdictDetails.textContent = data.details;
        
        let flagsHTML = '';
        if (data.flags && data.flags.length > 0) {
            flagsHTML = data.flags.map(f => `<span class="text-warn">[!] FLAG:</span> ${f}`).join('<br>');
        }
        urlFlagsLog.innerHTML = flagsHTML;
    } else if (stat === 'danger') {
        urlVerdictIcon.className = 'fa-solid fa-radiation';
        urlVerdictDetails.textContent = data.details;
        urlFlagsLog.innerHTML = `<span class="text-danger">[CRITICAL]</span> Threats matched in database: Phishing / Fraudulent Social Engineering.`;
    }
}

// 5. API - News Credibility verification Service
async function verifyNewsClaim(query) {
    newsIdle.classList.remove('active');
    newsLoading.classList.add('active');
    newsOutput.style.display = 'none';
    
    logToConsole(`API: POST /api/fact-check - Query string: "${query}"`, 'api');
    
    try {
        const response = await fetch('/api/fact-check', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query: query})
        });
        
        if (!response.ok) throw new Error('API server request rejected');
        const data = await response.json();
        
        logToConsole(`POST: /api/fact-check - Status: ${data.status} via ${data.source}`, 'post');
        
        // Update news source badge
        newsEngineSource.textContent = data.source;
        newsEngineSource.className = 'badge ham';
        
        // Build cards
        renderNewsClaims(data.claims, data.ai_summary);
        
        newsLoading.classList.remove('active');
        newsOutput.style.display = 'block';
    } catch (e) {
        logToConsole(`ERROR: News fact checking failed: ${e.message}`, 'err');
        newsIdle.classList.add('active');
        newsLoading.classList.remove('active');
        newsOutput.style.display = 'none';
    }
}

function renderNewsClaims(claims, aiSummary) {
    let aiCardHTML = '';
    if (aiSummary) {
        let verdictClass = 'suspicious';
        const vUpper = (aiSummary.verdict || 'UNVERIFIED').toUpperCase();
        if (vUpper.includes('TRUE')) {
            verdictClass = 'ham';
        } else if (vUpper.includes('FALSE') || vUpper.includes('OUTDATED')) {
            verdictClass = 'spam';
        }
        
        const bulletsHTML = (aiSummary.facts || []).map(f => `<li><i class="fa-solid fa-circle-check" style="margin-right: 6px; color: var(--color-brand);"></i> ${f}</li>`).join('');
        
        aiCardHTML = `
            <div class="news-card ai-summary-card" style="background: linear-gradient(135deg, rgba(56, 189, 248, 0.07) 0%, rgba(16, 185, 129, 0.03) 100%); border: 1px solid rgba(56, 189, 248, 0.15); margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2); width: 100%;">
                <div class="news-card-header" style="border-bottom: 1px dashed rgba(56, 189, 248, 0.15); padding-bottom: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; width: 100%;">
                    <span class="news-card-source" style="color: var(--color-brand); font-weight: 600;"><i class="fa-solid fa-robot pulse"></i> SpamGuard AI Summarizer</span>
                    <span class="badge ${verdictClass}">${aiSummary.verdict}</span>
                </div>
                <h4 class="news-card-claim" style="font-style: italic; font-weight: 500; font-size: 0.95rem; line-height: 1.5; color: #ffffff; margin-bottom: 12px;">
                    "${aiSummary.summary}"
                </h4>
                <div style="background: rgba(10, 13, 20, 0.3); border-radius: 6px; padding: 12px; border-left: 3px solid var(--color-brand);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; font-family: var(--font-mono); color: var(--text-muted); display: block; margin-bottom: 6px;">AI Verified Facts:</span>
                    <ul style="margin: 0; padding: 0 0 0 5px; list-style: none; color: var(--text-sub); font-size: 0.85rem; display: flex; flex-direction: column; gap: 6px;">
                        ${bulletsHTML}
                    </ul>
                </div>
            </div>
        `;
    }

    if (!claims || claims.length === 0) {
        newsCardsContainer.innerHTML = aiCardHTML + `
            <div class="news-card">
                <span class="news-card-source"><i class="fa-solid fa-triangle-exclamation"></i> Threat Scanner</span>
                <h4 class="news-card-claim">No records matched your query terms.</h4>
                <p class="news-card-explanation">This search query matches no cataloged disinformation hoaxes or claims inside the databases. It is recommended to cross-reference multiple independent sources.</p>
            </div>
        `;
        return;
    }
    
    const claimsHTML = claims.map(claim => {
        let rClass = 'ham';
        let rLabel = claim.rating;
        
        if (claim.rating.includes('FALSE') || claim.rating.includes('DEBUNKED')) {
            rClass = 'spam';
        } else if (claim.rating.includes('NEUTRAL') || claim.rating.includes('UNKNOWN') || claim.rating.includes('SUSPICIOUS')) {
            rClass = 'suspicious';
        }
        
        return `
            <div class="news-card">
                <div class="news-card-header">
                    <span class="news-card-source"><i class="fa-solid fa-building-columns"></i> ${claim.publisher}</span>
                    <span class="badge ${rClass}">${rLabel}</span>
                </div>
                <h4 class="news-card-claim">Claim: "${claim.text}"</h4>
                <span class="subtext-detail">Claimant Source: ${claim.claimant}</span>
                <p class="news-card-explanation">${claim.details}</p>
                <a href="${claim.url}" target="_blank" class="news-card-link"><i class="fa-solid fa-arrow-up-right-from-square"></i> Read Full Review</a>
            </div>
        `;
    }).join('');

    newsCardsContainer.innerHTML = aiCardHTML + claimsHTML;
}

// 6. History Local Storage Logger
function loadHistory() {
    const data = localStorage.getItem('spamguard_core_history');
    history = data ? JSON.parse(data) : [];
    renderHistoryTable();
}

function renderHistoryTable() {
    if (history.length === 0) {
        logsTableBody.innerHTML = `
            <tr class="table-empty-row">
                <td colspan="5">No logs in buffer. Initiate analyses to record audit trails.</td>
            </tr>
        `;
        return;
    }
    
    logsTableBody.innerHTML = history.map(item => {
        const snippet = item.message.length > 50 ? item.message.substring(0, 50) + '...' : item.message;
        const bClass = item.isSpam ? 'spam' : 'ham';
        const bLabel = item.isSpam ? 'SPAM' : 'HAM';
        
        return `
            <tr>
                <td>${item.timestamp}</td>
                <td><span class="text-snippet font-mono text-sm" title="${item.message.replace(/"/g, '&quot;')}">${snippet}</span></td>
                <td><span class="badge ${bClass}">${bLabel}</span></td>
                <td>${(item.confidence * 100).toFixed(1)}%</td>
                <td><button onclick="showAuditDetails(${item.id})" class="btn btn-secondary btn-sm" style="margin: 0; width: auto;"><i class="fa-solid fa-binoculars"></i> Audit</button></td>
            </tr>
        `;
    }).join('');
}

function clearAuditHistory() {
    if (confirm('Verify: Purge local audit history logs from buffer?')) {
        history = [];
        localStorage.removeItem('spamguard_core_history');
        renderHistoryTable();
        logToConsole('SYSTEM: Local audit history tables purged.', 'sys');
    }
}

function showAuditDetails(id) {
    const item = history.find(h => h.id === id);
    if (!item) return;
    
    modalMetaTime.textContent = item.timestamp;
    modalMetaBadge.className = `badge ${item.isSpam ? 'spam' : 'ham'}`;
    modalMetaBadge.textContent = item.isSpam ? 'SPAM' : 'HAM';
    modalTextContent.textContent = item.message;
    
    const spamLikelihoodStr = item.logSpam.toFixed(2);
    const hamLikelihoodStr = item.logHam.toFixed(2);
    
    modalLogLikelihood.innerHTML = `
        <strong>Probability Logs Matrix:</strong><br>
        • Log Likelihood P(Spam | Message): <code>${spamLikelihoodStr}</code><br>
        • Log Likelihood P(Ham | Message): <code>${hamLikelihoodStr}</code><br>
        • Confidence Classifier normalization: <strong>${(item.confidence * 100).toFixed(3)}%</strong><br><br>
        <em>Bayes Theorem log-likelihood values represent the sum of probabilities log(P) to eliminate decimal float underflow errors during execution.</em>
    `;
    
    auditModal.classList.add('active');
}

window.showAuditDetails = showAuditDetails;

function exportAuditLogsToCSV() {
    if (history.length === 0) {
        alert('No audit logs available for export.');
        return;
    }
    
    let csv = 'data:text/csv;charset=utf-8,';
    csv += 'Timestamp,Classification,Confidence,Message\r\n';
    
    history.forEach(item => {
        const msg = `"${item.message.replace(/"/g, '""')}"`;
        const cls = item.isSpam ? 'SPAM' : 'HAM';
        const conf = (item.confidence * 100).toFixed(2) + '%';
        csv += `${item.timestamp},${cls},${conf},${msg}\r\n`;
    });
    
    const uri = encodeURI(csv);
    const link = document.createElement('a');
    link.href = uri;
    link.download = `spamguard_audit_logs_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    logToConsole('SYSTEM: Audit history data exported to CSV file.', 'sys');
}

// 7. Bulk Upload Handlers
function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
}

function handleFile(file) {
    const reader = new FileReader();
    const isCSV = file.name.endsWith('.csv');
    const isTXT = file.name.endsWith('.txt');
    
    if (!isCSV && !isTXT) {
        alert('Format not supported. Please upload a .txt or .csv file.');
        return;
    }
    
    logToConsole(`SYSTEM: File upload detected: "${file.name}" (${(file.size/1024).toFixed(2)} KB)`, 'sys');
    
    reader.onload = function(e) {
        const text = e.target.result;
        
        if (isTXT) {
            // Load content inside message area and trigger click
            messageText.value = text;
            messageText.dispatchEvent(new Event('input'));
            analyzeMessage(text);
        } else if (isCSV) {
            batchProcessCSV(text);
        }
    };
    
    reader.readAsText(file);
}

// Bulk CSV Parser
async function batchProcessCSV(csvContent) {
    const lines = csvContent.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length === 0) return;
    
    let startIdx = 0;
    if (lines[0].toLowerCase().includes('message') || lines[0].toLowerCase().includes('text')) {
        startIdx = 1;
    }
    
    logToConsole(`API: Starting bulk CSV batch scans. Payload count: ${lines.length - startIdx} rows.`, 'api');
    
    let spamCount = 0;
    let hamCount = 0;
    
    for (let i = startIdx; i < lines.length; i++) {
        let text = lines[i];
        if (text.startsWith('"') && text.endsWith('"')) {
            text = text.substring(1, text.length - 1).replace(/""/g, '"');
        }
        
        if (!text.trim()) continue;
        
        try {
            // We run request synchronously sequentially for local server handling
            const response = await fetch('/api/analyze-text', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({text: text})
            });
            const data = await response.json();
            
            if (data.isSpam) spamCount++; else hamCount++;
            
            const auditRecord = {
                id: Date.now() + i,
                timestamp: new Date().toLocaleString(),
                message: text,
                isSpam: data.isSpam,
                confidence: data.confidence,
                logSpam: data.logSpam,
                logHam: data.logHam,
                matched: data.matched,
                tokens: data.tokens
            };
            history.unshift(auditRecord);
        } catch (err) {
            console.error(err);
        }
    }
    
    if (history.length > 50) history = history.slice(0, 50);
    localStorage.setItem('spamguard_core_history', JSON.stringify(history));
    renderHistoryTable();
    
    logToConsole(`POST: Batch CSV analysis completed. Flagged Spam: ${spamCount}, Classified Ham: ${hamCount}`, 'post');
    alert(`CSV Batch Scan Complete!\n- Flagged as Spam: ${spamCount}\n- Classified as Ham: ${hamCount}\n\nLogs appended to local audit history below.`);
}

// Handle Logout
const logoutBtn = document.getElementById('logout-btn');
if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login.html';
        } catch (e) {
            console.error('Logout failed', e);
        }
    });
}
