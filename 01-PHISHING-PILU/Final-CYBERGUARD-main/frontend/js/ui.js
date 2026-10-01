/**
 * CYBERGUARD UI MANAGER
 * Handles state transitions, cinematic animations, SVG risk gauge, and history tracking.
 */
class UIManager {
    constructor() {
        this.currentMode = 'message';
        this.currentChannel = 'EMAIL';
        this.currentResultData = null;
        this.historyFilter = 'ALL';
        this.loadingInterval = null;

        // Cache DOM Elements
        this.dom = {
            // Main Views
            dashboardView: document.getElementById('dashboardView'),
            workspaceView: document.getElementById('workspaceView'),
            historyView: document.getElementById('historyView'),
            resultScreen: document.getElementById('resultScreen'),
            toastContainer: document.getElementById('toastContainer'),

            // Navigation
            navAnalyze: document.getElementById('navAnalyze'),
            navHistory: document.getElementById('navHistory'),
            systemDot: document.getElementById('systemDot'),
            systemStatusText: document.getElementById('systemStatusText'),
            systemSubText: document.getElementById('systemSubText'),
            historyCountBadge: document.getElementById('historyCountBadge'),

            // Workspace Header
            workspaceTitle: document.getElementById('workspaceTitle'),
            workspaceSubtitle: document.getElementById('workspaceSubtitle'),
            workspaceDesc: document.getElementById('workspaceDesc'),
            contextSignalValue: document.getElementById('contextSignalValue'),
            contextEngineStatus: document.getElementById('contextEngineStatus'),

            // Mode Panels
            panelMessage: document.getElementById('message-panel'),
            panelUrl: document.getElementById('url-panel'),
            panelQr: document.getElementById('qr-panel'),

            // Command Switcher
            tabModeMessage: document.getElementById('tabModeMessage'),
            tabModeUrl: document.getElementById('tabModeUrl'),
            tabModeQr: document.getElementById('tabModeQr'),

            // Message Sub-tabs & Sub-views
            subTabEmail: document.getElementById('subTabEmail'),
            subTabSms: document.getElementById('subTabSms'),
            subTabSocial: document.getElementById('subTabSocial'),
            subViewEmail: document.getElementById('subViewEmail'),
            subViewSms: document.getElementById('subViewSms'),
            subViewSocial: document.getElementById('subViewSocial'),
            messageChannelBadge: document.getElementById('messageChannelBadge'),

            // Inputs
            msgSubject: document.getElementById('msgSubject'),
            msgInput: document.getElementById('msgInput'),
            smsInput: document.getElementById('smsInput'),
            socialInput: document.getElementById('socialInput'),
            urlInput: document.getElementById('urlInput'),
            msgCharCount: document.getElementById('msgCharCount'),
            smsCharCount: document.getElementById('smsCharCount'),
            socialCharCount: document.getElementById('socialCharCount'),

            // QR Components
            qrDropZone: document.getElementById('qrDropZone'),
            qrFileInput: document.getElementById('qrFileInput'),
            qrPreview: document.getElementById('qrPreview'),
            qrPreviewContainer: document.getElementById('qrPreviewContainer'),
            qrPlaceholderContent: document.getElementById('qrPlaceholderContent'),
            qrFileName: document.getElementById('qrFileName'),
            qrFileSize: document.getElementById('qrFileSize'),
            btnAnalyzeQr: document.getElementById('btnAnalyzeQr'),

            // Loading Overlay
            loadingState: document.getElementById('loadingState'),
            loadingBrandTitle: document.getElementById('loadingBrandTitle'),
            loadingSubtext: document.getElementById('loadingSubtext'),
            step1Text: document.getElementById('step1Text'),
            step2Text: document.getElementById('step2Text'),
            step3Text: document.getElementById('step3Text'),
            step4Text: document.getElementById('step4Text'),

            // Results Components
            resultTimestamp: document.getElementById('resultTimestamp'),
            gaugePath: document.getElementById('riskGaugePath'),
            scoreValue: document.getElementById('riskScoreValue'),
            severityLabel: document.getElementById('riskSeverityLabel'),
            summaryClassification: document.getElementById('summaryClassification'),
            summaryProbability: document.getElementById('summaryProbability'),
            summaryAction: document.getElementById('summaryAction'),
            summaryTargetType: document.getElementById('summaryTargetType'),
            extractedContentBox: document.getElementById('extractedContentBox'),
            extractedText: document.getElementById('extractedText'),
            btnCopyDecodedUrl: document.getElementById('btnCopyDecodedUrl'),
            viewInputBox: document.getElementById('viewInputBox'),
            btnToggleInput: document.getElementById('btnToggleInput'),
            originalInputText: document.getElementById('originalInputText'),
            inputContextType: document.getElementById('inputContextType'),
            explanationList: document.getElementById('explanationList'),
            recommendationAction: document.getElementById('recommendationAction'),
            recommendationText: document.getElementById('recommendationText'),

            // History
            historyListContainer: document.getElementById('historyListContainer'),
            historyEmptyState: document.getElementById('historyEmptyState')
        };

        // Initialize history count
        this.updateHistoryBadge();
    }

    setSystemStatus(isOnline, hostInfo = '') {
        if (!this.dom.systemDot) return;
        if (isOnline) {
            this.dom.systemDot.className = 'status-dot online';
            this.dom.systemStatusText.textContent = 'ONLINE';
            this.dom.systemStatusText.style.color = 'var(--color-primary)';
            if (this.dom.systemSubText) {
                this.dom.systemSubText.textContent = hostInfo || 'HYBRID ML READY';
            }
        } else {
            this.dom.systemDot.className = 'status-dot error';
            this.dom.systemStatusText.textContent = 'OFFLINE';
            this.dom.systemStatusText.style.color = 'var(--color-critical)';
            if (this.dom.systemSubText) {
                this.dom.systemSubText.textContent = 'BACKEND UNREACHABLE';
            }
        }
    }

    showDashboard() {
        this.dom.workspaceView.classList.add('hidden');
        this.dom.historyView.classList.add('hidden');
        this.dom.dashboardView.classList.remove('hidden');
        if (this.dom.navAnalyze) this.dom.navAnalyze.classList.add('active');
        if (this.dom.navHistory) this.dom.navHistory.classList.remove('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    openWorkspace(mode = 'message') {
        this.dom.dashboardView.classList.add('hidden');
        this.dom.historyView.classList.add('hidden');
        this.dom.workspaceView.classList.remove('hidden');

        if (this.dom.navAnalyze) this.dom.navAnalyze.classList.add('active');
        if (this.dom.navHistory) this.dom.navHistory.classList.remove('active');

        this.setCommandMode(mode);
        this.hideResults();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    setCommandMode(mode) {
        this.currentMode = mode;

        // Reset switcher buttons
        [this.dom.tabModeMessage, this.dom.tabModeUrl, this.dom.tabModeQr].forEach(tab => {
            if (tab) tab.classList.remove('active');
        });

        // Hide all panels
        [this.dom.panelMessage, this.dom.panelUrl, this.dom.panelQr].forEach(panel => {
            if (panel) panel.classList.remove('active-section');
        });

        if (mode === 'message') {
            if (this.dom.tabModeMessage) this.dom.tabModeMessage.classList.add('active');
            if (this.dom.panelMessage) this.dom.panelMessage.classList.add('active-section');
            this.dom.workspaceSubtitle.textContent = 'CYBERGUARD / ANALYSIS / MESSAGE';
            this.dom.workspaceTitle.textContent = 'MESSAGE INTELLIGENCE';
            this.dom.workspaceDesc.textContent = 'Inspect emails, SMS and social conversations before interacting with them.';
            this.dom.contextSignalValue.textContent = `MESSAGE / ${this.currentChannel}`;
            this.dom.contextEngineStatus.textContent = 'READY (UNIFIED HYBRID)';
        } else if (mode === 'url') {
            if (this.dom.tabModeUrl) this.dom.tabModeUrl.classList.add('active');
            if (this.dom.panelUrl) this.dom.panelUrl.classList.add('active-section');
            this.dom.workspaceSubtitle.textContent = 'CYBERGUARD / ANALYSIS / URL';
            this.dom.workspaceTitle.textContent = 'URL INTELLIGENCE';
            this.dom.workspaceDesc.textContent = 'Deep-scan direct links and domain infrastructure for malicious patterns.';
            this.dom.contextSignalValue.textContent = 'DESTINATION URL';
            this.dom.contextEngineStatus.textContent = 'READY (42-D LEXICAL)';
        } else if (mode === 'qr') {
            if (this.dom.tabModeQr) this.dom.tabModeQr.classList.add('active');
            if (this.dom.panelQr) this.dom.panelQr.classList.add('active-section');
            this.dom.workspaceSubtitle.textContent = 'CYBERGUARD / ANALYSIS / QR';
            this.dom.workspaceTitle.textContent = 'QR THREAT SCANNER';
            this.dom.workspaceDesc.textContent = 'Decode QR image matrix, extract hidden destination, and deep-scan URL targets.';
            this.dom.contextSignalValue.textContent = 'QR MATRIX IMAGE';
            this.dom.contextEngineStatus.textContent = 'READY (VISION + URL)';
        }
    }

    setMessageChannel(channel) {
        this.currentChannel = channel;

        // Reset sub tabs
        [this.dom.subTabEmail, this.dom.subTabSms, this.dom.subTabSocial].forEach(tab => {
            if (tab) tab.classList.remove('active');
        });

        // Hide all sub views
        [this.dom.subViewEmail, this.dom.subViewSms, this.dom.subViewSocial].forEach(view => {
            if (view) {
                view.classList.add('hidden');
                view.classList.remove('active');
            }
        });

        if (channel === 'EMAIL') {
            if (this.dom.subTabEmail) this.dom.subTabEmail.classList.add('active');
            if (this.dom.subViewEmail) {
                this.dom.subViewEmail.classList.remove('hidden');
                this.dom.subViewEmail.classList.add('active');
            }
            if (this.dom.messageChannelBadge) this.dom.messageChannelBadge.textContent = 'EMAIL ANALYZER';
        } else if (channel === 'SMS') {
            if (this.dom.subTabSms) this.dom.subTabSms.classList.add('active');
            if (this.dom.subViewSms) {
                this.dom.subViewSms.classList.remove('hidden');
                this.dom.subViewSms.classList.add('active');
            }
            if (this.dom.messageChannelBadge) this.dom.messageChannelBadge.textContent = 'SMS / SMISHING ANALYZER';
        } else if (channel === 'SOCIAL') {
            if (this.dom.subTabSocial) this.dom.subTabSocial.classList.add('active');
            if (this.dom.subViewSocial) {
                this.dom.subViewSocial.classList.remove('hidden');
                this.dom.subViewSocial.classList.add('active');
            }
            if (this.dom.messageChannelBadge) this.dom.messageChannelBadge.textContent = 'SOCIAL / CHAT ANALYZER';
        }

        if (this.dom.contextSignalValue) {
            this.dom.contextSignalValue.textContent = `MESSAGE / ${channel}`;
        }
    }

    showHistory() {
        this.dom.dashboardView.classList.add('hidden');
        this.dom.workspaceView.classList.add('hidden');
        this.dom.historyView.classList.remove('hidden');

        if (this.dom.navAnalyze) this.dom.navAnalyze.classList.remove('active');
        if (this.dom.navHistory) this.dom.navHistory.classList.add('active');

        this.renderHistoryList();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showLoading(targetType = 'message') {
        this.dom.loadingState.classList.remove('hidden');

        if (targetType === 'message') {
            this.dom.loadingBrandTitle.textContent = 'AI MESSAGE INFERENCE';
            this.dom.loadingSubtext.textContent = 'EVALUATING LANGUAGE & SOCIAL ENGINEERING SIGNALS';
            this.dom.step1Text.textContent = 'INPUT RECEIVED & CANONICALIZED ✓';
            this.dom.step2Text.textContent = 'EXTRACTING 21 CYBER FEATURES ●';
            this.dom.step3Text.textContent = 'RUNNING DUAL-BRANCH HYBRID MODEL ○';
            this.dom.step4Text.textContent = 'ISOTONIC RISK CALIBRATION & XAI ○';
        } else if (targetType === 'url') {
            this.dom.loadingBrandTitle.textContent = 'URL INTELLIGENCE PIPELINE';
            this.dom.loadingSubtext.textContent = 'DEEP-SCANNING DOMAIN & INFRASTRUCTURE PATTERNS';
            this.dom.step1Text.textContent = 'URL CANONICALIZED & VALIDATED ✓';
            this.dom.step2Text.textContent = 'EXTRACTING 42 LEXICAL / TLD INDICATORS ●';
            this.dom.step3Text.textContent = 'HYBRID CNN & FEATURE MLP INFERENCE ○';
            this.dom.step4Text.textContent = 'CALIBRATING RISK PROBABILITY ○';
        } else if (targetType === 'qr') {
            this.dom.loadingBrandTitle.textContent = 'QR VISION & URL PIPELINE';
            this.dom.loadingSubtext.textContent = 'DECODING OPTICAL MATRIX & TRACING TARGET';
            this.dom.step1Text.textContent = 'DECODING QR MATRIX VIA MULTI-STAGE OPENCV ✓';
            this.dom.step2Text.textContent = 'EXTRACTING EMBEDDED DESTINATION URL ●';
            this.dom.step3Text.textContent = 'DISPATCHING TO URL INTELLIGENCE ENGINE ○';
            this.dom.step4Text.textContent = 'SYNTHESIZING XAI THREAT ASSESSMENT ○';
        }

        const steps = [
            document.getElementById('loadStep1'),
            document.getElementById('loadStep2'),
            document.getElementById('loadStep3'),
            document.getElementById('loadStep4')
        ];

        steps.forEach(s => { if (s) s.className = 'load-step'; });
        if (steps[0]) steps[0].classList.add('active');

        let cur = 0;
        clearInterval(this.loadingInterval);
        this.loadingInterval = setInterval(() => {
            if (cur < steps.length - 1) {
                if (steps[cur]) steps[cur].className = 'load-step done';
                cur++;
                if (steps[cur]) steps[cur].className = 'load-step active';
            }
        }, 400);
    }

    hideLoading() {
        clearInterval(this.loadingInterval);
        this.dom.loadingState.classList.add('hidden');
    }

    showToast(message, isError = false) {
        const toast = document.createElement('div');
        toast.className = `cg-toast ${isError ? 'error' : ''}`;
        toast.innerHTML = `
            <span style="font-size: 1.1rem;">${isError ? '⚠️' : '✓'}</span>
            <div>${message}</div>
        `;
        this.dom.toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4500);
    }

    renderResult(data, type) {
        this.hideLoading();
        this.currentResultData = { ...data, _type: type };

        // Save to audit history
        this.saveToHistory(data, type);

        this.dom.resultScreen.classList.remove('hidden', 'env-low', 'env-medium', 'env-high', 'env-critical');

        const score = Math.round(data.risk_score || 0);
        const severity = (data.severity || data.risk_level || 'UNKNOWN').toUpperCase();
        const action = (data.action || data.recommendation || 'ALLOW').toUpperCase();
        const indicators = data.indicators || data.reasons || [];
        const explanation = data.explanation || (Array.isArray(data.reasons) ? data.reasons[0] : '') || '';
        const prob = data.calibrated_probability !== undefined 
            ? `${(data.calibrated_probability * 100).toFixed(1)}%` 
            : (data.malicious_probability !== undefined ? `${(data.malicious_probability * 100).toFixed(1)}%` : `${score}%`);
        const classification = (data.prediction || data.classification || (score >= 50 ? 'MALICIOUS' : 'BENIGN')).toUpperCase();

        // Apply environmental glow
        const sevClass = `env-${severity.toLowerCase()}`;
        this.dom.resultScreen.classList.add(sevClass);

        // Animate circular gauge & score
        this._animateGauge(score, severity);

        // Severity label
        this.dom.severityLabel.textContent = severity;
        this.dom.severityLabel.style.color = this._getColorForSeverity(severity);

        // Telemetry Summary Stack
        this.dom.summaryClassification.textContent = classification;
        this.dom.summaryClassification.style.color = classification === 'MALICIOUS' ? 'var(--color-critical)' : 'var(--color-low)';

        this.dom.summaryProbability.textContent = prob;
        this.dom.summaryAction.textContent = action;
        this.dom.summaryAction.style.color = this._getColorForSeverity(severity);
        this.dom.summaryTargetType.textContent = type.toUpperCase();

        if (this.dom.resultTimestamp) {
            const now = new Date();
            this.dom.resultTimestamp.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        // Handle QR Decoded URL display
        if (type === 'qr' && data.decoded_url) {
            this.dom.extractedContentBox.classList.remove('hidden');
            this.dom.extractedText.textContent = data.decoded_url;
        } else {
            this.dom.extractedContentBox.classList.add('hidden');
        }

        // Handle Original Input display
        if (this.dom.viewInputBox && this.dom.originalInputText) {
            let inputContent = '';
            if (type === 'message') {
                if (this.currentChannel === 'EMAIL') {
                    const subj = this.dom.msgSubject ? this.dom.msgSubject.value.trim() : '';
                    const body = this.dom.msgInput ? this.dom.msgInput.value.trim() : '';
                    inputContent = subj ? `Subject: ${subj}\n\n${body}` : body;
                } else if (this.currentChannel === 'SMS') {
                    inputContent = this.dom.smsInput ? this.dom.smsInput.value.trim() : '';
                } else {
                    inputContent = this.dom.socialInput ? this.dom.socialInput.value.trim() : '';
                }
            } else if (type === 'url') {
                inputContent = this.dom.urlInput ? this.dom.urlInput.value.trim() : '';
            } else if (type === 'qr') {
                inputContent = data.decoded_url || 'Decoded QR Matrix';
            }

            if (inputContent) {
                this.dom.viewInputBox.classList.remove('hidden');
                this.dom.originalInputText.textContent = inputContent;
            } else {
                this.dom.viewInputBox.classList.add('hidden');
            }
        }

        // Render XAI Indicators
        this._renderExplanations(indicators, explanation, severity);

        // Render Recommendation Banner
        this.dom.recommendationAction.textContent = action.replace('_', ' ');
        this.dom.recommendationAction.style.color = this._getColorForSeverity(severity);
        this.dom.recommendationAction.style.borderColor = this._getColorForSeverity(severity);
        this.dom.recommendationText.textContent = data.guidance || this._getActionDescription(action);

        // Smooth scroll to result
        setTimeout(() => {
            this.dom.resultScreen.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);
    }

    _renderExplanations(indicators, fallbackExplanation, severity) {
        if (!this.dom.explanationList) return;

        if (indicators && indicators.length > 0) {
            this.dom.explanationList.innerHTML = indicators.map((ind, i) => {
                let title = 'DETECTED SIGNAL';
                let desc = '';
                let level = 'INFO';

                if (typeof ind === 'object' && ind !== null) {
                    title = ind.title || 'SECURITY SIGNAL';
                    desc = ind.description || '';
                    level = ind.level || 'MEDIUM';
                } else if (typeof ind === 'string') {
                    if (ind.includes(':')) {
                        const parts = ind.split(':');
                        title = parts[0].trim();
                        desc = parts.slice(1).join(':').trim();
                    } else {
                        desc = ind;
                    }
                    if (desc.toLowerCase().includes('critical') || desc.toLowerCase().includes('malicious')) level = 'CRITICAL';
                    else if (desc.toLowerCase().includes('suspicious') || desc.toLowerCase().includes('threat')) level = 'HIGH';
                    else if (desc.toLowerCase().includes('unencrypted') || desc.toLowerCase().includes('warn')) level = 'MEDIUM';
                }

                return `
                    <div class="cg-insight-item">
                        <div class="insight-header">
                            <span class="insight-level-badge ${level.toLowerCase()}">${level}</span>
                            <span class="insight-title">${title}</span>
                        </div>
                        <div class="insight-desc">${this._highlightThreatTokens(desc)}</div>
                    </div>
                `;
            }).join('');
        } else if (fallbackExplanation) {
            this.dom.explanationList.innerHTML = `
                <div class="cg-insight-item">
                    <div class="insight-header">
                        <span class="insight-level-badge ${severity.toLowerCase()}">${severity}</span>
                        <span class="insight-title">MODEL ASSESSMENT</span>
                    </div>
                    <div class="insight-desc">${this._highlightThreatTokens(fallbackExplanation)}</div>
                </div>
            `;
        } else {
            this.dom.explanationList.innerHTML = `
                <div class="cg-insight-item">
                    <div class="insight-header">
                        <span class="insight-level-badge info">INFO</span>
                        <span class="insight-title">CLEAN REPUTATION</span>
                    </div>
                    <div class="insight-desc">No deceptive, phishing, or anomalous infrastructure patterns were triggered during verification.</div>
                </div>
            `;
        }
    }

    hideResults() {
        if (!this.dom.resultScreen.classList.contains('hidden')) {
            this.dom.resultScreen.classList.add('hidden');
        }
    }

    _animateGauge(score, severity) {
        this.dom.scoreValue.textContent = '00';

        let cur = 0;
        const duration = 1200;
        const intervalTime = 25;
        const steps = duration / intervalTime;
        const inc = score / steps;

        const timer = setInterval(() => {
            cur += inc;
            if (cur >= score) {
                cur = score;
                clearInterval(timer);
            }
            this.dom.scoreValue.textContent = String(Math.round(cur)).padStart(2, '0');
        }, intervalTime);

        // Circular stroke animation
        const svgCircumference = 565.48; // 2 * PI * 90
        const offset = svgCircumference - (score / 100) * svgCircumference;
        const color = this._getColorForSeverity(severity);

        this.dom.gaugePath.style.strokeDashoffset = svgCircumference;
        this.dom.gaugePath.style.stroke = color;

        // Force reflow
        void this.dom.gaugePath.getBoundingClientRect();
        this.dom.gaugePath.style.strokeDashoffset = offset;
    }

    _getColorForSeverity(sev) {
        const s = (sev || '').toUpperCase();
        if (s === 'LOW' || s === 'BENIGN') return 'var(--color-low)';
        if (s === 'MEDIUM') return 'var(--color-medium)';
        if (s === 'HIGH') return 'var(--color-high)';
        if (s === 'CRITICAL' || s === 'MALICIOUS') return 'var(--color-critical)';
        return 'var(--color-text-muted)';
    }

    _getActionDescription(action) {
        switch ((action || '').toUpperCase()) {
            case 'ALLOW':
                return 'Content appears safe and consistent with legitimate communication standards.';
            case 'FLAG_SUSPICIOUS':
            case 'WARN':
                return 'Proceed with heightened caution. Sender or domain structure exhibits suspicious traits.';
            case 'BLOCK_LINK':
            case 'BLOCK':
                return 'Deceptive destination detected. Automated network block or user avoidance advised.';
            case 'QUARANTINE':
                return 'High-confidence credential harvesting or malicious payload. Isolate and delete immediately.';
            default:
                return 'Review threat signals before proceeding.';
        }
    }

    _highlightThreatTokens(text) {
        if (!text) return '';
        const keywords = [
            'phishing', 'credential', 'suspicious', 'malicious', 'urgent', 'suspension',
            'blocked', 'unencrypted', '.xyz', '.top', 'token', 'harvesting', 'trap'
        ];
        let res = text;
        keywords.forEach(kw => {
            const regex = new RegExp(`\\b(${kw})\\b`, 'gi');
            res = res.replace(regex, '<span class="highlight-threat-token">$1</span>');
        });
        return res;
    }

    // ====================================================
    // LOCAL AUDIT TRAIL / HISTORY
    // ====================================================
    saveToHistory(data, type) {
        try {
            const stored = JSON.parse(localStorage.getItem('cyberguard_audit_trail') || '[]');
            const record = {
                id: 'cg_' + Date.now(),
                timestamp: new Date().toISOString(),
                type: type.toUpperCase(),
                riskScore: data.risk_score || 0,
                severity: (data.severity || data.risk_level || 'LOW').toUpperCase(),
                action: (data.action || data.recommendation || 'ALLOW').toUpperCase(),
                preview: this._getInputPreview(type, data),
                fullData: data
            };
            stored.unshift(record);
            if (stored.length > 50) stored.pop();
            localStorage.setItem('cyberguard_audit_trail', JSON.stringify(stored));
            this.updateHistoryBadge();
        } catch (e) {
            // Storage quota exceeded or disabled
        }
    }

    _getInputPreview(type, data) {
        if (type === 'url') return (this.dom.urlInput ? this.dom.urlInput.value : '') || data.url || 'URL Target';
        if (type === 'qr') return data.decoded_url || 'QR Code Matrix';
        if (this.currentChannel === 'EMAIL') {
            return (this.dom.msgSubject && this.dom.msgSubject.value ? this.dom.msgSubject.value + ' - ' : '') + 
                   (this.dom.msgInput ? this.dom.msgInput.value.slice(0, 70) : 'Email message');
        }
        if (this.currentChannel === 'SMS') {
            return this.dom.smsInput ? this.dom.smsInput.value.slice(0, 80) : 'SMS message';
        }
        return this.dom.socialInput ? this.dom.socialInput.value.slice(0, 80) : 'Social message';
    }

    updateHistoryBadge() {
        try {
            const stored = JSON.parse(localStorage.getItem('cyberguard_audit_trail') || '[]');
            if (this.dom.historyCountBadge) {
                this.dom.historyCountBadge.textContent = stored.length;
            }
        } catch (e) { /* ignore */ }
    }

    renderHistoryList() {
        const stored = JSON.parse(localStorage.getItem('cyberguard_audit_trail') || '[]');
        const filtered = this.historyFilter === 'ALL'
            ? stored
            : stored.filter(item => item.type === this.historyFilter);

        if (filtered.length === 0) {
            this.dom.historyEmptyState.classList.remove('hidden');
            this.dom.historyListContainer.innerHTML = '';
            return;
        }

        this.dom.historyEmptyState.classList.add('hidden');
        this.dom.historyListContainer.innerHTML = filtered.map(item => {
            const color = this._getColorForSeverity(item.severity);
            const dateStr = new Date(item.timestamp).toLocaleString([], {
                month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
            });

            return `
                <div class="history-card-item" data-id="${item.id}">
                    <div class="history-col-meta">
                        <span class="history-type-badge">${item.type}</span>
                        <span class="history-timestamp">${dateStr}</span>
                    </div>
                    <div class="history-col-preview" title="${item.preview}">
                        ${item.preview}
                    </div>
                    <div class="history-col-score">
                        <div class="history-score-badge" style="background: ${color}20; color: ${color}; border: 1px solid ${color}60;">
                            ${item.riskScore} / 100
                        </div>
                        <button class="cg-btn-minimal btn-reinspect" data-id="${item.id}">RE-INSPECT →</button>
                    </div>
                </div>
            `;
        }).join('');

        // Attach re-inspect click handlers
        this.dom.historyListContainer.querySelectorAll('.btn-reinspect').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.currentTarget.dataset.id;
                const rec = stored.find(s => s.id === id);
                if (rec && rec.fullData) {
                    this.openWorkspace(rec.type.toLowerCase());
                    this.renderResult(rec.fullData, rec.type.toLowerCase());
                }
            });
        });
    }

    clearHistory() {
        localStorage.removeItem('cyberguard_audit_trail');
        this.updateHistoryBadge();
        this.renderHistoryList();
        this.showToast('Audit history cleared.');
    }

    copyReportToClipboard() {
        if (!this.currentResultData) return;
        const d = this.currentResultData;
        const report = `
========================================
CYBERGUARD DIGITAL THREAT REPORT
========================================
TIMESTAMP: ${new Date().toISOString()}
TARGET TYPE: ${d._type.toUpperCase()}
RISK SCORE: ${d.risk_score} / 100
SEVERITY: ${d.severity || d.risk_level}
CLASSIFICATION: ${d.prediction || d.classification}
RECOMMENDED ACTION: ${d.action || d.recommendation}
GUIDANCE: ${d.guidance || ''}

EXPLANATIONS:
${(d.indicators || d.reasons || []).map((ind, i) => `[${i + 1}] ${typeof ind === 'object' ? ind.title + ' - ' + ind.description : ind}`).join('\n')}
========================================
`;
        navigator.clipboard.writeText(report.trim()).then(() => {
            this.showToast('Full Threat Report copied to clipboard! 📋');
        }).catch(() => {
            this.showToast('Report generated.', false);
        });
    }
}
