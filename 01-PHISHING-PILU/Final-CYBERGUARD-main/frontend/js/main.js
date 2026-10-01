/**
 * CYBERGUARD MAIN CONTROLLER
 * High-performance event orchestration, live model analysis, and ambient canvas effects.
 */
document.addEventListener('DOMContentLoaded', () => {
    const api = new CyberGuardAPI();
    const ui = new UIManager();
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

    // 1. Initial Backend Health Discovery
    api.autoDetectPort().then(res => {
        ui.setSystemStatus(res.online, res.data ? `v${res.data.version}` : '');
    });

    // Periodic ping every 12 seconds
    setInterval(() => {
        api.checkHealth().then(isOnline => {
            ui.setSystemStatus(isOnline, api.lastHealthData ? `v${api.lastHealthData.version}` : '');
        });
    }, 12000);

    // 2. Ambient Particles Canvas (Optimized, Zero-Lag)
    initAmbientParticles();

    // 3. Top Navigation
    document.getElementById('btnHome').addEventListener('click', () => ui.showDashboard());
    document.getElementById('navAnalyze').addEventListener('click', () => ui.showDashboard());
    document.getElementById('navHistory').addEventListener('click', () => ui.showHistory());
    document.getElementById('btnBackFromHistory').addEventListener('click', () => ui.showDashboard());
    document.getElementById('btnClearHistory').addEventListener('click', () => ui.clearHistory());
    document.getElementById('btnHistoryStartScan').addEventListener('click', () => ui.openWorkspace('message'));

    // 4. Hero Section Actions
    document.getElementById('btnHeroStartAnalysis').addEventListener('click', () => {
        ui.openWorkspace('message');
    });

    document.getElementById('btnHeroExplore').addEventListener('click', () => {
        const dock = document.getElementById('instrumentsDockSection');
        if (dock) dock.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    // 5. Analysis Entry Cards (Instrument Dock)
    document.querySelectorAll('.instrument-card').forEach(card => {
        card.addEventListener('click', (e) => {
            const target = e.currentTarget.dataset.target;
            const mode = target.replace('-panel', '');
            ui.openWorkspace(mode);
        });
        card.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                const target = e.currentTarget.dataset.target;
                const mode = target.replace('-panel', '');
                ui.openWorkspace(mode);
            }
        });
    });

    // 6. Workspace Navigation
    document.getElementById('btnBackToDashboard').addEventListener('click', () => ui.showDashboard());

    // Command Switcher (Segmented Control)
    document.getElementById('tabModeMessage').addEventListener('click', () => ui.setCommandMode('message'));
    document.getElementById('tabModeUrl').addEventListener('click', () => ui.setCommandMode('url'));
    document.getElementById('tabModeQr').addEventListener('click', () => ui.setCommandMode('qr'));

    // Message Sub-tabs (Email / SMS / Social Media)
    document.getElementById('subTabEmail').addEventListener('click', () => ui.setMessageChannel('EMAIL'));
    document.getElementById('subTabSms').addEventListener('click', () => ui.setMessageChannel('SMS'));
    document.getElementById('subTabSocial').addEventListener('click', () => ui.setMessageChannel('SOCIAL'));

    // Social Platform Chips
    document.querySelectorAll('.platform-chip').forEach(chip => {
        chip.addEventListener('click', (e) => {
            document.querySelectorAll('.platform-chip').forEach(c => c.classList.remove('active'));
            e.currentTarget.classList.add('active');
        });
    });

    // 7. Character Counters
    const setupCharCounter = (inputEl, counterEl) => {
        if (!inputEl || !counterEl) return;
        inputEl.addEventListener('input', () => {
            counterEl.textContent = `${inputEl.value.length} / 5000 characters`;
        });
    };
    setupCharCounter(ui.dom.msgInput, ui.dom.msgCharCount);
    setupCharCounter(ui.dom.smsInput, ui.dom.smsCharCount);
    setupCharCounter(ui.dom.socialInput, ui.dom.socialCharCount);

    // 8. Demo Samples Loaders
    // Message Phishing & Benign
    document.getElementById('btnSampleMsgPhishing').addEventListener('click', () => {
        if (ui.currentChannel === 'EMAIL') {
            ui.dom.msgSubject.value = 'URGENT: SBI Security Notice - Immediate Verification Required';
            ui.dom.msgInput.value = 'Dear Customer, your bank account access has been suspended due to an unrecognized login attempt from an unknown device. Verify your credentials immediately at http://sbi-kyc-verify-portal.top/login to prevent permanent restriction within 24 hours.';
            ui.dom.msgCharCount.textContent = `${ui.dom.msgInput.value.length} / 5000 characters`;
        } else if (ui.currentChannel === 'SMS') {
            ui.dom.smsInput.value = 'URGENT: Your SBI debit card has been blocked. Please verify your OTP and account credentials at http://sbi-card-reactivate.xyz immediately to restore banking privileges.';
            ui.dom.smsCharCount.textContent = `${ui.dom.smsInput.value.length} / 5000 characters`;
        } else {
            ui.dom.socialInput.value = 'Hey! I saw your profile and you won our $1,000 crypto giveaway! Claim it now before timer expires at http://telegram-reward-claim.xyz/auth with your Telegram login.';
            ui.dom.socialCharCount.textContent = `${ui.dom.socialInput.value.length} / 5000 characters`;
        }
        ui.showToast('Phishing sample loaded into analyzer.');
    });

    document.getElementById('btnSampleMsgBenign').addEventListener('click', () => {
        if (ui.currentChannel === 'EMAIL') {
            ui.dom.msgSubject.value = 'Project Documentation Review - Team Sync';
            ui.dom.msgInput.value = 'Hi Team, please find the updated technical report and sprint notes attached for our hackathon project review tomorrow at 3 PM. Let me know if you have any questions or feedback before the call.';
            ui.dom.msgCharCount.textContent = `${ui.dom.msgInput.value.length} / 5000 characters`;
        } else if (ui.currentChannel === 'SMS') {
            ui.dom.smsInput.value = 'Hey Alex, your order #4912 has been delivered to your front porch. Thanks for ordering with us!';
            ui.dom.smsCharCount.textContent = `${ui.dom.smsInput.value.length} / 5000 characters`;
        } else {
            ui.dom.socialInput.value = 'Hey are you available for a quick study session on Discord this evening? We are finishing up the AI slides.';
            ui.dom.socialCharCount.textContent = `${ui.dom.socialInput.value.length} / 5000 characters`;
        }
        ui.showToast('Safe benign sample loaded.');
    });

    // URL Phishing & Benign
    document.getElementById('btnSampleUrlPhishing').addEventListener('click', () => {
        ui.dom.urlInput.value = 'http://secure-login-apple.xyz/verify?token=92841';
        ui.showToast('Malicious URL sample loaded.');
    });

    document.getElementById('btnSampleUrlBenign').addEventListener('click', () => {
        ui.dom.urlInput.value = 'https://wikipedia.org';
        ui.showToast('Safe Wikipedia URL loaded.');
    });

    // QR Samples (Fetches real sample PNGs stored in frontend/samples)
    const loadQrSample = async (samplePath, sampleName) => {
        try {
            ui.showToast(`Loading sample ${sampleName}...`);
            const response = await fetch(samplePath);
            if (!response.ok) throw new Error('Sample file not found');
            const blob = await response.blob();
            const file = new File([blob], sampleName, { type: 'image/png' });
            handleQrFileSelection(file);
            ui.showToast(`${sampleName} loaded into inspection chamber.`);
        } catch (e) {
            ui.showToast(`Could not load sample: ${e.message}`, true);
        }
    };

    document.getElementById('btnSampleQrPhishing').addEventListener('click', () => {
        loadQrSample('samples/phishing_sample.png', 'malicious_apple_qr.png');
    });

    document.getElementById('btnSampleQrBenign').addEventListener('click', () => {
        loadQrSample('samples/benign_sample.png', 'wikipedia_qr.png');
    });

    // 9. Analysis Actions
    // Analyze Message
    document.getElementById('btnAnalyzeMsg').addEventListener('click', async () => {
        let text = '';
        if (ui.currentChannel === 'EMAIL') {
            const subj = ui.dom.msgSubject ? ui.dom.msgSubject.value.trim() : '';
            const body = ui.dom.msgInput ? ui.dom.msgInput.value.trim() : '';
            text = subj ? `Subject: ${subj}\n\n${body}` : body;
        } else if (ui.currentChannel === 'SMS') {
            text = ui.dom.smsInput ? ui.dom.smsInput.value.trim() : '';
        } else {
            text = ui.dom.socialInput ? ui.dom.socialInput.value.trim() : '';
        }

        if (!text) {
            ui.showToast('Please enter message content to analyze.', true);
            return;
        }

        ui.showLoading('message');
        try {
            const result = await api.analyzeMessage(text, ui.currentChannel);
            ui.renderResult(result, 'message');
        } catch (err) {
            ui.hideLoading();
            ui.showToast(err.message || 'Threat Engine connection failed.', true);
        }
    });

    // Analyze URL
    document.getElementById('btnAnalyzeUrl').addEventListener('click', async () => {
        let url = ui.dom.urlInput ? ui.dom.urlInput.value.trim() : '';
        if (!url) {
            ui.showToast('Please enter a destination URL to inspect.', true);
            return;
        }

        if (!/^https?:\/\//i.test(url)) {
            url = 'https://' + url;
            ui.dom.urlInput.value = url;
        }

        ui.showLoading('url');
        try {
            const result = await api.analyzeURL(url);
            ui.renderResult(result, 'url');
        } catch (err) {
            ui.hideLoading();
            ui.showToast(err.message || 'URL Intelligence Engine unreachable.', true);
        }
    });

    // QR Code Chamber & Upload Flow
    let currentQrFile = null;
    const qrDropZone = ui.dom.qrDropZone;
    const qrFileInput = ui.dom.qrFileInput;
    const btnBrowseQr = document.getElementById('btnBrowseQr');
    const btnClearQr = document.getElementById('btnClearQr');
    const btnAnalyzeQr = ui.dom.btnAnalyzeQr;

    btnBrowseQr.addEventListener('click', () => qrFileInput.click());
    btnClearQr.addEventListener('click', clearQrChamber);

    qrDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        qrDropZone.classList.add('dragover');
    });

    qrDropZone.addEventListener('dragleave', () => {
        qrDropZone.classList.remove('dragover');
    });

    qrDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        qrDropZone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleQrFileSelection(e.dataTransfer.files[0]);
        }
    });

    qrFileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleQrFileSelection(e.target.files[0]);
        }
    });

    function handleQrFileSelection(file) {
        if (!file.type.startsWith('image/')) {
            ui.showToast('Please select a valid image file (PNG, JPG, WEBP).', true);
            return;
        }
        currentQrFile = file;

        const reader = new FileReader();
        reader.onload = (e) => {
            ui.dom.qrPreview.src = e.target.result;
            ui.dom.qrFileName.textContent = file.name;
            ui.dom.qrFileSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
            ui.dom.qrPreviewContainer.classList.remove('hidden');
            ui.dom.qrPlaceholderContent.classList.add('hidden');
            btnAnalyzeQr.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    function clearQrChamber() {
        currentQrFile = null;
        qrFileInput.value = '';
        ui.dom.qrPreview.src = '';
        ui.dom.qrPreviewContainer.classList.add('hidden');
        ui.dom.qrPlaceholderContent.classList.remove('hidden');
        btnAnalyzeQr.disabled = true;
        qrDropZone.classList.remove('scanning');
    }

    btnAnalyzeQr.addEventListener('click', async () => {
        if (!currentQrFile) return;

        qrDropZone.classList.add('scanning');
        ui.showLoading('qr');

        try {
            const result = await api.analyzeQR(currentQrFile);
            qrDropZone.classList.remove('scanning');

            if (result.decode_status === 'failed' || result.success === false) {
                ui.hideLoading();
                ui.showToast(result.message || result.error || 'QR CODE NOT DETECTED: Try uploading a clearer QR image.', true);
                return;
            }

            ui.renderResult(result, 'qr');
        } catch (err) {
            qrDropZone.classList.remove('scanning');
            ui.hideLoading();
            ui.showToast(err.message || 'QR Vision service failed.', true);
        }
    });

    // 10. Result Screen Interactivity
    const handleResetAll = () => {
        ui.hideResults();
        setTimeout(() => {
            if (ui.dom.msgSubject) ui.dom.msgSubject.value = '';
            if (ui.dom.msgInput) ui.dom.msgInput.value = '';
            if (ui.dom.smsInput) ui.dom.smsInput.value = '';
            if (ui.dom.socialInput) ui.dom.socialInput.value = '';
            if (ui.dom.urlInput) ui.dom.urlInput.value = '';
            clearQrChamber();
        }, 400);
    };

    document.getElementById('btnBackToInput').addEventListener('click', () => ui.hideResults());
    document.getElementById('btnBackToInputBottom').addEventListener('click', () => ui.hideResults());
    document.getElementById('btnReset').addEventListener('click', handleResetAll);
    document.getElementById('btnResetBottom').addEventListener('click', handleResetAll);
    document.getElementById('btnNewAnalysis').addEventListener('click', handleResetAll);

    // Toggle Input Preview
    document.getElementById('btnToggleInput').addEventListener('click', () => {
        const isHidden = ui.dom.originalInputText.classList.toggle('hidden');
        const icon = document.querySelector('.toggle-icon');
        if (icon) icon.textContent = isHidden ? 'VIEW INPUT ▾' : 'HIDE INPUT ▴';
    });

    // Copy Decoded URL
    if (ui.dom.btnCopyDecodedUrl) {
        ui.dom.btnCopyDecodedUrl.addEventListener('click', () => {
            const text = ui.dom.extractedText.textContent;
            navigator.clipboard.writeText(text).then(() => {
                ui.showToast('Decoded URL copied to clipboard! 📋');
            });
        });
    }

    // Copy Threat Report
    document.getElementById('btnCopyReport').addEventListener('click', () => {
        ui.copyReportToClipboard();
    });

    // 11. History Filters
    document.querySelectorAll('.filter-pill').forEach(pill => {
        pill.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
            e.currentTarget.classList.add('active');
            ui.historyFilter = e.currentTarget.dataset.filter;
            ui.renderHistoryList();
        });
    });

    // 12. Cursor Light Tracking (Linear / Apple-style Glass Illumination)
    if (!prefersReducedMotion.matches) {
        document.addEventListener('mousemove', (e) => {
            const x = e.clientX;
            const y = e.clientY;

            // Shift ambient primary light slightly with mouse
            const pLight = document.getElementById('ambientLightPrimary');
            if (pLight) {
                pLight.style.transform = `translate3d(${(x - window.innerWidth / 2) * 0.05}px, ${(y - window.innerHeight / 2) * 0.05}px, 0)`;
            }

            // Cards edge highlight
            document.querySelectorAll('.instrument-card, .cg-workspace-primary, .history-card-item').forEach(card => {
                const rect = card.getBoundingClientRect();
                const cardX = x - rect.left;
                const cardY = y - rect.top;
                card.style.setProperty('--mouse-x', `${cardX}px`);
                card.style.setProperty('--mouse-y', `${cardY}px`);
            });
        });
    }

    // Canvas Particles
    function initAmbientParticles() {
        const canvas = document.getElementById('cgParticlesCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        const numParticles = 40;
        const particles = [];
        for (let i = 0; i < numParticles; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.35,
                vy: (Math.random() - 0.5) * 0.35,
                radius: Math.random() * 1.5 + 0.5,
                color: Math.random() > 0.3 ? 'rgba(0, 255, 135, ' : 'rgba(255, 123, 176, ',
                alpha: Math.random() * 0.5 + 0.1
            });
        }

        let animId;
        function renderParticles() {
            ctx.clearRect(0, 0, width, height);

            for (let i = 0; i < numParticles; i++) {
                const p = particles[i];
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0) p.x = width;
                if (p.x > width) p.x = 0;
                if (p.y < 0) p.y = height;
                if (p.y > height) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color + p.alpha + ')';
                ctx.fill();
            }

            if (!prefersReducedMotion.matches) {
                animId = requestAnimationFrame(renderParticles);
            }
        }

        renderParticles();
    }
});
