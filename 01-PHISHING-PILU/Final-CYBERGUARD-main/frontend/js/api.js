/**
 * CYBERGUARD API Client
 * Enterprise-grade communication interface for Message, URL, and QR Threat Intelligence
 */
class CyberGuardAPI {
    constructor() {
        // Automatically determine backend baseUrl
        // If served from FastAPI static files on any port, window.location.origin is used.
        // If loaded from file:// or other origin, test port 8000 and 8001
        this.baseUrl = window.location.protocol.startsWith('http')
            ? window.location.origin
            : 'http://127.0.0.1:8000';
        this.lastHealthData = null;
    }

    async autoDetectPort() {
        const candidates = [
            this.baseUrl,
            'http://127.0.0.1:8000',
            'http://127.0.0.1:8001',
            'http://localhost:8000',
            'http://localhost:8001'
        ];
        
        // Remove duplicates
        const uniqueCandidates = [...new Set(candidates)];

        for (const candidate of uniqueCandidates) {
            try {
                const ctrl = new AbortController();
                const timeoutId = setTimeout(() => ctrl.abort(), 1500);
                const res = await fetch(`${candidate}/health`, { signal: ctrl.signal });
                clearTimeout(timeoutId);
                
                if (res.ok) {
                    const data = await res.json();
                    if (data && (data.status === 'online' || data.url_module === 'active')) {
                        this.baseUrl = candidate;
                        this.lastHealthData = data;
                        return { online: true, data };
                    }
                }
            } catch (err) {
                // Continue to next candidate port
            }
        }
        return { online: false, data: null };
    }

    async checkHealth() {
        const check = await this.autoDetectPort();
        return check.online;
    }

    async analyzeMessage(text, channel = "SMS") {
        const response = await fetch(`${this.baseUrl}/api/v1/detect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, channel })
        });
        return this._handleResponse(response);
    }

    async analyzeURL(url) {
        const response = await fetch(`${this.baseUrl}/predict_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        return this._handleResponse(response);
    }

    async analyzeQR(file) {
        const formData = new FormData();
        formData.append('file', file);
        const response = await fetch(`${this.baseUrl}/detect_qr`, {
            method: 'POST',
            body: formData
        });
        return this._handleResponse(response);
    }

    async _handleResponse(response) {
        if (!response.ok) {
            let errorMsg = `Server responded with HTTP ${response.status}`;
            try {
                const errData = await response.json();
                if (errData.detail) errorMsg = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
                else if (errData.message) errorMsg = errData.message;
            } catch (e) { /* ignore JSON parsing error */ }
            throw new Error(errorMsg);
        }
        return await response.json();
    }
}
