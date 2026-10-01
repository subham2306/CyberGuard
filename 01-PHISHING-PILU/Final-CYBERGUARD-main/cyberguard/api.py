import os
import json
import pickle
import base64
import numpy as np
import pandas as pd
from typing import List, Optional, Dict, Any

from cyberguard.features import CyberFeatureExtractor
from cyberguard.risk_engine import RiskEngine
from cyberguard.xai import DualXAIEngine
from cyberguard.model import CyberGuardHybridModel
from url_intelligence.inference import URLIntelligenceEngine

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MSG_BUNDLE_PATH = str(BASE_DIR / 'saved_models' / 'cyberguard_bundle.pt')
URL_BUNDLE_PATH = str(BASE_DIR / 'saved_models' / 'url_intelligence_bundle.pkl')
FRONTEND_DIR = str(BASE_DIR / 'frontend')

class UnifiedCyberGuardHub:
    """
    Unified Production Inference Pipeline.
    Manages both Message Phishing Intelligence and Unified Direct URL & QR Code Intelligence.
    """
    def __init__(self):
        # 1. Message Model Setup
        self.msg_extractor = CyberFeatureExtractor()
        self.msg_xai_engine = DualXAIEngine()
        self.device = 'cpu'
        self.msg_model = None
        self.msg_scaler = None
        self.msg_vectorizer = None
        self.msg_risk_engine = RiskEngine()
        self._load_msg_bundle()

        # 2. URL & QR Intelligence Engine Setup
        self.url_engine = URLIntelligenceEngine(bundle_path=URL_BUNDLE_PATH)

    def _load_msg_bundle(self):
        if os.path.exists(MSG_BUNDLE_PATH):
            try:
                with open(MSG_BUNDLE_PATH, 'rb') as f:
                    bundle = pickle.load(f)
                cfg = bundle['model_config']
                self.msg_model = CyberGuardHybridModel(
                    text_dim=cfg['text_dim'],
                    cyber_in_dim=cfg['cyber_in_dim'],
                    cyber_out_dim=cfg['cyber_out_dim'],
                    hidden_dim=cfg['hidden_dim'],
                    num_classes=cfg['num_classes'],
                    dropout=cfg['dropout']
                )
                self.msg_model.load_state_dict(bundle['model_state_dict'])
                self.msg_model.eval()
                self.msg_scaler = bundle['scaler']
                self.msg_vectorizer = bundle['vectorizer']
                self.msg_risk_engine = bundle['risk_engine']
            except Exception as e:
                print(f"[UnifiedHub] Note loading message bundle: {e}")

    def predict_message(self, text: str, channel: str = "SMS") -> Dict[str, Any]:
        feats_dict = self.msg_extractor.extract_dict(text, channel)
        raw_feat_vector = np.array([feats_dict[k] for k in self.msg_extractor.FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
        
        if self.msg_model is not None and self.msg_vectorizer is not None and self.msg_scaler is not None:
            import torch
            norm_feats = self.msg_scaler.transform(raw_feat_vector)
            norm_feats = np.clip(norm_feats, -2.0, 2.0)
            text_vec = self.msg_vectorizer.transform([text]).toarray().astype(np.float32)
            with torch.no_grad():
                logits = self.msg_model(text_embeddings=torch.tensor(text_vec), cyber_features=torch.tensor(norm_feats))
                probs = torch.softmax(logits, dim=1).numpy()[0]
                raw_prob = float(probs[1])
        else:
            # High-fidelity deterministic heuristic score if message weights not loaded
            score = 0.05
            if feats_dict.get('has_urgency', 0.0) == 1.0: score += 0.35
            if feats_dict.get('has_account_threat', 0.0) == 1.0: score += 0.30
            if feats_dict.get('has_credential_request', 0.0) == 1.0: score += 0.30
            if feats_dict.get('has_shortened_url', 0.0) == 1.0: score += 0.25
            raw_prob = min(0.99, score)

        risk_dict = self.msg_risk_engine.calculate_risk(raw_prob)
        risk_score = risk_dict['risk_score']
        
        # Context-Aware URL Analysis & Risk Fusion
        import re
        urls = re.findall(r'https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/[^\s]*', text)
        url_context = {'has_urls': False}
        
        if urls:
            url_context['has_urls'] = True
            url_scores = []
            for u in urls:
                try:
                    u_res = self.predict_url(u)
                    url_scores.append(u_res.get('risk_score', 0))
                except Exception:
                    pass
            
            if url_scores:
                max_url_score = max(url_scores)
                if max_url_score >= 80: url_context['url_severity'] = "CRITICAL"
                elif max_url_score >= 50: url_context['url_severity'] = "HIGH"
                elif max_url_score >= 25: url_context['url_severity'] = "MEDIUM"
                else: url_context['url_severity'] = "LOW"
                
                has_strong_indicators = (feats_dict.get('account_threat', 0) > 0) or \
                                        (feats_dict.get('payment_request', 0) > 0) or \
                                        (feats_dict.get('otp_request', 0) > 0) or \
                                        (feats_dict.get('impersonation_flag', 0) > 0)

                if max_url_score < 40:
                    # Safe URL: discount message score if it was inflated by the mere presence of a URL
                    risk_score = int(risk_score * 0.4 + max_url_score * 0.6)
                    # Force MEDIUM/LOW if the text has no strong programmatic phishing signals
                    if not has_strong_indicators:
                        risk_score = min(risk_score, 45)
                else:
                    # Suspicious URL: dominates overall risk
                    risk_score = max(risk_score, max_url_score)
        else:
            # No URLs: Cap score if no strong programmatic indicators exist
            has_strong_indicators = (feats_dict.get('account_threat', 0) > 0) or \
                                    (feats_dict.get('payment_request', 0) > 0) or \
                                    (feats_dict.get('otp_request', 0) > 0) or \
                                    (feats_dict.get('impersonation_flag', 0) > 0)
            
            if not has_strong_indicators and risk_score > 49:
                risk_score = min(risk_score, 45) # Keep at MEDIUM maximum for purely conversational keywords

        # Recalculate Severity and Action based on adjusted risk_score
        if risk_score <= 24:
            severity = "LOW"
            action = "ALLOW"
        elif risk_score <= 49:
            severity = "MEDIUM"
            action = "FLAG_SUSPICIOUS"
        elif risk_score <= 79:
            severity = "HIGH"
            action = "BLOCK_LINK"
        else:
            severity = "CRITICAL"
            action = "QUARANTINE"

        risk_dict['risk_score'] = risk_score
        risk_dict['severity'] = severity
        risk_dict['action'] = action
        
        cal_prob = risk_dict['calibrated_prob']
        xai_res = self.msg_xai_engine.generate_explanation(text, feats_dict, risk_dict, token_saliency=[], url_context=url_context)
        
        return {
            "channel": channel,
            "raw_probability": round(raw_prob, 4),
            "calibrated_probability": round(cal_prob, 4),
            "risk_score": risk_score,
            "severity": severity,
            "action": action,
            "prediction": "MALICIOUS" if risk_score >= 50 else "BENIGN",
            "indicators": xai_res['rule_indicators'],
            "suspicious_tokens": xai_res['suspicious_tokens'],
            "recommendation": xai_res['recommendation'],
            "explanation": xai_res['explanation_summary']
        }

    def predict_url(self, raw_url: str) -> Dict[str, Any]:
        return self.url_engine.analyze_url(raw_url, source="direct_url")

    def predict_qr_base64(self, image_b64: str) -> Dict[str, Any]:
        import cv2
        import numpy as np
        if ',' in image_b64:
            image_b64 = image_b64.split(',', 1)[1]
        raw_bytes = base64.b64decode(image_b64)
        nparr = np.frombuffer(raw_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return {'success': False, 'error': 'Failed to decode image buffer.'}
        return self.url_engine.analyze_qr_image(img)

    def predict_qr_file(self, file_bytes: bytes) -> Dict[str, Any]:
        import cv2
        import numpy as np
        nparr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return {'success': False, 'error': 'Failed to decode uploaded image file.'}
        return self.url_engine.analyze_qr_image(img)

# FastAPI Application
try:
    from fastapi import FastAPI, HTTPException, UploadFile, File
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel
    
    app = FastAPI(
        title="CYBERGUARD & URL INTELLIGENCE API",
        description="Unified Enterprise Detection Hub for Messages, Direct URLs, and QR Codes",
        version="2.0.0"
    )
    
    from fastapi.middleware.cors import CORSMiddleware
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    _hub_instance = None
    
    def get_hub():
        global _hub_instance
        if _hub_instance is None:
            _hub_instance = UnifiedCyberGuardHub()
        return _hub_instance

    class MessageDetectionRequest(BaseModel):
        text: str
        channel: Optional[str] = "SMS"

    class URLDetectionRequest(BaseModel):
        url: str

    class QRBase64Request(BaseModel):
        image_base64: str

    @app.get("/health")
    def health():
        hub = get_hub()
        return {
            "status": "online",
            "message_module": "active",
            "url_module": "active",
            "url_bundle_loaded": hub.url_engine.bundle_loaded,
            "version": "2.0.0"
        }

    @app.post("/api/v1/detect")
    def detect_message(req: MessageDetectionRequest):
        hub = get_hub()
        return hub.predict_message(req.text, req.channel)

    @app.post("/api/v1/detect/url")
    @app.post("/predict_url")
    def detect_url(req: URLDetectionRequest):
        hub = get_hub()
        res = hub.predict_url(req.url)
        return {
            "input_type": "url",
            "url": req.url,
            "classification": "malicious" if res['risk_score'] >= 50 else "benign",
            "malicious_probability": res['calibrated_p_malicious'],
            "risk_score": res['risk_score'],
            "risk_level": res['severity'],
            "recommendation": res['action'],
            "reasons": [ind['title'] + ": " + ind['description'] for ind in res.get('indicators', [])] or [res.get('explanation', '')],
            "raw_details": res
        }

    @app.post("/api/v1/detect/qr")
    @app.post("/detect_qr")
    async def detect_qr(file: UploadFile = File(...)):
        hub = get_hub()
        file_bytes = await file.read()
        res = hub.predict_qr_file(file_bytes)
        
        # If decode failed, just return the error gracefully
        if res.get('decode_status') == 'failed':
            return res
            
        # Format if it's not a URL payload
        if res.get('payload_type') == 'text':
            return res
            
        return res

    @app.get("/api/v1/benchmark/summary")
    def get_benchmark():
        csv_path = BASE_DIR / 'url_benchmark_results.csv'
        if csv_path.exists():
            df = pd.read_csv(str(csv_path))
            return {"results": df.to_dict(orient='records')}
        return {"error": "Benchmark results not yet generated"}

    from fastapi.staticfiles import StaticFiles
    if Path(FRONTEND_DIR).exists():
        app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

except ImportError:
    app = None

if __name__ == "__main__":
    hub = UnifiedCyberGuardHub()
    import json
    print("\n" + "="*70)
    print("        CYBERGUARD & URL INTELLIGENCE UNIFIED API DEMO")
    print("="*70)
    print("\n[Testing Message Phishing]:")
    print(json.dumps(hub.predict_message("URGENT: SBI account suspended. Verify at http://bit.ly/sbi-acc", "SMS"), indent=2))
    print("\n[Testing Direct URL Intelligence]:")
    print(json.dumps(hub.predict_url("https://secure-update-paypal-notice.xyz/verify?token=92841"), indent=2))
