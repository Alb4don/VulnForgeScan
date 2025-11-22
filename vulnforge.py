#!/usr/bin/env python3

import os
import re
import json
import sqlite3
import logging
import platform
import threading
import tkinter as tk  
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse, parse_qs, urlencode
from logging.handlers import RotatingFileHandler


try:
    import requests
    import ttkbootstrap as ttk
    from ttkbootstrap.constants import *
    from ttkbootstrap.dialogs import Messagebox
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
except ImportError as e:
    print(f"Missing dependency: {e.name}")
    print("Run: pip install requests ttkbootstrap scikit-learn joblib numpy")
    exit(1)


APP_NAME = "VulnForge"
VERSION = "1.0"

def get_app_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path.home() / f".{APP_NAME.lower()}"
    app_dir = base / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

APP_DIR = get_app_dir()
MODEL_PATH = APP_DIR / "models" / "classifier.joblib"
LOG_PATH = APP_DIR / "vulnforge.log"
(APP_DIR / "models").mkdir(exist_ok=True)


def setup_logging():
    logger = logging.getLogger("vulnforge")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=5)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(handler)
    return logger

log = setup_logging()

PAYLOADS = [
    "javascript:alert(1)", "'\"/><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "';alert(1)//",
    "<svg onload=alert(1)>", "jaVasCript:alert(1)",
]

SINKS = ["alert(", "eval(", "settimeout(", "setinterval(", "function(", "execscript("]

class AIDetector:
    def __init__(self):
        self.classifier = RandomForestClassifier(n_estimators=50, warm_start=True)
        self.regressor = RandomForestRegressor(n_estimators=30, warm_start=True)
        self.vectorizer = TfidfVectorizer(max_features=200, lowercase=True, ngram_range=(1, 2))
        self.is_trained = False
        self.load_models()

    def extract_features(self, url: str, content: str, payload: str) -> Dict:
        c = content.lower()
        return {
            "sink_count": sum(c.count(s) for s in SINKS),
            "payload_reflected": int(payload in content),
            "js_scheme": int("javascript:" in c),
            "on_handler": len(re.findall(r'on\w+\s*=', content, re.I)),
            "script_tags": content.lower().count("<script"),
            "response_len": len(content),
            "param_count": url.count("&") + 1,
            "text_blob": " ".join(re.findall(r'\w+', content.lower()[:1500]))
        }

    def vectorize(self, features: Dict) -> np.ndarray:
        numeric = np.array([[features["sink_count"], features["payload_reflected"],
                             features["js_scheme"], features["on_handler"],
                             features["script_tags"], features["response_len"],
                             features["param_count"]]], dtype=float)
        if not hasattr(self.vectorizer, "vocabulary_"):
            text_vec = np.zeros((1, 200))
        else:
            text_vec = self.vectorizer.transform([features["text_blob"]]).toarray()
        return np.hstack([numeric, text_vec])

    def classify(self, url: str, content: str, payload: str) -> tuple[bool, float]:
        feats = self.extract_features(url, content, payload)
        X = self.vectorize(feats)
        if not self.is_trained:
            score = feats["sink_count"] * 25 + feats["payload_reflected"] * 50
            return score > 40, min(score, 100.0)
        prob = self.classifier.predict_proba(X)[0][1]
        risk = float(self.regressor.predict(X)[0])
        return prob > 0.58, max(0.0, min(100.0, risk))

    def learn(self, url: str, content: str, payload: str, vulnerable: bool, risk: float):
        feats = self.extract_features(url, content, payload)
        X = self.vectorize(feats)
        y_cls = 1 if vulnerable else 0
        self.vectorizer.fit([feats["text_blob"]])
        if not self.is_trained:
            self.classifier.fit(X, [y_cls])
            self.regressor.fit(X, [risk])
            self.is_trained = True
        else:
            self.classifier.n_estimators += 5
            self.classifier.fit(X, [y_cls])
            self.regressor.n_estimators += 3
            self.regressor.fit(X, [risk])
        self.save_models()

    def save_models(self):
        joblib.dump({
            "classifier": self.classifier,
            "regressor": self.regressor,
            "vectorizer": self.vectorizer,
            "trained": self.is_trained
        }, MODEL_PATH)

    def load_models(self):
        if MODEL_PATH.exists():
            try:
                data = joblib.load(MODEL_PATH)
                self.classifier = data["classifier"]
                self.regressor = data["regressor"]
                self.vectorizer = data["vectorizer"]
                self.is_trained = data.get("trained", False)
            except Exception as e:
                log.warning(f"Model load failed: {e}")


class VulnForgeScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"{APP_NAME}/{VERSION}"
        self.ai = AIDetector()
        self.timeout = 12

    def scan(self, raw_url: str, callback=None):
        url = raw_url.strip().rstrip("/")
        if not url.startswith("http"):
            url = "https://" + url

        result = {"target": url, "vulnerabilities": [], "risk_score": 0.0}

        try:
            r = self.session.get(url, timeout=10)
            params = list(parse_qs(urlparse(url).query).keys()) or ["q"]
        except:
            params = ["q"]

        total = len(params) * len(PAYLOADS)
        completed = 0

        for param in params:
            for payload in PAYLOADS:
                test_url = f"{url.split('?')[0]}?{urlencode({param: payload})}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    is_vuln, risk = self.ai.classify(test_url, resp.text, payload)
                    if is_vuln:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "risk": round(risk, 2), "url": test_url
                        })
                    self.ai.learn(test_url, resp.text, payload, is_vuln, risk)
                except Exception as e:
                    log.debug(f"Request error: {e}")
                completed += 1
                if callback:
                    callback(completed, total, result)

        if result["vulnerabilities"]:
            result["risk_score"] = round(sum(v["risk"] for v in result["vulnerabilities"]) / len(result["vulnerabilities"]), 2)
        return result


class VulnForgeGUI(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")  
        self.title(f"{APP_NAME} v{VERSION} — AI DOM XSS Scanner")
        self.geometry("1240x780")
        self.minsize(1000, 600)
        self.scanner = VulnForgeScanner()
        self.create_widgets()
        self.center_window()

    def center_window(self):
        self.update_idletasks()
        w, h = self.winfo_screenwidth(), self.winfo_screenheight()
        size = tuple(int(_) for _ in self.geometry().split('+')[0].split('x'))
        x = w//2 - size[0]//2
        y = h//2 - size[1]//2
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
    
        header = ttk.Frame(self, padding=25)
        header.pack(fill=X)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 34, "bold"), foreground="#00ff41").pack(side=tk.LEFT)
        ttk.Label(header, text="AI-Powered DOM-Based XSS Scanner", font=("Segoe UI", 14), foreground="#cccccc").pack(side=tk.LEFT, padx=20)

        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(container, text=" Target Configuration ", padding=15)
        input_frame.pack(fill=X, pady=(0, 15))
        ttk.Label(input_frame, text="URL:", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.url_var = tk.StringVar(value="https://example.com")
        url_entry = ttk.Entry(input_frame, textvariable=self.url_var, font=("Consolas", 12), width=80)
        url_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=(0, 15))
        ttk.Button(input_frame, text="Start Scan", bootstyle=SUCCESS, command=self.start_scan).grid(row=0, column=2, sticky=tk.E)
        input_frame.columnconfigure(1, weight=1)

        prog_frame = ttk.Frame(container)
        prog_frame.pack(fill=X, pady=(0, 10))
        self.progress = ttk.Progressbar(prog_frame, mode="determinate", bootstyle="success-striped")
        self.progress.pack(fill=X, side=tk.LEFT, expand=True)
        self.status_label = ttk.Label(prog_frame, text="Ready", foreground="#00ff41", font=("Segoe UI", 11, "bold"))
        self.status_label.pack(side=tk.RIGHT, padx=(15, 0))

        # Results Table
        table_frame = ttk.LabelFrame(container, text=" Vulnerabilities Found ", padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        columns = ("param", "payload", "risk", "url")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", bootstyle="danger")
        self.tree.heading("param", text="Parameter")
        self.tree.heading("payload", text="Payload")
        self.tree.heading("risk", text="Risk Score")
        self.tree.heading("url", text="Test URL")
        self.tree.column("param", width=130, anchor="center")
        self.tree.column("payload", width=380, anchor="w")
        self.tree.column("risk", width=110, anchor="center")
        self.tree.column("url", width=580, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        log_frame = ttk.LabelFrame(container, text=" Scan Log & Summary ", padding=15)
        log_frame.pack(fill=X)
        self.summary = tk.Text(log_frame, height=7, font=("Consolas", 10), bg="#1e1e1e", fg="#00ff88", wrap="word")
        self.summary.pack(fill=X)
        self.summary.insert("end", f"{APP_NAME} v{VERSION} ready.\nAI model learns from every scan.\n")
        self.summary.insert("end", f"Data directory: {APP_DIR}\n")

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            Messagebox.show_error("Please enter a target URL", "Input Required")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress["value"] = 0
        self.status_label.config(text="Scanning...")
        self.summary.delete(1.0, "end")
        self.summary.insert("end", f"Target: {url}\n\nScanning in progress...\n")

        def scan_worker():
            def progress_callback(done: int, total: int, result: Dict):
                self.progress["value"] = (done / total) * 100
                self.status_label.config(text=f"Tested {done}/{total}")
                self.update_idletasks()

            result = self.scanner.scan(url, callback=progress_callback)
            self.after(0, self.scan_complete, result)

        threading.Thread(target=scan_worker, daemon=True).start()

    def scan_complete(self, result: Dict):
        self.progress["value"] = 100
        self.status_label.config(text="Scan Complete")

        vulns = result.get("vulnerabilities", [])
        if not vulns:
            self.summary.insert("end", "\nNo DOM-based XSS vulnerabilities detected.")
            Messagebox.show_info("No issues found", "Clean Result")
        else:
            for v in vulns:
                self.tree.insert("", "end", values=(v["param"], v["payload"], f"{v['risk']}/100", v["url"]))
            self.summary.insert("end", f"\nFound {len(vulns)} vulnerability(-ies)!\n")
            self.summary.insert("end", f"Overall Risk Score: {result['risk_score']}/100")
            Messagebox.show_warning(f"{len(vulns)} DOM XSS issue(s) detected!", "Vulnerabilities Found")

        self.summary.insert("end", f"\n\nScan finished. AI model updated.")

if __name__ == "__main__":
    app = VulnForgeGUI()
    app.mainloop()
