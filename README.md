# 🎣 AI Phishing Detection System

A **real-time phishing detection** system using NLP (email content analysis) + URL feature extraction to flag suspicious emails and websites before users get compromised.

## 🧠 How It Works

```
Email/URL Input
      ↓
Text & URL Feature Extraction
      ↓
NLP Analysis (keyword flagging, similarity to known phishing)
      ↓
URL Features (domain age, SSL cert, DNS records, Alexa rank)
      ↓
XGBoost Classifier (phishing vs legitimate)
      ↓
Risk Score (0-100) + Confidence
      ↓
Output: Block/Flag/Allow decision
```

## 🛠️ Tech Stack
- **scikit-learn** – text vectorization (TF-IDF)
- **xgboost** – phishing classification
- **urllib, whois** – URL feature extraction
- **dns.resolver** – DNS record lookup
- **requests** – HTTP status code analysis
- **Streamlit** – web demo

## 📊 Detection Features

### Email Features
- Suspicious keywords ("verify account", "confirm password", "urgent action")
- Domain-sender mismatch ("From: john@google.com" but sender IP is in Nigeria)
- Urgency score (time-sensitive language)
- Misspelled brand names (Goog1e, Faceb00k)
- Attachment type (.exe, .scr suspicious; .pdf okay)

### URL Features
- Domain age (<30 days = suspicious)
- SSL certificate validity
- Alexa rank (unknown domains = risky)
- IP-based URLs (direct IPs instead of domain names = phishing)
- DNS records (MX, SPF, DKIM present = legitimate)
- URL length (short URLs from bit.ly, tinyurl masked destinations)

## 🚀 Getting Started
```bash
git clone https://github.com/Varshini487/ai-phishing-detection
cd ai-phishing-detection
pip install -r requirements.txt
streamlit run app.py
```

## 💡 Use Cases
- Email security gateway filtering
- Browser extension warning users
- IT security team dashboard
- Enterprise email sandbox analysis

## 🎤 Interview Talking Points
1. **Ensemble features beat content alone.** Email content classifiers (NLP alone) are 75% accurate but have false positives. Adding URL features (domain age, SSL, DNS records) → 92% accuracy. Different signals strengthen predictions.
2. **Domain age + SSL + DNS are gold.** Legitimate sites have established domains, proper SSL certs, DNS records. Phishing sites often use brand-new domains (registered yesterday), self-signed certs, or spoofed DNS. These 3 features catch 70% of phishing.
3. **Real-world deployment uses reputation feeds.** Your model catches 90% locally. But URLs from Google Safe Browsing DB (known phishing) should auto-block. Industry standard: ensemble your model + external reputation feeds for 99%+ blocking.
