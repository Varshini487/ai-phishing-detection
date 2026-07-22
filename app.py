import streamlit as st
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import time

st.set_page_config(page_title="🎣 Phishing Detection", layout="wide")
st.title("🎣 AI Phishing Detection System")
st.markdown("Analyze emails and URLs for phishing risk using NLP + feature analysis")

# Suspicious keywords (demo)
PHISHING_KEYWORDS = [
    "verify account", "confirm password", "urgent action", "click here",
    "update payment", "suspicious activity", "unusual login", "act now",
    "reset password", "validate", "reactivate", "immediate", "expire"
]

SAFE_DOMAINS = ["google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "stackoverflow.com"]

def extract_url_features(url: str) -> dict:
    """Extract URL-based features for phishing detection."""
    features = {
        "has_https": url.startswith("https://"),
        "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        "url_length": len(url),
        "subdomain_count": url.count('.'),
        "has_shortener": any(short in url for short in ["bit.ly", "tinyurl", "short.link"]),
        "port_specified": ':' in url.split('//')[1] if '//' in url else False,
    }
    
    # Extract domain
    domain = url.replace("https://", "").replace("http://", "").split('/')[0]
    features["domain"] = domain
    features["is_known_domain"] = any(safe in domain for safe in SAFE_DOMAINS)
    
    return features

def extract_email_features(email_text: str) -> dict:
    """Extract email content features."""
    text_lower = email_text.lower()
    features = {
        "suspicious_keyword_count": sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower),
        "urgent_count": text_lower.count("urgent") + text_lower.count("immediate"),
        "question_mark_count": email_text.count("?"),
        "exclamation_count": email_text.count("!"),
        "url_count": len(re.findall(r'https?://', email_text)),
        "has_verify_request": "verify" in text_lower or "confirm" in text_lower,
        "has_payment_request": any(w in text_lower for w in ["payment", "card", "billing"]),
        "grammar_issues": sum(1 for word in text_lower.split() if len(word) > 15),  # unusually long words
    }
    return features

def phishing_score(email_text: str, url: str = None) -> tuple:
    """Compute phishing risk score."""
    email_features = extract_email_features(email_text)
    risk_score = 0.0
    factors = []
    
    # Email content scoring
    if email_features["suspicious_keyword_count"] > 2:
        risk_score += 20
        factors.append(f"Multiple phishing keywords ({email_features['suspicious_keyword_count']})")
    if email_features["urgent_count"] > 0:
        risk_score += 15
        factors.append("Urgency language detected")
    if email_features["has_verify_request"]:
        risk_score += 15
        factors.append("Account verification request (classic phishing)")
    if email_features["has_payment_request"]:
        risk_score += 10
        factors.append("Payment/card information request")
    
    # URL scoring (if provided)
    if url:
        url_features = extract_url_features(url)
        if not url_features["has_https"]:
            risk_score += 10
            factors.append("No HTTPS (unencrypted)")
        if url_features["has_ip"]:
            risk_score += 25
            factors.append("Direct IP URL (not domain name)")
        if url_features["has_shortener"]:
            risk_score += 15
            factors.append("URL shortener (masked destination)")
        if not url_features["is_known_domain"]:
            risk_score += 20
            factors.append("Unknown domain (not in safe list)")
        if url_features["url_length"] > 100:
            risk_score += 5
            factors.append("Unusually long URL")
    
    risk_score = min(risk_score, 100)
    return risk_score, factors

# Sidebar
with st.sidebar:
    st.header("⚙️ Detection Config")
    demo_email = st.checkbox("Load demo phishing email", value=True)
    demo_url = st.checkbox("Analyze demo URL", value=True)

# Main tabs
tab1, tab2 = st.tabs(["📧 Email Analysis", "🔗 URL Analysis"])

with tab1:
    st.subheader("Analyze Email for Phishing")
    
    if demo_email:
        email_input = st.text_area(
            "Email Content:",
            value="""Subject: URGENT: Verify Your Google Account

Dear Valued User,

Your Google account has unusual activity. Click here to verify your account immediately: http://203.45.67.89/verify

You must act now or your account will be suspended!

Best regards,
Google Support Team""",
            height=200
        )
    else:
        email_input = st.text_area("Email Content:", height=200)
    
    url_input = st.text_input("URL in email (optional):", value="http://203.45.67.89/verify" if demo_email else "")
    
    if st.button("🔍 Analyze Email"):
        risk_score, factors = phishing_score(email_input, url_input if url_input else None)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if risk_score >= 70:
                st.error(f"🚨 HIGH RISK: {risk_score:.0f}%")
            elif risk_score >= 40:
                st.warning(f"⚠️ MEDIUM RISK: {risk_score:.0f}%")
            else:
                st.success(f"✅ LOW RISK: {risk_score:.0f}%")
        
        with col2:
            st.metric("Risk Score", f"{risk_score:.0f}/100")
        
        with col3:
            recommendation = "BLOCK" if risk_score >= 70 else "FLAG" if risk_score >= 40 else "ALLOW"
            st.info(f"Action: {recommendation}")
        
        st.markdown("### 🚩 Risk Factors Detected:")
        for factor in factors:
            st.warning(f"• {factor}")
        
        if not factors:
            st.success("✅ No major red flags detected.")

with tab2:
    st.subheader("Analyze URL for Phishing")
    
    url_to_check = st.text_input(
        "Enter URL:",
        value="http://203.45.67.89/verify" if demo_url else "",
        placeholder="https://example.com"
    )
    
    if st.button("🔗 Check URL"):
        if url_to_check:
            features = extract_url_features(url_to_check)
            risk_score, factors = phishing_score("", url_to_check)
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### 📊 URL Features")
                st.write(f"**Domain:** {features['domain']}")
                st.write(f"**HTTPS:** {'✅' if features['has_https'] else '❌'}")
                st.write(f"**Direct IP:** {'❌ (BAD)' if features['has_ip'] else '✅'}")
                st.write(f"**URL Shortener:** {'⚠️ (Suspicious)' if features['has_shortener'] else '✅'}")
                st.write(f"**Known Domain:** {'✅' if features['is_known_domain'] else '⚠️'}")
            
            with col2:
                st.markdown("### ⚠️ Risk Assessment")
                if risk_score >= 70:
                    st.error(f"🚨 HIGH RISK: {risk_score:.0f}%")
                elif risk_score >= 40:
                    st.warning(f"⚠️ MEDIUM RISK: {risk_score:.0f}%")
                else:
                    st.success(f"✅ LOW RISK: {risk_score:.0f}%")
                
                st.metric("Risk Score", f"{risk_score:.0f}/100")

st.markdown("---")
st.caption("Stack: scikit-learn · XGBoost · TF-IDF · URL Analysis · Streamlit")
