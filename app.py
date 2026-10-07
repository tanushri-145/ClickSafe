import re
from urllib.parse import urlparse
 
from flask import Flask, render_template, request, jsonify
from transformers import pipeline
 
app = Flask(__name__)
 
print("Loading model...")
 
classifier = pipeline(
    "text-classification",
    model="./phishing_model",
    tokenizer="./phishing_model"
)
 
print("Model loaded successfully!")
 
 
# ---------- Rule layer (sits on top of the model) ----------
 
# Domains you trust. A host matches if it IS the domain or a subdomain of it.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "linkedin.com", "spotify.com",
    "wikipedia.org", "microsoft.com", "apple.com", "amazon.com", "amazon.in",
    "facebook.com", "instagram.com", "x.com", "twitter.com", "reddit.com",
    "stackoverflow.com", "vercel.app", "netflix.com", "paypal.com",
}
 
# Brand names that phishers imitate.
BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "sbi", "hdfc", "icici", "bankofamerica",
]
 
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "work", "support", "buzz"}
 
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
            "suspend", "confirm", "banking", "password", "wallet"]
 
 
def get_host(url):
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()
 
 
def is_trusted(host):
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)
 
 
def rule_score(url, host):
    score = 0
    reasons = []
    lowered = url.lower()
 
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 3
        reasons.append("the host is a raw IP address")
 
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 2
        reasons.append("it uses a .%s domain, common in phishing" % tld)
 
    if any(b in host for b in BRANDS):
        score += 2
        reasons.append("it names a well-known brand on a domain that isn't theirs")
 
    if host.count("-") >= 2:
        score += 1
        reasons.append("the domain has several hyphens")
 
    if host.count(".") >= 3:
        score += 1
        reasons.append("the domain has many subdomains")
 
    hits = [k for k in KEYWORDS if k in lowered]
    if len(hits) >= 2:
        score += 1
        reasons.append("it contains words like " + ", ".join(hits[:3]))
 
    if "@" in url:
        score += 2
        reasons.append("it contains an @ sign, which can hide the real destination")
 
    if len(url) > 75:
        score += 1
        reasons.append("the URL is unusually long")
 
    return score, reasons
 
 
# ---------- Routes ----------
 
@app.route("/")
def home():
    return render_template("index.html")
 
 
@app.route("/predict", methods=["POST"])
def predict():
 
    try:
        data = request.get_json()
 
        url = data.get("url", "").strip()
 
        print("URL received:", url)
 
        if not url:
            return jsonify({
                "error": "Please enter a URL."
            }), 400
 
        result = classifier(url)[0]
        print("Model result:", result)
 
        label = result["label"]
        confidence = result["score"]
        reasons = []
 
        host = get_host(url)
        rules, rule_reasons = rule_score(url, host)
        print("Rule score:", rules, rule_reasons)
 
        if is_trusted(host):
            # Known-good domain: trust it over the model (fixes profile-URL misses).
            if label.lower() != "safe":
                print("Overridden by trusted domain list")
            label = "Safe"
        elif rules >= 3 and label.lower() == "safe":
            # Strong suspicious signals but model said safe: flag it.
            print("Overridden by rules")
            label = "Phishing"
            confidence = min(0.5 + 0.08 * rules, 0.95)
            reasons = rule_reasons
 
        return jsonify({
            "prediction": label,
            "confidence": confidence,
            "reasons": reasons
        })
 
    except Exception as e:
 
        print("ERROR:", repr(e))
 
        return jsonify({
            "error": str(e)
        }), 500
 
 
if __name__ == "__main__":
    app.run(debug=False)
 

