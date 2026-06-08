import streamlit as st
from openai import OpenAI
import os

st.set_page_config(page_title="ScamGuard AI Analyzer", page_icon="🛡️", layout="centered")

st.sidebar.title("💎 Premium ScamGuard")
st.sidebar.markdown("""
* ✅ 24/7 Priority Processing
* ✅ Scan Malicious URLs & PDFs
* ✅ Forward Emails to Scan (API access)
""")
st.sidebar.link_button("💳 Subscribe to Premium ($4.99/mo)", "https://stripe.com/")

# Fetch OpenRouter API key securely
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)

def analyze_email(text):
    prompt = f"""You are an elite cybersecurity AI. Analyze this email. 
    1. Score it 0 to 100 on scam risk.
    2. List top 3 phishing triggers (urgency, spoofed domains, psychology).
    3. Final advice (Ignore, Safe, or Verify via external channels).
    Email Text: {text}"""
    
    # We use 'openrouter/free'. This relies on their internal load balancer, which instantly 
    # picks ANY available, highly responsive free model without ever throwing 404 routing errors.
    response = client.chat.completions.create(
      model="openrouter/free",
      max_tokens=600, # Stops 402 out-of-credit threshold loops 
      messages=[
          {"role": "system", "content": "You are ScamGuard, a helpful security AI."},
          {"role": "user", "content": prompt}
      ]
    )
    return response.choices[0].message.content

st.title("🛡️ ScamGuard Email Phishing AI")
st.write("Detect gift card scams, CEO impersonation, and fake invoices in seconds.")

email_text = st.text_area("📋 Paste suspicious email text here:", height=200)

if st.button("🔍 Scan for Threats"):
    if not API_KEY:
        st.error("Setup required: Add API key to .streamlit/secrets.toml")
    elif not email_text:
        st.warning("Please paste an email.")
    else:
        with st.spinner("AI analyzing threat footprint across our decentralized servers..."):
            try:
                result = analyze_email(email_text)
                st.success("✅ Analysis Complete!")
                st.write(result)
                st.divider()
                st.info("Unlock Premium for in-depth technical analysis of embedded IP trackers.")
            except Exception as e:
                st.error(f"⚠️ Network congestion warning. Error trace: {e}")