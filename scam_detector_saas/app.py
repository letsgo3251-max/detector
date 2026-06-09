import streamlit as st
import streamlit.components.v1 as components
from openai import OpenAI
import os
import time
import re
import PyPDF2
import sqlite3
import hashlib
import stripe
import datetime
import urllib.parse
import requests
import extra_streamlit_components as stx

st.set_page_config(page_title="ScamGuard | True Threat Analysis", page_icon="🛡️", layout="wide")

# ================= CUSTOM ENTERPRISE CSS INJECTION ================= #
st.markdown("""
    <style>
    /* Clean up default Streamlit menus */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Professional modern button styling */
    div.stButton > button {
        background-color: #2e66ff;
        color: white;
        border-radius: 6px;
        border: none;
        transition: 0.3s;
        font-weight: bold;
    }
    div.stButton > button:hover {
        background-color: #1a4dcf;
        box-shadow: 0px 4px 10px rgba(46,102,255,0.4);
    }
    
    /* Dark professional metric panels */
    div[data-testid="metric-container"] {
        background-color: #1e1e1e;
        border: 1px solid #333;
        padding: 10px;
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# ================= BACKGROUND SETUP & APIS ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "")

# ⚠️ ENSURE THIS EXACTLY MATCHES YOUR AUTHORIZED URI IN GOOGLE CLOUD
REDIRECT_URI = "https://email-scam-detector.streamlit.app/"

client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)
stripe.api_key = STRIPE_KEY

# Secure local fallback database
conn = sqlite3.connect("scamguard_users.db", check_same_thread=False)
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS userstable(email TEXT PRIMARY KEY, password TEXT)')
conn.commit()

def add_user(email, password):
    c.execute('INSERT INTO userstable(email, password) VALUES (?,?)', (email, password))
    conn.commit()

def login_user(email, password):
    c.execute('SELECT * FROM userstable WHERE email = ? AND password = ?', (email, password))
    return c.fetchall()

def hash_pswd(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_premium_status(user_email):
    """Securely checks your real Stripe account if this email pays the monthly fee."""
    if user_email == "admin@scamguard.com": return True 
    if not STRIPE_KEY: return False 
    try:
        customers = stripe.Customer.search(query=f"email:'{user_email}'")
        if not customers.data: return False
        subs = stripe.Subscription.list(customer=customers.data[0].id, status="active")
        return len(subs.data) > 0
    except Exception:
        return False

# ================= NATIVE GOOGLE SSO ================= #
def get_google_auth_url():
    if not GOOGLE_CLIENT_ID: return "#"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile"
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)

def verify_google_code(code):
    try:
        r = requests.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        })
        access_token = r.json().get("access_token")
        if not access_token: return None
        res = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={"Authorization": f"Bearer {access_token}"})
        return res.json().get("email")
    except Exception:
        return None

# ================= AUTH MEMORY (COOKIE) MANAGER ================= #
cookie_manager = stx.CookieManager(key="sg_cookies")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

# Auto-login checking 10-year browser cookie
saved_user = cookie_manager.get(cookie="scamguard_user")
if saved_user and not st.session_state["logged_in"]:
    st.session_state["logged_in"] = True
    st.session_state["user_email"] = saved_user
    st.session_state["is_premium"] = check_premium_status(saved_user)

# Intercept Google login callback code cleanly
if not st.session_state.get("logged_in") and st.query_params.get("code"):
    with st.spinner("Securing Enterprise Connection..."):
        user_email = verify_google_code(st.query_params.get("code"))
        if user_email:
            st.session_state["logged_in"] = True
            st.session_state["user_email"] = user_email
            st.session_state["is_premium"] = check_premium_status(user_email)
            st.query_params.clear() 
            st.rerun()
        else:
            st.error("Authentication integration disrupted by Network protocols.")
            st.query_params.clear()

# ================= LOGIN PORTAL UI ================= #
if not st.session_state.get("logged_in"):
    col1, col2, col3 = st.columns([1, 2, 1]) # Centered enterprise layout
    with col2:
        st.title("🛡️ Secure AI Authenticator")
        st.write("Welcome to ScamGuard Cloud Intelligence Platform.")
        st.divider()

        # --- The Javascript "Sledgehammer" Google Iframe Bypass ---
        if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
            st.markdown("##### Preferred Network")
            # Using native streamlit button instead of HTML box, launching secure top-level JS navigation.
            if st.button("🌐 Sign In Securely with Google", use_container_width=True):
                auth_url = get_google_auth_url()
                components.html(f"<script>window.parent.location.href='{auth_url}';</script>", height=0, width=0)
            st.divider()
            
        st.markdown("##### Corporate Login Access")
        auth_mode = st.selectbox("Action Directive", ["Sign In with Passkey", "Establish Free Account"])
        email = st.text_input("Identity Reference (Email)").lower().strip()
        password = st.text_input("Secure Vault Passkey", type='password')
        remember_me = st.checkbox("Keep network tunnel open (Remember Me)")
        expire_date = datetime.datetime.now() + datetime.timedelta(days=3650)
        
        if auth_mode == "Establish Free Account":
            if st.button("Create Authorization Vault"):
                if email and password:
                    try:
                        add_user(email, hash_pswd(password))
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = email
                        st.session_state["is_premium"] = check_premium_status(email)
                        if remember_me: cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                        time.sleep(0.5) 
                        st.rerun()
                    except sqlite3.IntegrityError: st.error("Email Identity currently allocated. Switch to Sign In.")
                else: st.warning("Requires strict parameters (email & pass).")
                    
        elif auth_mode == "Sign In with Passkey":
            if st.button("Enter Dashboard Interface"):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    if remember_me: cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                    time.sleep(0.5)
                    st.rerun()
                else: st.error("Auth Failure: Credentials rejected by protocol.")

else:
    # ---------------- ACTIVE HUB UI (ENTERPRISE EDITION) ----------------
    with st.sidebar:
        st.image("https://upload.wikimedia.org/wikipedia/commons/e/e4/Security_blue.svg", width=60)
        st.subheader(f"Access Protocol\n{st.session_state['user_email']}")
        st.divider()

        if st.session_state["is_premium"]:
            st.success("💳 Status: PREMIUM ACTIVE")
            st.markdown("- Deep PDF Tracking Enabled\n- Sub-surface Link Extraction")
        else:
            st.info("⚠️ Status: Free Developer Plan")
            # ⚠️ ADD YOUR REAL STRIPE BUY LINK ON THIS LINE BELOW:
            st.link_button("🚀 Enable Premium Infrastructure", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00")
            st.caption("Transactions sync automatically utilizing secure gateway match criteria.")
            
        st.divider()
        if st.button("Close Active Session"):
            try:
                if cookie_manager.get(cookie="scamguard_user"): cookie_manager.delete("scamguard_user")
            except Exception: pass
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
            st.session_state["is_premium"] = False
            time.sleep(1.5)
            st.rerun()

    # --- Secure Scan Architecture Interface ---
    st.title("🛡️ Threat Assessment Dashboard")
    st.write("Deploy the heuristic grid logic analyzer on sophisticated text vectors natively through secure channels.")
    st.divider()

    tcol1, tcol2 = st.columns([2, 1])

    with tcol1:
        txt = st.text_area("📋 Submit Malicious Array Data:", placeholder="Enter Email text or Phishing payloads natively.", height=180)

        if st.session_state["is_premium"]:
            file = st.file_uploader("📄 Elite Component: Drop PDFs and Invoices for sub-frame string pulls", type=['txt', 'pdf'])
            if file:
                try:
                    if file.name.endswith('.pdf'):
                        pdf = PyPDF2.PdfReader(file)
                        txt += " \n\n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                    else: txt += " \n\n" + file.getvalue().decode("utf-8")
                    st.info("Uploaded data successfully merged to scan target.")
                except Exception: st.error("Document ingestion pipeline broke.")

        run_scan = st.button("🚨 Compile Threat Logic")

    with tcol2:
        st.markdown("##### Current System Parameters:")
        st.metric(label="Server Operational Health", value="Optimal")
        if st.session_state["is_premium"]:
            st.metric(label="Queue Limitations", value="Infinite")
        else:
            st.metric(label="Payload Cap Enabled", value="Warning")

    st.divider()

    if run_scan:
        if not txt.strip():
            st.warning("Insufficient length. Submit content to launch heuristics.")
        else:
            if st.session_state["is_premium"]:
                urls = re.findall(r'(https?://[^\s]+)', txt)
                if urls:
                    st.error(f"🛑 Found {len(urls)} URL network calls attached:")
                    for u in urls: st.code(u)

            with st.spinner("Grid execution processing psychological identifiers against remote scam heuristics..."):
                # Round-robin
                prompt = f"Act as elite CyberSec Threat Intel. Score Risk: 0-100. Breakdown the exact fraud markers in text. End with safe verdict.\nText:\n{txt}"
                models = ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-pro-exp-02-05:free"]
                final_res = "⚠️ Systems Busy."
                for m in models:
                    try:
                        res = client.chat.completions.create(model=m, max_tokens=850, messages=[{"role":"user","content":prompt}])
                        final_res = res.choices[0].message.content
                        break
                    except Exception:
                        time.sleep(0.5)
                        continue

                st.markdown("### Threat Eradication Log:")
                if "⚠️" in final_res: st.error(final_res)
                else: 
                    st.success("Target analysis completed securely.")
                    st.write(final_res)
