import streamlit as st
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
from openai import OpenAI

st.set_page_config(page_title="ScamGuard | Executive Security", page_icon="🛡️", layout="wide")

# ================= CUSTOM ENTERPRISE CSS INJECTION ================= #
# This annihilates the Streamlit footers/logos and converts UI into high-end Silicon Valley UX
st.markdown("""
    <style>
    /* Destroy Default Streamlit Clutter (Headers, Menus, Footers, and Logos) */
    #MainMenu, footer, header, .viewerBadge_container, [data-testid="stHeader"], [data-testid="stDecoration"], [data-testid="manage-app-button"] {
        visibility: hidden !important;
        display: none !important;
    }
    
    /* Clean, Modern Font & Margin Architecture */
    html, body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    }

    /* Silicon Valley Luxury Primary Buttons (Meta/Apple style) */
    div.stButton > button:first-child {
        background: linear-gradient(135deg, #0b57d0 0%, #1a73e8 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.5rem;
        font-weight: 600;
        box-shadow: 0 4px 14px rgba(26, 115, 232, 0.4);
        transition: all 0.2s ease-in-out;
        width: 100%;
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(26, 115, 232, 0.6);
        background: linear-gradient(135deg, #1a73e8 0%, #0b57d0 100%);
        color: white;
    }

    /* Elevated Premium Containers */
    [data-testid="stSidebar"] {
        border-right: 1px solid rgba(255,255,255,0.05) !important;
        background-color: #0c0f14 !important;
    }
    
    /* Deep Corporate UI for Inputs */
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
        color: #e6edf3 !important;
        border-radius: 8px !important;
        box-shadow: inset 0 2px 5px rgba(0,0,0,0.2) !important;
        transition: all 0.2s ease;
    }
    .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
        border-color: #2f81f7 !important;
        box-shadow: 0 0 0 3px rgba(47, 129, 247, 0.2) !important;
    }

    /* Google Button Custom A-Tag to match Primary Button Theme */
    .google-btn-native {
        display: block;
        width: 100%;
        padding: 0.6rem 1.5rem;
        background-color: white;
        color: #3c4043 !important;
        text-align: center;
        text-decoration: none;
        font-weight: bold;
        font-size: 15px;
        border-radius: 8px;
        border: 1px solid #dadce0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        transition: background 0.2s, box-shadow 0.2s;
    }
    .google-btn-native:hover {
        background-color: #f8f9fa;
        box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        color: #3c4043 !important;
        text-decoration: none;
    }
    </style>
""", unsafe_allow_html=True)

# ================= BACKGROUND SETUP & APIS ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "")

# ⚠️ ENSURE THIS MATCHES GOOGLE CLOUD AND INCLUDES THE TRAILING SLASH!
REDIRECT_URI = "https://email-scam-detector.streamlit.app/"

client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)
stripe.api_key = STRIPE_KEY

# Secure Database Connection
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
    """Secure Stripe check running quietly in the background"""
    if user_email == "admin@scamguard.com": return True 
    if not STRIPE_KEY: return False 
    try:
        customers = stripe.Customer.search(query=f"email:'{user_email}'")
        if not customers.data: return False
        subs = stripe.Subscription.list(customer=customers.data[0].id, status="active")
        return len(subs.data) > 0
    except Exception:
        return False

# ================= BULLETPROOF GOOGLE OAUTH ================= #
def get_google_auth_url():
    if not GOOGLE_CLIENT_ID: return "#"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
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
        token_data = r.json()
        if not token_data.get("access_token"): return None
        res = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={"Authorization": f"Bearer {token_data.get('access_token')}"})
        return res.json().get("email")
    except Exception as e:
        return None

# ================= AUTH MEMORY ================= #
cookie_manager = stx.CookieManager(key="sg_cookies")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

# Auto-Login (Bypasses rendering Login screen immediately if Cookie is detected)
saved_user = cookie_manager.get(cookie="scamguard_user")
if saved_user and not st.session_state["logged_in"]:
    st.session_state["logged_in"] = True
    st.session_state["user_email"] = saved_user
    st.session_state["is_premium"] = check_premium_status(saved_user)

# Evaluate Callback Intercept natively
if not st.session_state.get("logged_in") and st.query_params.get("code"):
    user_email = verify_google_code(st.query_params.get("code"))
    if user_email:
        st.session_state["logged_in"] = True
        st.session_state["user_email"] = user_email
        st.session_state["is_premium"] = check_premium_status(user_email)
        expire_date = datetime.datetime.now() + datetime.timedelta(days=3650)
        cookie_manager.set("scamguard_user", user_email, expires_at=expire_date)
        time.sleep(1) # Finalizer save cycle for cookie processing
        st.query_params.clear() 
        st.rerun()
    else:
        st.error("Google authentication link invalid or expired.")
        st.query_params.clear()

# ================= USER PORTAL (LOGIN SCREEN) ================= #
if not st.session_state.get("logged_in"):
    st.title("🛡️ Identity & Defense Protocol")
    st.markdown("We neutralize deep-tier social engineering schemes in seconds using enterprise-scale node routing. Start operating instantly.")
    
    col_l, empty, col_r = st.columns([4, 1, 4])
    
    with col_l:
        st.markdown("### Access Authorization")
        st.write("Link identity instantly. No account required.")
        if GOOGLE_CLIENT_ID:
            auth_url = get_google_auth_url()
            # This HTML directly intercepts clicks, guarantees Target _top breakage and runs flawless CSS integration.
            btn_html = f'''
            <a href="{auth_url}" target="_top" class="google-btn-native">
                <span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#34A853">g</span><span style="color:#4285F4">l</span><span style="color:#EA4335">e</span> Sign-In Handshake
            </a>
            '''
            st.markdown(btn_html, unsafe_allow_html=True)
        else:
            st.warning("Admin Check required for keys.")
            
        st.divider()
        auth_mode = st.radio("Standard Entry Protocol:", ["Existing Credential Portal", "Issue New Free Clearance"], horizontal=True, label_visibility="collapsed")
        
        email = st.text_input("Identity Register (Email)").lower().strip()
        password = st.text_input("Verification Protocol (Passkey)", type='password')
        remember_me = st.checkbox("Persistent Login Key (10 years)", value=True)
        expire_date = datetime.datetime.now() + datetime.timedelta(days=3650)
        
        if auth_mode == "Issue New Free Clearance":
            if st.button("Establish Encrypted Core Account", use_container_width=True):
                if email and password:
                    try:
                        add_user(email, hash_pswd(password))
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = email
                        st.session_state["is_premium"] = check_premium_status(email)
                        if remember_me: cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                        time.sleep(0.5) 
                        st.rerun()
                    except sqlite3.IntegrityError: st.error("Database conflict: Account ID present.")
                else: st.warning("Data incomplete.")
                    
        elif auth_mode == "Existing Credential Portal":
            if st.button("Transmit Payload and Access", use_container_width=True):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    if remember_me: cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                    time.sleep(0.5)
                    st.rerun()
                else: st.error("Authentication rejected: Parameters incorrect.")
                
    with col_r:
        # Added sleek right panel mimicking Enterprise aesthetic details
        st.info("📊 **Operational Intel**\n\nThe 2026 digital ecosystem faces $3B/year in targeted identity manipulation traps. Enterprise protocols defend networks safely by decentralizing validation keys utilizing external security LLMs in unthrottled zero-tier queues.")
        
else:
    # ---------------- MAIN OPERATIONS (DASHBOARD) ----------------
    with st.sidebar:
        st.subheader("Secure Transmission Portal")
        st.caption(f"Network Key:\n{st.session_state['user_email']}")
        st.divider()

        if st.session_state["is_premium"]:
            st.success("🟢 Security Override Active: PREMIUM")
            st.markdown("- Enterprise AI Priority Pools\n- Encrypted Doc Extractors")
        else:
            st.warning("🟡 Developer Free Tier Running")
            # ⚠️ ADD YOUR REAL STRIPE BUY LINK ON THIS LINE BELOW:
            st.link_button("💎 Uplink to Infinite Scale Protocol", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00", use_container_width=True)
            st.caption("Verify purchases locally automatically mapping user keys.")
            
        st.divider()
        if st.button("Disconnect Local Server Memory", use_container_width=True):
            try:
                if cookie_manager.get(cookie="scamguard_user"): cookie_manager.delete("scamguard_user")
            except Exception: pass
            st.session_state["logged_in"] = False
            time.sleep(0.5)
            st.rerun()

    def extract_urls(text):
        return re.findall(r'(https?://[^\s]+)', text)

    def analyze_threat(text, is_premium):
        prem = "\nVIP Request: Provide surgical trace mapping to origin domains." if is_premium else ""
        prompt = f"Scam and exploit threat scan needed. Score integer Risk from 0 to 100%. Highlight structural threat. Details:\n{text}{prem}"
        fallbacks = ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-pro-exp-02-05:free"]
        
        for n in fallbacks:
            try:
                resp = client.chat.completions.create(model=n, max_tokens=700, messages=[{"role":"system","content":"Tactical Security Assessor AI deployed."},{"role":"user","content":prompt}])
                return resp.choices[0].message.content
            except Exception:
                time.sleep(0.2)
                continue
        return "⚠️ Redundancy networks depleted momentarily. Upgrade to priority enterprise or refresh connection loop."

    st.title("🛡️ Core Diagnostics: Neural Fraud Tracker")
    st.write("Intercept strings of potential bad actor attempts securely mapping psychological triggers autonomously.")

    txt = st.text_area("📋 Deposit Transmission Strings/Headers Below:", height=180, placeholder="Example: PayPal Final Urgent Reminder...")

    if st.session_state["is_premium"]:
        file = st.file_uploader("📁 Document Processing Core: Injest PDF records.", type=['txt', 'pdf'])
        if file:
            try:
                if file.name.endswith('.pdf'):
                    pdf = PyPDF2.PdfReader(file)
                    txt += " \n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                else: txt += " \n" + file.getvalue().decode("utf-8")
            except Exception: st.error("Unable to execute translation matrix.")

    if st.button("🚨 Compile Threat Geometry Scan", use_container_width=True):
        if not txt.strip():
            st.warning("Insufficient length. Submit content array to process execution.")
        else:
            if st.session_state["is_premium"]:
                found = extract_urls(txt)
                if found:
                    st.error(f"🛑 Found {len(found)} background IP tracking hyperlinks globally:")
                    for u in found: st.code(u)

            with st.spinner("Compiling tactical behavior heuristics to global open weights node instances..."):
                r = analyze_threat(txt, st.session_state["is_premium"])
                if "⚠️" in r: st.error(r)
                else: 
                    st.success("✅ Deep Network Matrix Resolved Output:")
                    st.info(r)
