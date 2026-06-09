import streamlit as st
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

st.set_page_config(page_title="ScamGuard | True Threat Analysis", page_icon="🛡️", layout="centered")

# ================= BACKGROUND SETUP & APIS ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "")

# ⚠️ ENSURE THIS MATCHES YOUR LIVE STREAMLIT LINK!
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

saved_user = cookie_manager.get(cookie="scamguard_user")
if saved_user and not st.session_state["logged_in"]:
    st.session_state["logged_in"] = True
    st.session_state["user_email"] = saved_user
    st.session_state["is_premium"] = check_premium_status(saved_user)

expire_date = datetime.datetime.now() + datetime.timedelta(days=3650)

if not st.session_state.get("logged_in") and st.query_params.get("code"):
    with st.spinner("Securely verifying Identity Matrix..."):
        user_email = verify_google_code(st.query_params.get("code"))
        if user_email:
            st.session_state["logged_in"] = True
            st.session_state["user_email"] = user_email
            st.session_state["is_premium"] = check_premium_status(user_email)
            st.query_params.clear() 
            
            # Upgraded Feature: Ensure Google Log-ins are ALSO remembered for 10 years!
            cookie_manager.set("scamguard_user", user_email, expires_at=expire_date)
            time.sleep(1) # CRITICAL: Gives browser time to store the new cookie.
            st.rerun()
        else:
            st.error("Authentication halted by gateway. Switch to Local Passkeys.")
            st.query_params.clear()

# ================= MAIN LOGIN UI ================= #
if not st.session_state.get("logged_in"):
    with st.sidebar:
        st.title("🛡️ Secure Access")
        
        if GOOGLE_CLIENT_ID:
            st.subheader("Fast Verification")
            auth_url = get_google_auth_url()
            st.link_button("🌐 Continue with Google", auth_url, use_container_width=True)
            st.divider()
        else:
            st.error("🔑 Notice to Admin: Setup APIs in Streamlit settings.")
        
        auth_mode = st.selectbox("Backup Login Method", ["Log In", "Sign Up For Free"])
        email = st.text_input("Email Address").lower().strip()
        password = st.text_input("Password", type='password')
        remember_me = st.checkbox("Keep me logged in forever")
        
        if auth_mode == "Sign Up For Free":
            if st.button("Create Account"):
                if email and password:
                    try:
                        add_user(email, hash_pswd(password))
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = email
                        st.session_state["is_premium"] = check_premium_status(email)
                        
                        if remember_me: 
                            cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                        time.sleep(1) # CRITICAL Buffer
                        st.rerun()
                    except sqlite3.IntegrityError: st.error("Email is registered.")
                else: st.warning("Please fill all fields.")
                    
        elif auth_mode == "Log In":
            if st.button("Access Dashboard"):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    
                    if remember_me: 
                        cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                    time.sleep(1) # CRITICAL Buffer
                    st.rerun()
                else: st.error("Incorrect Email or Password.")
else:
    # ---------------- Active Hub Session ----------------
    with st.sidebar:
        st.success(f"Verified Identity:\n{st.session_state['user_email']}")
        
        if st.session_state["is_premium"]:
            st.info("💎 Status: PREMIUM USER")
            st.markdown("* ✅ File Upload Scans\n* ✅ Malicious Deep Trace\n* ✅ Priority Fast Nodes")
        else:
            st.warning("👤 Status: Free Account")
            
            # ⚠️ ADD YOUR REAL STRIPE BUY LINK ON THIS LINE:
            st.link_button("💳 Upgrade for Full Capabilities", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00")
            st.caption("Please checkout using the exact email you are logged in with to instantly activate your benefits.")
            
        st.divider()
        if st.button("Secure Log Out"):
            # Turn variables off
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
            st.session_state["is_premium"] = False
            st.query_params.clear()
            
            # Send javascript request to browser to burn cookie keys
            cookie_manager.delete("scamguard_user")
            
            # MASSIVELY IMPORTANT SLEEP TIMER: Allows browser to clear its system tracking cookies successfully before Streamlit reboots page 
            with st.spinner("Securely ending private instance session..."):
                time.sleep(1.5)
            st.rerun()

# ================= CORE AI ANALYSIS LOGIC ================= #
def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text)

def analyze_threat(text, is_premium):
    prem = "\nEXECUTE ENTERPRISE DIVE: Conduct deep analysis of link psychology and masking intent." if is_premium else ""
    prompt = f"Analyze if this email is a scam. Score risk 0-100. Give practical advice.{prem}\nContext:\n{text}"
    fallbacks = ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-pro-exp-02-05:free", "microsoft/phi-3-mini-128k-instruct:free"]
    
    for n in fallbacks:
        try:
            resp = client.chat.completions.create(model=n, max_tokens=800, messages=[{"role":"system","content":"You are a tactical Threat Analyst AI."},{"role":"user","content":prompt}])
            return resp.choices[0].message.content
        except Exception:
            time.sleep(0.5)
            continue
    return "⚠️ Server network traffic bottlenecking detected. Click scan again."

# --- Security Scanner Interface ---
if st.session_state.get("logged_in"):
    st.title("🛡️ Secure Email Processing Node")
    txt = st.text_area("📋 Insert suspicious mail contents or link here:", height=150)

    if st.session_state["is_premium"]:
        file = st.file_uploader("📄 Premium Module: Attach Fake Invoices/PDFs", type=['txt', 'pdf'])
        if file:
            try:
                if file.name.endswith('.pdf'):
                    pdf = PyPDF2.PdfReader(file)
                    txt += " \n\n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                else: txt += " \n\n" + file.getvalue().decode("utf-8")
            except Exception: st.error("Reader failed to mount Document code")

    if st.button("🚨 Run Heuristic Scan Protocol"):
        if not txt.strip():
            st.warning("System pending input...")
        else:
            if st.session_state["is_premium"]:
                found = extract_urls(txt)
                if found:
                    st.error(f"🛑 Found {len(found)} URL vectors buried within string:")
                    for u in found: st.code(u)

            with st.spinner("Decoding language markers and server intentions via Neural Grid..."):
                r = analyze_threat(txt, st.session_state["is_premium"])
                if "⚠️" in r: st.error(r)
                else: 
                    st.success("✅ Assessment Finalized.")
                    st.write(r)
else:
    st.title("🛡️ Welcome to ScamGuard Identity Protector")
    st.subheader("Stop the $3 billion a year phishing crisis locally on your computer.")
    st.write("Scan deep emails against malicious intent networks dynamically through secure open routers globally for completely zero cost limitations")
    st.error("🔒 Please expand the left sidebar menu to sign in securely and deploy your private instance hub!")
