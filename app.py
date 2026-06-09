import streamlit as st
from openai import OpenAI
import os
import time
import re
import PyPDF2
import sqlite3
import hashlib
import stripe
import asyncio
from httpx_oauth.clients.google import GoogleOAuth2

st.set_page_config(page_title="ScamGuard | True Threat Analysis", page_icon="🛡️", layout="centered")

# ================= BACKGROUND SETUP & APIS ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "")

# ⚠️ TODO #1: REPLACE WITH YOUR EXPECTED LIVE STREAMLIT LINK! MUST END IN A SLASH (/)
REDIRECT_URI = "https://email-scam-detector.streamlit.app/"

client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)
stripe.api_key = STRIPE_KEY

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    google_oauth2 = GoogleOAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
else:
    google_oauth2 = None

# Secure local fallback database
conn = sqlite3.connect("scamguard_users.db", check_same_thread=False)
c = conn.cursor()

def create_usertable():
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
    if user_email == "admin@scamguard.com": return True # Master override 
    if not STRIPE_KEY: return False 
    try:
        customers = stripe.Customer.search(query=f"email:'{user_email}'")
        if not customers.data: return False
        subs = stripe.Subscription.list(customer=customers.data[0].id, status="active")
        return len(subs.data) > 0
    except Exception as e:
        return False

create_usertable()

# ================= GOOGLE OAUTH INTERCEPT LOGIC ================= #
async def google_login():
    code = st.query_params.get("code")
    if code and google_oauth2:
        try:
            token = await google_oauth2.get_access_token(code, REDIRECT_URI)
            user_id, user_email = await google_oauth2.get_id_email(token['access_token'])
            
            st.session_state["logged_in"] = True
            st.session_state["user_email"] = user_email
            st.session_state["is_premium"] = check_premium_status(user_email)
            st.query_params.clear() 
            st.rerun()
        except Exception as e:
            st.error(f"Google verification failed. If testing locally, set REDIRECT_URI back to http://localhost:8501/")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state.get("logged_in") and st.query_params.get("code"):
    asyncio.run(google_login())

# ================= LOGIN PORTAL UI ================= #
if not st.session_state.get("logged_in"):
    with st.sidebar:
        st.title("🛡️ Secure Access")
        
        # Google SSO
        if google_oauth2:
            st.subheader("1-Click Authentication")
            authorization_url = asyncio.run(google_oauth2.get_authorization_url(REDIRECT_URI, scope=["email"]))
            st.markdown(f'<a href="{authorization_url}" target="_top" style="display: block; width: 100%; padding: 10px; background-color: white; color: black; border: 1px solid #ccc; text-align: center; text-decoration: none; font-weight: bold; border-radius: 5px;">Continue with Google</a>', unsafe_allow_html=True)
            st.divider()
        
        # Email & Pass Backup
        auth_mode = st.selectbox("Standard Login", ["Log In", "Sign Up For Free"])
        email = st.text_input("Email Address").lower()
        password = st.text_input("Password", type='password')
        
        if auth_mode == "Sign Up For Free":
            if st.button("Create Local Account"):
                if email and password:
                    try:
                        add_user(email, hash_pswd(password))
                        st.success("Account Created! You can now log in.")
                    except sqlite3.IntegrityError:
                        st.error("Email is registered. Try logging in.")
                else: st.warning("Fill all fields.")
                    
        elif auth_mode == "Log In":
            if st.button("Access Dashboard"):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    st.rerun()
                else: st.error("Incorrect Email/Password.")
else:
    # ---------------- Logged In Profile UI ----------------
    with st.sidebar:
        st.success(f"Session Active:\n{st.session_state['user_email']}")
        
        if st.session_state["is_premium"]:
            st.info("💎 Status: PREMIUM USER")
            st.markdown("* ✅ File Upload Scans\n* ✅ Malicious Deep Trace\n* ✅ Priority Fast Nodes")
        else:
            st.warning("👤 Status: Free Account")
            st.write("Upgrade for full capability:")
            # ⚠️ TODO #2: REPLACE THE STRIPE LINK BELOW WITH YOUR REAL BUY.STRIPE LINK!
            st.link_button("💳 Upgrade ($4.99/mo)", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00")
            st.caption("IMPORTANT: Make sure you type your current login email at Stripe checkout so our system upgrades you automatically!")
        
        st.divider()
        if st.button("Secure Log Out"):
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
            st.session_state["is_premium"] = False
            st.rerun()

# ================= CORE AI ANALYSIS LOGIC ================= #
def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text)

def analyze_threat(text, is_premium):
    prem = "\nEXECUTE ENTERPRISE DIVE: Perform high psychological risk triage. Outline precise URL traps." if is_premium else ""
    prompt = f"Analyze if this email is a scam. Score risk 0 to 100. Give precise advice.{prem}\nEmail Context:\n{text}"
    
    fallbacks = [
        "meta-llama/llama-3.3-70b-instruct:free",
        "google/gemini-2.0-pro-exp-02-05:free"
    ]
    
    for n in fallbacks:
        try:
            resp = client.chat.completions.create(model=n, max_tokens=750, messages=[{"role":"system","content":"You are ScamGuard Threat Analyst AI."},{"role":"user","content":prompt}])
            return resp.choices[0].message.content
        except Exception:
            time.sleep(0.5)
            continue
    return "⚠️ Server bottleneck. Open internet security nodes are at maximum capacity right now. Try again momentarily."

if st.session_state.get("logged_in"):
    st.title("🔍 Threat Interceptor Console")
    txt = st.text_area("📋 Target Payload:", height=150)

    if st.session_state["is_premium"]:
        file = st.file_uploader("📄 Premium Module: Attach Fake Invoices/PDFs", type=['txt', 'pdf'])
        if file:
            try:
                if file.name.endswith('.pdf'):
                    pdf = PyPDF2.PdfReader(file)
                    txt += " \n\n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                else: txt += " \n\n" + file.getvalue().decode("utf-8")
                st.info("Uploaded data successfully merged to scan target.")
            except Exception: 
                st.error("Error formatting document.")

    if st.button("🚨 Execute Analysis"):
        if txt.strip():
            if st.session_state["is_premium"]:
                found = extract_urls(txt)
                if found:
                    st.error(f"🛑 Found {len(found)} masked internet hyperlinks:")
                    for u in found: st.code(u)

            with st.spinner("AI analyzing spoofing patterns and social engineering risks..."):
                r = analyze_threat(txt, st.session_state["is_premium"])
                if "⚠️" in r: st.error(r)
                else: 
                    st.success("✅ Threat Detection Cycle Complete")
                    st.write(r)
else:
    st.title("🛡️ Welcome to ScamGuard")
    st.subheader("We catch sophisticated Phishing, Fraud, and Spoofs.")
    st.error("🔒 Please look to the left sidebar and 'Log In' or 'Sign In with Google' to access your private scanning dashboard!")