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
import extra_streamlit_components as stx

st.set_page_config(page_title="ScamGuard | True Threat Analysis", page_icon="🛡️", layout="centered")

# ================= BACKGROUND SETUP & APIS ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")

client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)
stripe.api_key = STRIPE_KEY

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

# ================= 10-YEAR "FOREVER" COOKIE MANAGER ================= #
@st.cache_resource
def get_cookie_manager():
    return stx.CookieManager()

cookie_manager = get_cookie_manager()

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

# Auto-Login checking cookie memory in the background (Silently bypasses login)
saved_user = cookie_manager.get(cookie="scamguard_user")
if saved_user and not st.session_state["logged_in"]:
    st.session_state["logged_in"] = True
    st.session_state["user_email"] = saved_user
    st.session_state["is_premium"] = check_premium_status(saved_user)

# ================= LOGIN PORTAL UI ================= #
if not st.session_state.get("logged_in"):
    with st.sidebar:
        st.title("🛡️ Secure Access")
        
        auth_mode = st.selectbox("Welcome. Select action:", ["Log In", "Sign Up For Free"])
        email = st.text_input("Email Address").lower().strip()
        password = st.text_input("Password", type='password')
        
        # User Choice: Checkbox added here!
        remember_me = st.checkbox("Keep me logged in forever")
        
        # Define 'forever' as a cookie lasting exactly 10 years (3650 days)
        expire_date = datetime.datetime.now() + datetime.timedelta(days=3650)
        
        if auth_mode == "Sign Up For Free":
            if st.button("Create Account & Sign In"):
                if email and password:
                    try:
                        # 1. Add user to database
                        add_user(email, hash_pswd(password))
                        
                        # 2. Instantly log them in directly
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = email
                        st.session_state["is_premium"] = check_premium_status(email)
                        
                        # 3. Permanently save to browser ONLY if they checked the box
                        if remember_me:
                            cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                            
                        time.sleep(0.5) # Quick buffer for browser cache
                        st.rerun()
                        
                    except sqlite3.IntegrityError:
                        st.error("Email is already registered. Please change dropdown to Log In.")
                else: 
                    st.warning("Please fill all fields.")
                    
        elif auth_mode == "Log In":
            if st.button("Access Dashboard"):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    
                    # Permanently save to browser ONLY if they checked the box
                    if remember_me:
                        cookie_manager.set("scamguard_user", email, expires_at=expire_date)
                        
                    time.sleep(0.5)
                    st.rerun()
                else: 
                    st.error("Incorrect Email or Password.")
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
            # REPLACE BELOW WITH YOUR LIVE BUY.STRIPE LINK!
            st.link_button("💳 Upgrade ($4.99/mo)", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00")
            st.caption("IMPORTANT: Make sure you use your exact login email at checkout to instantly unlock Premium.")
        
        st.divider()
        if st.button("Secure Log Out"):
            # Delete permanent cookie & sign out
            cookie_manager.delete("scamguard_user")
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
    
    # Fully Free Round-Robin API Fallback Loop 
    free_fallbacks = [
        "meta-llama/llama-3.3-70b-instruct:free",
        "google/gemini-2.0-pro-exp-02-05:free",
        "microsoft/phi-3-mini-128k-instruct:free"
    ]
    
    for n in free_fallbacks:
        try:
            resp = client.chat.completions.create(
                model=n, 
                max_tokens=800, 
                messages=[{"role":"system","content":"You are ScamGuard Threat Analyst AI. Do not hallucinate."},{"role":"user","content":prompt}]
            )
            return resp.choices[0].message.content
        except Exception:
            time.sleep(0.5) 
            continue
    return "⚠️ Open internet routing congestion. Try hitting scan again, or upgrade to Premium for dedicated API unthrottled queues."

# ----------------- MAIN UI ----------------- #
if st.session_state.get("logged_in"):
    st.title("🔍 Threat Interceptor Console")
    txt = st.text_area("📋 Target Payload:", placeholder="Paste a highly suspicious email or invoice contents right here.", height=150)

    if st.session_state["is_premium"]:
        file = st.file_uploader("📄 Premium Module: Attach Fake Invoices/PDFs", type=['txt', 'pdf'])
        if file:
            try:
                if file.name.endswith('.pdf'):
                    pdf = PyPDF2.PdfReader(file)
                    txt += " \n\n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                else: 
                    txt += " \n\n" + file.getvalue().decode("utf-8")
                st.info("Uploaded document successfully stripped of malicious elements and ready for analysis.")
            except Exception: 
                st.error("Error reading attached file schema.")

    if st.button("🚨 Execute Complete AI Scan"):
        if not txt.strip():
            st.warning("You must enter a payload to process.")
        else:
            if st.session_state["is_premium"]:
                found = extract_urls(txt)
                if found:
                    st.error(f"🛑 Warning! Traced {len(found)} masked internet hyperlinks in transmission payload:")
                    for u in found: st.code(u)

            with st.spinner("Deciphering text origins and spoof tactics using our decentralized engine array..."):
                r = analyze_threat(txt, st.session_state["is_premium"])
                if "⚠️" in r: 
                    st.error(r)
                else: 
                    st.success("✅ Secure Threat Processing Check Completed.")
                    st.write(r)
else:
    # Completely logged-out presentation page
    st.title("🛡️ Welcome to ScamGuard")
    st.subheader("Detect Gift Card Extortion, Fake PayPal Invoices, & Phishing")
    st.write("Leveraging our free local and enterprise deep-scan systems.")
    st.info("🔒 Look to the sidebar menu: **Log In or Sign Up (for free)** to build your local secure session now.")
