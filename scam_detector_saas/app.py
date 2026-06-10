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

# Setup page layout
st.set_page_config(page_title="ScamGuard | Scam Detector", page_icon="🛡️", layout="wide")

# ================= DELETE WATERMARKS & STYLE THE UI ================= #
st.markdown("""
    <style>
    /* Aggressively hide the bottom-right 'Hosted by Streamlit' watermark & header icons */
    .viewerBadge_container { display: none !important; }
    [data-testid="stDecoration"] { display: none !important; }
    [data-testid="stToolbar"] { display: none !important; }
    footer { visibility: hidden !important; }
    
    /* Make standard Streamlit buttons blue */
    div.stButton > button:first-child {
        background-color: #2e66ff; color: white; border-radius: 6px; border: none; font-weight: bold; width: 100%; padding: 0.5rem;
    }
    div.stButton > button:first-child:hover {
        background-color: #1a4dcf; color: white; border: none;
    }
    
    /* Style the custom Google Button to look authentic */
    .google-button {
        display: block; width: 100%; padding: 12px; background-color: #ffffff; color: #444444; 
        text-align: center; text-decoration: none; font-weight: bold; font-size: 15px; 
        border-radius: 5px; border: 1px solid #d2d2d2; box-shadow: 0px 2px 4px rgba(0,0,0,0.1); 
        margin-bottom: 20px; transition: 0.2s;
    }
    .google-button:hover {
        background-color: #f8f9fa; color: black; border-color: #bbbbbb; text-decoration: none;
    }
    </style>
""", unsafe_allow_html=True)

# ================= SECRETS & APIs ================= #
API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
STRIPE_KEY = st.secrets.get("STRIPE_API_KEY", "")
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "")

# ⚠️ ENSURE THIS EXACTLY MATCHES YOUR AUTHORIZED URI IN GOOGLE CLOUD
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
    """Checks your real Stripe account if this email pays the monthly fee"""
    if user_email == "admin@scamguard.com": return True 
    if not STRIPE_KEY: return False 
    try:
        customers = stripe.Customer.search(query=f"email:'{user_email}'")
        if not customers.data: return False
        subs = stripe.Subscription.list(customer=customers.data[0].id, status="active")
        return len(subs.data) > 0
    except Exception:
        return False

# ================= GOOGLE AUTHENTICATION ================= #
def get_google_auth_url():
    if not GOOGLE_CLIENT_ID: return "#"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
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
    except Exception:
        return None

# ================= SESSION MEMORY (REMAIN LOGGED IN) ================= #
cookie_manager = stx.CookieManager(key="auth_cookies")
expire_date = datetime.datetime.now() + datetime.timedelta(days=3650) # Keeps logged in for 10 years

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

# Auto-login if cookie is found
saved_user = cookie_manager.get(cookie="sg_email_token")
if saved_user and not st.session_state["logged_in"]:
    st.session_state["logged_in"] = True
    st.session_state["user_email"] = saved_user
    st.session_state["is_premium"] = check_premium_status(saved_user)

# Intercept Google login when someone returns from the pop-up tab
if not st.session_state.get("logged_in") and st.query_params.get("code"):
    user_email = verify_google_code(st.query_params.get("code"))
    if user_email:
        st.session_state["logged_in"] = True
        st.session_state["user_email"] = user_email
        st.session_state["is_premium"] = check_premium_status(user_email)
        # Force browser memory
        cookie_manager.set("sg_email_token", user_email, expires_at=expire_date)
        time.sleep(1)
        st.query_params.clear() 
        st.rerun()
    else:
        st.error("Google authentication failed. Please try standard login.")
        st.query_params.clear()

# ================= FRONT-END VISUAL LOGIN ================= #
if not st.session_state.get("logged_in"):
    
    st.title("🛡️ Welcome to ScamGuard")
    st.write("We catch phishing links, fake invoices, and gift-card scams in seconds.")
    st.write("")
    
    col1, empty, col2 = st.columns([1.5, 0.5, 2.5])
    
    with col1:
        st.subheader("Login or Sign Up")
        
        # Google Button Fix: Using target="_blank" pops open a new tab seamlessly so it never breaks.
        if GOOGLE_CLIENT_ID:
            g_url = get_google_auth_url()
            html_g_btn = f'''
            <a href="{g_url}" target="_blank" class="google-button">
                <span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#34A853">g</span><span style="color:#4285F4">l</span><span style="color:#EA4335">e</span> Sign In
            </a>
            '''
            st.markdown(html_g_btn, unsafe_allow_html=True)
            st.markdown("<p style='text-align:center;'>Or use your email:</p>", unsafe_allow_html=True)

        auth_mode = st.radio("Choose Action:", ["Log In", "Create Free Account"], horizontal=True)
        email = st.text_input("Email").lower().strip()
        password = st.text_input("Password", type='password')
        remember_me = st.checkbox("Keep me logged in", value=True)
        
        if auth_mode == "Create Free Account":
            if st.button("Sign Up Now"):
                if email and password:
                    try:
                        add_user(email, hash_pswd(password))
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = email
                        st.session_state["is_premium"] = check_premium_status(email)
                        if remember_me: cookie_manager.set("sg_email_token", email, expires_at=expire_date)
                        time.sleep(1) 
                        st.rerun()
                    except sqlite3.IntegrityError: st.error("Email is already registered! Please switch to 'Log In'.")
                else: st.warning("Please enter email and password.")
                    
        elif auth_mode == "Log In":
            if st.button("Log In"):
                if login_user(email, hash_pswd(password)):
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["is_premium"] = check_premium_status(email)
                    if remember_me: cookie_manager.set("sg_email_token", email, expires_at=expire_date)
                    time.sleep(1)
                    st.rerun()
                else: st.error("Incorrect Email or Password.")

    with col2:
        st.info("💡 **Why use ScamGuard?** \n\nEvery day, thousands fall for advanced spoofed emails. Simply create an account, paste in an email you aren't sure about, and let our Artificial Intelligence analyze the links, words, and sender instantly for free.")

else:
    # ---------------- INSIDE THE DASHBOARD ----------------
    with st.sidebar:
        st.success(f"Logged in as:\n**{st.session_state['user_email']}**")
        
        if st.session_state["is_premium"]:
            st.info("💎 Status: Premium Active")
            st.write("You have access to PDF File Scanning and malicious link extraction.")
        else:
            st.warning("👤 Status: Free Account")
            # ⚠️ ADD YOUR REAL STRIPE URL ON THE LINE BELOW THIS!
            st.link_button("💳 Upgrade to Premium ($4.99/mo)", "https://buy.stripe.com/8x2aEYaOsbkSb4h9re9bO00", use_container_width=True)
            st.caption("Use this exact email at checkout to instantly upgrade.")
            
        st.divider()
        if st.button("Log Out"):
            try:
                cookie_manager.delete("sg_email_token")
            except Exception: pass
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
            st.session_state["is_premium"] = False
            time.sleep(1) # Silent sleep handles clean cookie logout
            st.rerun()

    def analyze_threat(text, is_premium):
        prem = "\nPlease provide deep link checking and search for URL hiding attempts." if is_premium else ""
        prompt = f"Analyze if this email is a scam. Score the risk 0 to 100%. Explain the warning signs clearly.{prem}\nText:\n{text}"
        # Cycles through multiple free AI's so it never charges you money
        fallbacks = ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-pro-exp-02-05:free"]
        
        for n in fallbacks:
            try:
                resp = client.chat.completions.create(model=n, max_tokens=800, messages=[{"role":"system","content":"You are a helpful Security Analyst AI."},{"role":"user","content":prompt}])
                return resp.choices[0].message.content
            except Exception:
                time.sleep(0.5)
                continue
        return "⚠️ All free AI servers are currently busy processing other people's emails! Please click scan again."

    st.title("🛡️ Email Scam Scanner")
    st.write("Paste the text from an email below to verify if it is safe.")

    txt = st.text_area("📋 Paste Email or Text message here:", height=200, placeholder="Example: Hey, it's the CEO, I need you to go buy me Google Play gift cards...")

    if st.session_state["is_premium"]:
        st.subheader("Premium Uploads")
        file = st.file_uploader("Attach PDF invoice or File to scan:", type=['txt', 'pdf'])
        if file:
            try:
                if file.name.endswith('.pdf'):
                    pdf = PyPDF2.PdfReader(file)
                    txt += " \n\n" + " ".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                else: txt += " \n\n" + file.getvalue().decode("utf-8")
                st.info("File successfully scanned into the text box above.")
            except Exception: st.error("Failed to read this document.")

    st.write("")
    if st.button("🔍 Scan Email Now", use_container_width=True):
        if not txt.strip():
            st.warning("Please paste some text into the box first!")
        else:
            if st.session_state["is_premium"]:
                found = re.findall(r'(https?://[^\s]+)', txt)
                if found:
                    st.error(f"🛑 Found {len(found)} hidden website links in that text:")
                    for u in found: st.write(u)

            with st.spinner("AI is thinking..."):
                result = analyze_threat(txt, st.session_state["is_premium"])
                if "⚠️" in result: st.error(result)
                else: 
                    st.success("✅ Scan Completed.")
                    st.write(result)
