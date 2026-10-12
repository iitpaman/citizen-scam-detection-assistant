import html
import re

import streamlit as st

import auth
from detector import analyze_message, get_matched_words
from link_checker import analyze_links

st.set_page_config(
    page_title="Scam Detection Assistant",
    layout="wide",
    initial_sidebar_state="auto",
)

auth.init_db()

# =====================================================================
# Look and feel
#   Idea: the verdict is a rubber stamp pressed on the message slip.
#   Colours come from an Indian office desk: stamp-pad blue ink, red
#   FRAUD stamp, turmeric highlighter, neem green, ledger-paper grey.
# =====================================================================

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@500;700;800;900&family=Hanken+Grotesk:wght@400;500;600;700&family=Special+Elite&display=swap');

:root {
    --ink: #E8EAF0;
    --muted: #9AA1B5;
    --pad: #2F3AA8;
    --paper: #14161C;
    --panel: #1C1F2A;
    --sheet: #F1EEE3;
    --slipink: #1E2233;
    --line: #2E3342;
    --red: #E0524A;
    --turmeric: #E7B13C;
    --neem: #4CB37A;
    --stamp-red: #B3261E;
    --stamp-amber: #A8650A;
    --stamp-green: #2E7D4F;
    --display: 'Archivo', 'Helvetica Neue', Arial, sans-serif;
    --body: 'Hanken Grotesk', 'Segoe UI', Arial, sans-serif;
    --type: 'Special Elite', 'Courier New', monospace;
}

#MainMenu, footer {visibility: hidden;}
.stApp {background: var(--paper); color: var(--ink); font-family: var(--body);}
.block-container {padding-top: 2.4rem; max-width: 1040px;}
.stApp, .stApp p, .stApp label, .stApp button, .stApp input, .stApp textarea {font-family: var(--body);}
[data-testid="stHeaderActionElements"], .action h4 a {display: none !important;}

/* Sidebar */
[data-testid="stSidebar"] {background: #0F1116; border-right: 1px solid var(--line);}

/* Buttons: square-ish, no floating hover */
.stButton > button, .stFormSubmitButton > button {
    border-radius: 4px; font-weight: 700; padding: .6rem 1.4rem;
    letter-spacing: .01em; box-shadow: none; transition: background .15s ease;
}
.stButton > button:focus-visible, .stFormSubmitButton > button:focus-visible,
input:focus-visible, textarea:focus-visible {outline: 3px solid var(--turmeric) !important; outline-offset: 2px;}

/* Inputs */
div[data-baseweb="input"], div[data-baseweb="textarea"], div[data-baseweb="base-input"] {border-radius: 4px !important;}
div[data-baseweb="input"], div[data-baseweb="textarea"], [data-testid="stTextInputRootElement"], [data-testid="stTextAreaRootElement"] {border: 1.5px solid #3A4054 !important; background: var(--panel) !important; border-radius: 4px !important;}
div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea {background: var(--panel) !important; color: var(--ink) !important;}
textarea {font-family: var(--type) !important; font-size: 1.02rem !important; line-height: 1.6 !important;}

/* Tabs */
button[role="tab"] {font-family: var(--display); font-weight: 700; font-size: 1rem;}

/* Headings */
.masthead {margin: 0 0 1.6rem 0;}
.masthead h1 {
    font-family: var(--display); font-weight: 900; font-size: clamp(1.8rem, 4.2vw, 2.9rem);
    line-height: 1.02; letter-spacing: -.02em; margin: 0 0 .5rem 0; color: var(--ink);
}
.masthead p {margin: 0; color: var(--muted); font-size: 1.05rem; max-width: 52ch;}
.sec {font-family: var(--display); font-weight: 800; font-size: 1.15rem; margin: 2rem 0 .7rem 0; color: var(--ink);}

/* Sign-in panel */
.brandpanel {
    background: var(--pad); color: #F4F5FF; border-radius: 6px; padding: 2rem 1.8rem;
    min-height: 430px; margin-bottom: 2rem; display: flex; flex-direction: column; justify-content: space-between;
    background-image: radial-gradient(circle at 1px 1px, rgba(255,255,255,.10) 1px, transparent 0);
    background-size: 14px 14px;
}
.brandpanel h2 {
    font-family: var(--display); font-weight: 900; font-size: 2.5rem; line-height: 1;
    letter-spacing: -.02em; margin: 0 0 1rem 0; color: #fff;
}
.brandpanel p {color: #D6D9F7; font-size: 1.02rem; line-height: 1.55; margin: 0; max-width: 34ch;}
.brandpanel .help {border-top: 1px dashed rgba(255,255,255,.4); padding-top: 1rem; margin-top: 2rem;}
.brandpanel .help b {font-family: var(--display); font-size: 2.2rem; color: var(--turmeric); display: block; line-height: 1;}
.brandpanel .help span {color: #D6D9F7; font-size: .95rem;}

/* Message slip + stamp */
.slip {
    position: relative; background: var(--sheet); border: 1.5px solid var(--sheet);
    border-left: 6px dotted var(--slipink); border-radius: 3px; padding: 4.4rem 1.5rem 1.4rem 1.5rem;
}
.slip-label {
    position: absolute; top: 1rem; left: 1.5rem; color: #5B6275; font-size: .9rem; font-weight: 600;
}
.slip-body {font-family: var(--type); font-size: 1.08rem; line-height: 1.75; word-break: break-word; color: var(--slipink);}
.slip-body mark {background: linear-gradient(transparent 52%, var(--turmeric) 52%); color: inherit; padding: 0 .1em;}

.stamp {
    position: absolute; top: .8rem; right: 1.1rem; display: inline-block;
    font-family: var(--display); font-weight: 900; font-size: 1.55rem; letter-spacing: .09em;
    text-transform: uppercase; padding: .15rem .9rem; border: 6px double currentColor; border-radius: 6px;
    transform: rotate(-5deg); opacity: .93; mix-blend-mode: multiply; filter: url(#rough);
    animation: thud .28s cubic-bezier(.2,.9,.3,1.2) both;
}
.tone-high .stamp {color: var(--stamp-red);}
.tone-mid  .stamp {color: var(--stamp-amber);}
.tone-low  .stamp {color: var(--stamp-green);}
@keyframes thud {
    from {transform: rotate(-5deg) scale(1.7); opacity: 0;}
    to   {transform: rotate(-5deg) scale(1);   opacity: .93;}
}
@media (prefers-reduced-motion: reduce) {.stamp {animation: none;}}

.verdict {font-family: var(--display); font-weight: 800; font-size: 1.4rem; padding-top: 1.1rem;}

/* Probability ruler */
.gauge {margin-top: 1.2rem;}
.gauge-top {display: flex; align-items: baseline; gap: .8rem; flex-wrap: wrap;}
.gauge-num {font-family: var(--display); font-weight: 900; font-size: 2.6rem; line-height: 1;}
.gauge-cap {color: var(--muted); font-size: .95rem;}
.ruler {
    position: relative; height: 22px; margin-top: .6rem; border: 1.5px solid var(--muted); border-radius: 2px; background-color: var(--panel);
    background-image: repeating-linear-gradient(90deg, var(--muted) 0 1px, transparent 1px 10%);
    background-size: 100% 35%; background-repeat: no-repeat; background-position: 0 100%;
}
.ruler .fill {position: absolute; inset: 0 auto 0 0; opacity: .88;}
.tone-high .fill {background: var(--red);}
.tone-mid  .fill {background: var(--turmeric);}
.tone-low  .fill {background: var(--neem);}

/* Reason rows */
.row {border-left: 4px solid var(--line); padding: .15rem 0 .15rem .9rem; margin: .55rem 0; font-size: 1.02rem;}
.tone-high .row, .row.high {border-left-color: var(--red);}
.row.mid {border-left-color: var(--turmeric);}
.row.low {border-left-color: var(--neem);}
.row small {display: block; color: var(--muted); font-size: .92rem; margin-top: .15rem;}
.row .dom {font-family: var(--type); font-size: .98rem; word-break: break-all;}
.tag {display: inline-block; font-size: .78rem; font-weight: 700; padding: .08rem .55rem; border-radius: 2px; margin-right: .5rem; vertical-align: middle;}
.tag.high {background: var(--red); color: #14161C;}
.tag.mid {background: var(--turmeric); color: #14161C;}
.tag.low {background: var(--neem); color: #14161C;}
.note {color: var(--muted); font-size: .9rem; margin-top: .6rem;}

/* What to do panel */
.action {background: var(--pad); color: #F4F5FF; border-radius: 6px; padding: 1.4rem 1.6rem; margin: 2rem 0 1.5rem 0;}
.action h4 {font-family: var(--display); font-weight: 800; font-size: 1.15rem; margin: 0 0 .6rem 0; color: #fff;}
.action ul {margin: 0; padding-left: 1.1rem; line-height: 1.7;}
.action a {color: var(--turmeric);}
.action .big {font-family: var(--display); font-weight: 900; font-size: 2rem; color: var(--turmeric);}

/* History ledger */
.ledger {display: grid; grid-template-columns: 7.5rem 1fr; gap: .2rem 1rem; padding: .85rem 0; border-bottom: 1px solid var(--line);}
.ledger .when {color: var(--muted); font-size: .85rem;}
.ledger .msg {font-family: var(--type); font-size: .98rem; word-break: break-word;}
@media (max-width: 640px) {.ledger {grid-template-columns: 1fr;}}

/* Sidebar badge and stats */
.badge {display: flex; align-items: center; gap: .75rem; padding-bottom: 1rem; border-bottom: 1px dashed #3A4054; margin-bottom: 1rem;}
.badge .ini {
    width: 42px; height: 42px; background: var(--pad); color: #fff; display: flex; align-items: center;
    justify-content: center; font-family: var(--display); font-weight: 900; font-size: 1.3rem; border-radius: 3px;
}
.badge .nm {font-weight: 700; line-height: 1.1;}
.badge .ml {color: var(--muted); font-size: .78rem; overflow-wrap: anywhere;}
.stat {margin-bottom: 1rem;}
.stat b {font-family: var(--display); font-weight: 900; font-size: 2.3rem; line-height: 1; display: block;}
.stat span {color: var(--muted); font-size: .9rem;}
</style>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <filter id="rough"><feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" result="n"/>
  <feDisplacementMap in="SourceGraphic" in2="n" scale="1.6"/></filter>
</svg>
"""

st.markdown(CSS, unsafe_allow_html=True)

# =====================================================================
# Session state and labels
# =====================================================================

st.session_state.setdefault("user", None)
st.session_state.setdefault("last_result", None)
st.session_state.setdefault("message_input", "")

# risk -> (tone, sentence)
RISK_STYLE = {
    "High Risk": ("high", "This message looks very dangerous."),
    "Suspicious": ("mid", "Be careful - several warning signs found."),
    "Likely Safe": ("low", "No strong scam signs found."),
    "Safe": ("low", "No strong scam signs found."),
}
TONE_OF_LINK = {"High Risk": "high", "Suspicious": "mid", "Safe": "low"}
LINK_TEXT = {"High Risk": "High risk", "Suspicious": "Suspicious", "Safe": "Looks safe"}

FLAG_LABELS = {
    "urgency": "Creates false urgency",
    "credential_request": "Asks for OTP/PIN/password/Aadhaar",
    "suspicious_link": "Contains a suspicious link/click instruction",
    "money_lure": "Promises money, prizes, or lottery winnings",
    "payment_pressure": "Pressures you to pay a fee immediately",
    "dangerous_link": "Contains a high-risk link (see the link check below)",
}


def esc(text):
    return html.escape(str(text))


def put(markup):
    """Render HTML. Newlines are removed so Markdown never turns it into a code block."""
    st.markdown(" ".join(markup.split("\n")), unsafe_allow_html=True)


# =====================================================================
# Sign in / register
# =====================================================================

def render_auth():
    left, right = st.columns([5, 6], gap="large")

    with left:
        put(
            '<div class="brandpanel"><div>'
            "<h2>Check before you tap.</h2>"
            "<p>Paste an SMS, WhatsApp or email message. We read the wording and "
            "every link in it, then tell you what to do next.</p></div>"
            '<div class="help"><b>1930</b>'
            "<span>Already paid or shared an OTP? Call the cyber crime helpline right away.</span></div></div>"
        )

    with right:
        login_tab, register_tab = st.tabs(["Log in", "Create account"])

        with login_tab:
            with st.form("login_form"):
                identifier = st.text_input("Username or email", placeholder="e.g. aman_singh")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Log in", type="primary", use_container_width=True)
            if submitted:
                user = auth.login_user(identifier, password)
                if user:
                    st.session_state.user = user
                    st.session_state.last_result = None
                    st.rerun()
                else:
                    st.error("Incorrect username/email or password. Check both and try again.")

        with register_tab:
            with st.form("register_form"):
                username = st.text_input("Username", placeholder="3-20 letters, numbers, _ or .")
                email = st.text_input("Email", placeholder="you@example.com")
                col1, col2 = st.columns(2)
                password = col1.text_input("Password", type="password", help="At least 8 characters")
                confirm = col2.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)
            if submitted:
                ok, msg = auth.register_user(username, email, password, confirm)
                if ok:
                    st.success(msg + " Open the **Log in** tab to continue.")
                else:
                    st.error(msg)

        st.caption("Passwords are stored as salted hashes, never as plain text.")


# =====================================================================
# Analysis
# =====================================================================

def slip_html(text, matched_words):
    """Escape the message, then mark flagged words with a highlighter."""
    safe = esc(text.strip()).replace("\n", "<br>")
    words = sorted({esc(w) for w in matched_words}, key=len, reverse=True)
    if words:
        pattern = re.compile(
            r"(?<![A-Za-z0-9])(" + "|".join(re.escape(w) for w in words) + r")(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        safe = pattern.sub(r"<mark>\1</mark>", safe)
    return safe


def run_analysis():
    """Button callback: runs before the page re-renders, so sidebar stats stay fresh."""
    message = st.session_state.message_input
    if not message.strip():
        st.session_state.last_result = {"error": "Paste a message first, then press Check message."}
        return

    risk, flags, confidence = analyze_message(message)
    matched_words = get_matched_words(message)
    link_results, link_risk = analyze_links(message)

    # A high-risk link raises the final result by one level
    if link_risk == "High Risk":
        if risk in ("Safe", "Likely Safe"):
            risk = "Suspicious"
        elif risk == "Suspicious":
            risk = "High Risk"
        flags = list(flags) + ["dangerous_link"]

    auth.save_scan(st.session_state.user["id"], message, risk, confidence)

    st.session_state.last_result = {
        "message": message,
        "risk": risk,
        "flags": flags,
        "confidence": confidence,
        "matched_words": matched_words,
        "link_results": link_results,
    }


def render_result(res):
    if "error" in res:
        st.warning(res["error"])
        return

    risk = res["risk"]
    tone, sentence = RISK_STYLE.get(risk, RISK_STYLE["Suspicious"])
    pct = min(max(res["confidence"], 0), 1) * 100

    put(
        f'<div class="tone-{tone}">'
        f'<div class="slip"><span class="slip-label">Message you pasted</span>'
        f'<div class="stamp">{esc(risk)}</div>'
        f'<div class="slip-body">{slip_html(res["message"], res["matched_words"])}</div></div>'
        f'<div class="verdict">{esc(sentence)}</div>'
        f'<div class="gauge"><div class="gauge-top"><span class="gauge-num">{pct:.0f}%</span>'
        f'<span class="gauge-cap">chance this is a scam, according to the ML model</span></div>'
        f'<div class="ruler" role="img" aria-label="Scam probability {pct:.0f} percent">'
        f'<div class="fill" style="width:{pct:.0f}%"></div></div></div></div>'
    )

    put('<h3 class="sec">Why we flagged it</h3>')
    if res["flags"]:
        rows = "".join(
            f'<div class="row {tone}">{esc(FLAG_LABELS.get(f, f))}</div>' for f in res["flags"]
        )
        put(f'<div class="tone-{tone}">{rows}</div>')
    else:
        put('<div class="row low">No rule-based red flags found in the wording.</div>')

    put('<h3 class="sec">Links in this message</h3>')
    if not res["link_results"]:
        put('<div class="note">No links found.</div>')
    else:
        rows = ""
        for r in res["link_results"]:
            t = TONE_OF_LINK.get(r["risk"], "mid")
            reasons = "".join(f"<small>{esc(x)}</small>" for x in r["reasons"])
            rows += (
                f'<div class="row {t}"><span class="tag {t}">{LINK_TEXT.get(r["risk"], r["risk"])}</span>'
                f'<span class="dom">{esc(r["url"])}</span>{reasons}</div>'
            )
        put(rows + '<div class="note">Links are never opened. Only their name and structure are checked.</div>')

    if risk in ("High Risk", "Suspicious"):
        put(
            '<div class="action"><h4>What to do now</h4><ul>'
            "<li>Do not click any link or share an OTP, PIN or password.</li>"
            "<li>Contact the bank or company on its official number, not the one in the message.</li>"
            "<li>Report it at <a href='https://cybercrime.gov.in'>cybercrime.gov.in</a>.</li>"
            "</ul><p style='margin:.9rem 0 0 0'>Already lost money? Call "
            "<span class='big'>1930</span></p></div>"
        )


def render_analyze_tab():
    st.markdown("Paste any suspicious SMS, WhatsApp or email message below.")

    st.text_area(
        "Message",
        key="message_input",
        height=150,
        placeholder="e.g. Aapka account block ho jayega, turant OTP share karein...",
        label_visibility="collapsed",
    )
    st.button("Check message", type="primary", on_click=run_analysis, use_container_width=True)

    if st.session_state.last_result:
        st.write("")
        render_result(st.session_state.last_result)


# =====================================================================
# History
# =====================================================================

def render_history_tab():
    history = auth.get_history(st.session_state.user["id"])
    if not history:
        st.info("No checks yet. Check a message and it will be listed here.")
        return

    rows = ""
    for item in history:
        tone, _ = RISK_STYLE.get(item["risk"], RISK_STYLE["Suspicious"])
        preview = item["message"].strip().replace("\n", " ")
        if len(preview) > 140:
            preview = preview[:140] + "..."
        rows += (
            f'<div class="ledger"><div><span class="tag {tone}">{esc(item["risk"])}</span></div>'
            f'<div class="msg">{esc(preview)}</div>'
            f'<div class="when">{item["confidence"] * 100:.0f}% scam</div>'
            f'<div class="when">{esc(item["created_at"])} UTC</div></div>'
        )
    put(rows)

    st.write("")
    if st.button("Clear my history"):
        auth.clear_history(st.session_state.user["id"])
        st.rerun()


# =====================================================================
# Main app
# =====================================================================

def render_sidebar():
    user = st.session_state.user
    stats = auth.get_stats(user["id"])
    with st.sidebar:
        put(
            f'<div class="badge"><div class="ini">{esc(user["username"][0].upper())}</div>'
            f'<div><div class="nm">{esc(user["username"])}</div>'
            f'<div class="ml">{esc(user["email"])}</div></div></div>'
            f'<div class="stat"><b>{stats["total"]}</b><span>messages checked</span></div>'
            f'<div class="stat"><b>{stats["risky"]}</b><span>flagged as risky</span></div>'
        )
        if st.button("Log out", use_container_width=True):
            st.session_state.user = None
            st.session_state.last_result = None
            st.session_state.message_input = ""
            st.rerun()


def render_app():
    render_sidebar()
    put(
        '<div class="masthead"><h1>Is this message a scam?</h1>'
        f'<p>Welcome back, {esc(st.session_state.user["username"])}. '
        "Paste it below and we will check the wording and every link.</p></div>"
    )
    analyze_tab, history_tab = st.tabs(["Check a message", "History"])
    with analyze_tab:
        render_analyze_tab()
    with history_tab:
        render_history_tab()


if st.session_state.user is None:
    put(
        '<div class="masthead"><h1>Citizen Scam Detection Assistant</h1>'
        "<p>Check suspicious SMS, WhatsApp and email messages before you act on them.</p></div>"
    )
    render_auth()
else:
    render_app()

st.caption("Designed for a Safer Digital India | AI-Powered Cyber Fraud Awareness & Prevention..")