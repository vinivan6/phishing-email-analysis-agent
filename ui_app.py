import json
import requests
import streamlit as st
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

API_URL = "http://127.0.0.1:8000/analyze-email"

st.set_page_config(
    page_title="Phishing Email Analysis Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing Email Analysis Agent")
st.caption("Analyze suspicious emails using manual entry or by uploading an .eml email file.")


def get_verdict_color(verdict: str) -> str:
    verdict = (verdict or "").lower()
    if verdict == "phishing":
        return "#dc2626"  # red
    if verdict == "suspicious":
        return "#f59e0b"  # orange
    if verdict == "likely_safe":
        return "#16a34a"  # green
    return "#6b7280"      # gray


def get_confidence_color(verdict: str, confidence: str) -> str:
    verdict = (verdict or "").lower()
    confidence = (confidence or "").lower()

    if verdict == "phishing" and confidence == "high":
        return "#dc2626"  # red
    if verdict == "phishing":
        return "#f97316"  # orange-red
    if verdict == "suspicious":
        return "#f59e0b"  # orange
    if verdict == "likely_safe":
        return "#16a34a"  # green
    return "#6b7280"      # gray


def render_highlight_card(label: str, value: str, color: str):
    st.markdown(
        f"""
        <div style="
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid #e5e7eb;
            background-color: #f9fafb;
            margin-bottom: 8px;
        ">
            <div style="font-size: 0.9rem; color: #6b7280; font-weight: 600;">
                {label}
            </div>
            <div style="font-size: 1.4rem; font-weight: 800; color: {color};">
                {value}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def parse_attachments(raw_text: str) -> list[str]:
    if not raw_text.strip():
        return []
    return [item.strip() for item in raw_text.split(",") if item.strip()]


def extract_text_from_eml(file_bytes: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    from_header = msg.get("From", "")
    subject = msg.get("Subject", "")
    sender_name, sender_email = parseaddr(from_header)

    raw_headers = ""
    for key, value in msg.items():
        raw_headers += f"{key}: {value}\n"

    body_text = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get_content_disposition() or "").lower()
            content_type = str(part.get_content_type() or "").lower()
            filename = part.get_filename()

            if filename:
                attachments.append(filename)

            if content_disposition != "attachment" and content_type == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    pass

        if not body_text:
            for part in msg.walk():
                content_disposition = str(part.get_content_disposition() or "").lower()
                content_type = str(part.get_content_type() or "").lower()
                if content_disposition != "attachment" and content_type == "text/html":
                    try:
                        body_text = part.get_content()
                        break
                    except Exception:
                        pass
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = ""

    return {
        "sender": sender_email,
        "display_name": sender_name,
        "subject": subject,
        "body": body_text,
        "headers": raw_headers.strip(),
        "attachments": attachments
    }


def call_analysis_api(payload: dict) -> dict:
    response = requests.post(API_URL, json=payload, timeout=90)
    response.raise_for_status()
    return response.json()


def verdict_color(verdict: str) -> str:
    verdict = (verdict or "").lower()
    if verdict == "phishing":
        return "🚨"
    if verdict == "suspicious":
        return "⚠️"
    if verdict == "likely_safe":
        return "✅"
    return "ℹ️"


def render_badge(label: str, value: str):
    st.markdown(f"**{label}:** `{value}`")


def get_action_style(verdict: str) -> tuple[str, str, str]:
    verdict = (verdict or "").lower()

    if verdict == "phishing":
        return (
            "Immediate action required",
            "#7f1d1d",   # dark red background
            "#fecaca"    # light red text
        )
    if verdict == "suspicious":
        return (
            "Review with caution",
            "#78350f",   # dark amber background
            "#fde68a"    # light amber text
        )
    if verdict == "likely_safe":
        return (
            "Low risk",
            "#14532d",   # dark green background
            "#bbf7d0"    # light green text
        )

    return (
        "Review recommended",
        "#374151",      # dark gray background
        "#e5e7eb"       # light gray text
    )


def render_action_box(verdict: str, action_text: str):
    title, bg_color, text_color = get_action_style(verdict)

    st.markdown(
        f"""
        <div style="
            padding: 18px 20px;
            border-radius: 12px;
            background-color: {bg_color};
            border-left: 6px solid {text_color};
            margin-bottom: 12px;
        ">
            <div style="
                font-size: 0.95rem;
                font-weight: 700;
                color: {text_color};
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            ">
                {title}
            </div>
            <div style="
                font-size: 1.05rem;
                font-weight: 600;
                color: {text_color};
                line-height: 1.5;
            ">
                {action_text}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_results(data: dict):
    verdict = data.get("verdict", "unknown")
    confidence = data.get("confidence", "unknown")
    model_used = data.get("model_used", "unknown")
    semantic_category = data.get("semantic_category", "unknown")
    semantic_confidence = data.get("semantic_confidence", "unknown")

    st.divider()
    st.subheader(f"{verdict_color(verdict)} Analysis Result")

    col1, col2, col3 = st.columns(3)
    with col1:
        render_highlight_card("Verdict", verdict, get_verdict_color(verdict))
    with col2:
        render_highlight_card("Confidence", confidence, get_confidence_color(verdict, confidence))
    with col3:
        render_highlight_card("Model", model_used, "#2563eb")

    col4, col5 = st.columns(2)
    with col4:
        render_highlight_card("Semantic Category", semantic_category, "#7c3aed")
    with col5:
        render_highlight_card("Semantic Confidence", semantic_confidence, "#7c3aed")

    st.subheader("Recommended Action")
    render_action_box(
        verdict,
        data.get("recommended_action", "No recommendation available.")
    )

    left, right = st.columns([1.2, 1])

    with left:
        st.subheader("Reasons")
        reasons = data.get("reasons", [])
        if reasons:
            for item in reasons:
                st.write(f"- {item}")
        else:
            st.write("No reasons available.")

        st.subheader("Indicators")
        indicators = data.get("indicators", [])
        if indicators:
            st.write(", ".join(indicators))
        else:
            st.write("None")

    with right:
        st.subheader("Reputation Summary")
        summary = data.get("reputation_summary", {})
        st.json(summary)

    tab1, tab2, tab3, tab4 = st.tabs(
        ["Artifacts", "Reputation Details", "Raw Response", "LLM Notes"]
    )

    with tab1:
        st.json(data.get("artifacts", {}))

    with tab2:
        st.json(data.get("reputation", {}))

    with tab3:
        st.code(json.dumps(data, indent=2), language="json")

    with tab4:
        st.write(data.get("llm_notes", "No notes available."))


mode = st.radio(
    "Choose Input Mode",
    ["Manual Entry", "Upload .eml Email"],
    horizontal=True
)

if mode == "Manual Entry":
    with st.form("manual_email_analysis_form"):
        sender = st.text_input("Sender Email", value="service@paypal.com")
        display_name = st.text_input("Display Name", value="PayPal Notification")
        subject = st.text_input(
            "Subject",
            value="Pending deposit of USD 987.90 for account activation. Questions? Call-(888) 350-7916."
        )
        body = st.text_area(
            "Email Body",
            value=(
                "Hello, Ivan Mladenovic. FACIAL ACCENTS BY LEANNE CARTER, LLC sent you ₱0.12 PHP. "
                "Get instant access today in PayPal for free or transfer to a bank. "
                "Accept Money https://www.paypal.com/mobile-app/banking-bundle/enrol"
                "?source=payout_funds_in_moment&flow_intent=ACCEPT_MONEY&accept_money_amount=%24514.28 "
                "Money received"
            ),
            height=240
        )
        headers = st.text_area(
            "Raw Headers (optional)",
            value="From: service@paypal.com\nReply-To: service@paypal.com",
            height=120
        )
        attachments_input = st.text_input(
            "Attachments (comma-separated)",
            value=""
        )

        submitted = st.form_submit_button("Analyze Email")

    if submitted:
        payload = {
            "sender": sender,
            "display_name": display_name or "",
            "subject": subject.strip() if subject.strip() else "No subject",
            "body": body or "",
            "headers": headers or "",
            "attachments": parse_attachments(attachments_input)
        }

        try:
            data = call_analysis_api(payload)
            render_results(data)
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the FastAPI backend. Make sure Uvicorn is running on http://127.0.0.1:8000")
        except requests.exceptions.HTTPError as exc:
            st.error(f"API returned an error: {exc}")
        except Exception as exc:
            st.error(f"Unexpected error: {exc}")

else:
    uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

    if uploaded_file is not None:
        try:
            parsed_email = extract_text_from_eml(uploaded_file.read())

            st.subheader("Parsed Email Preview")
            col1, col2 = st.columns(2)
            with col1:
                render_badge("Sender", parsed_email.get("sender") or "N/A")
                render_badge("Display Name", parsed_email.get("display_name") or "N/A")
                render_badge("Subject", parsed_email.get("subject") or "N/A")
            with col2:
                attachments = parsed_email.get("attachments") or []
                render_badge("Attachments", ", ".join(attachments) if attachments else "None")

            with st.expander("Preview Body"):
                st.text(parsed_email.get("body", "")[:5000])

            with st.expander("Preview Headers"):
                st.text(parsed_email.get("headers", "")[:8000])

            if st.button("Analyze Uploaded Email"):
                payload = {
                    "sender": parsed_email.get("sender") or "unknown@example.com",
                    "display_name": parsed_email.get("display_name") or "",
                    "subject": parsed_email.get("subject").strip() if parsed_email.get("subject") and parsed_email.get("subject").strip() else "No subject",
                    "body": parsed_email.get("body") or "",
                    "headers": parsed_email.get("headers") or "",
                    "attachments": parsed_email.get("attachments") or []
                }

                with st.expander("Payload sent to API"):
                    st.json(payload)

                data = call_analysis_api(payload)
                render_results(data)

        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the FastAPI backend. Make sure Uvicorn is running on http://127.0.0.1:8000")
        except requests.exceptions.HTTPError as exc:
            st.error(f"API returned an error: {exc}")
        except Exception as exc:
            st.error(f"Failed to parse or analyze the uploaded email: {exc}")