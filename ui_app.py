import json
import requests
import streamlit as st
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

API_URL = "http://127.0.0.1:8000/analyze-email"

st.set_page_config(page_title="Phishing Email Analysis Agent", layout="wide")
st.title("Phishing Email Analysis Agent")
st.write("Analyze suspicious emails using manual entry or by uploading an .eml email file.")


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
    response = requests.post(API_URL, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()


def render_results(data: dict):
    st.subheader("Analysis Result")

    col1, col2, col3 = st.columns(3)
    col1.metric("Verdict", data.get("verdict", "N/A"))
    col2.metric("Confidence", data.get("confidence", "N/A"))
    col3.metric("Model", data.get("model_used", "N/A"))

    st.subheader("Recommended Action")
    st.warning(data.get("recommended_action", "No recommendation available."))

    st.subheader("Reasons")
    for item in data.get("reasons", []):
        st.write(f"- {item}")

    st.subheader("Indicators")
    indicators = data.get("indicators", [])
    st.write(", ".join(indicators) if indicators else "None")

    st.subheader("Artifacts")
    st.json(data.get("artifacts", {}))

    st.subheader("Reputation Summary")
    st.json(data.get("reputation_summary", {}))

    st.subheader("Reputation Details")
    st.json(data.get("reputation", {}))

    with st.expander("Full Raw Response"):
        st.code(json.dumps(data, indent=2), language="json")


mode = st.radio("Choose Input Mode", ["Manual Entry", "Upload .eml Email"], horizontal=True)

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
            height=220
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
            "display_name": display_name or None,
            "subject": subject,
            "body": body,
            "headers": headers or None,
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
            st.write(f"**Sender:** {parsed_email['sender'] or 'N/A'}")
            st.write(f"**Display Name:** {parsed_email['display_name'] or 'N/A'}")
            st.write(f"**Subject:** {parsed_email['subject'] or 'N/A'}")
            st.write(f"**Attachments:** {', '.join(parsed_email['attachments']) if parsed_email['attachments'] else 'None'}")

            with st.expander("Preview Body"):
                st.text(parsed_email["body"][:5000] if parsed_email["body"] else "")

            with st.expander("Preview Headers"):
                st.text(parsed_email["headers"][:8000] if parsed_email["headers"] else "")

            if st.button("Analyze Uploaded Email"):
                payload = {
                    "sender": parsed_email.get("sender") or "unknown@example.com",
                    "display_name": parsed_email.get("display_name") or "",
                    "subject": parsed_email.get("subject") or "",
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