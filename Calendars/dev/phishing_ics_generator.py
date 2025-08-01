import os
import sys
import uuid
import argparse
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

EMAIL_TEMPLATE_FILE = "email_template.html"
ICS_TEMPLATE_FILE = "iCalendar_template.ics"


def load_template(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def generate_uid():
    return str(uuid.uuid4()).replace("-", "")


def format_attendees(emails):
    attendees = []
    for email in emails:
        attendees.append(
            f"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;"
            f"PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN={email};X-NUM-GUESTS=0:mailto:{email}"
        )
    return "\r\n".join(attendees)


def generate_ics(template, args, dtstart, dtend, dtstamp):
    uid = generate_uid()
    attendees_str = format_attendees(args.recipients.split(","))

    return template.format(
        DTSTART=dtstart,
        DTEND=dtend,
        DTSTAMP=dtstamp,
        UID=uid,
        ORGANIZER_NAME=args.sender_name,
        ORGANIZER_EMAIL=args.sender,
        SUMMARY=args.summary,
        DESCRIPTION=args.event_url,
        ATTENDEES=attendees_str
    )


def generate_email_html(template, args):
    return template.format(EVENT_TEXT=args.description, EVENT_URL=args.event_url)


def export_files(output_dir, html_content, ics_content):
    os.makedirs(output_dir, exist_ok=True)

    html_path = os.path.join(output_dir, "invite.html")
    ics_path = os.path.join(output_dir, "invite.ics")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(ics_path, "w", encoding="utf-8") as f:
        f.write(ics_content)

    print(f"[+] Exported HTML: {html_path}")
    print(f"[+] Exported ICS : {ics_path}")
    return html_path, ics_path


def send_email(args, html_body, ics_body):
    msg = MIMEMultipart('mixed')
    msg['From'] = args.sender
    msg['To'] = args.recipients
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = args.subject

    alt = MIMEMultipart('alternative')
    msg.attach(alt)

    alt.attach(MIMEText(html_body, "html"))
    alt.attach(MIMEText(ics_body, "calendar;method=REQUEST"))

    ics_attachment = MIMEBase('application/ics', ' ;name="invite.ics"')
    ics_attachment.set_payload(ics_body)
    encode_base64(ics_attachment)
    ics_attachment.add_header('Content-Disposition', 'attachment; filename="invite.ics"')
    msg.attach(ics_attachment)

    server = smtplib.SMTP(args.smtp, 25)
    server.sendmail(args.sender, args.recipients.split(","), msg.as_string())
    server.quit()
    print(f"[+] Email sent to: {args.recipients}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated ICS Phishing Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--smtp", help="SMTP server (only needed if --send-email)", required=False)
    parser.add_argument("--sender", help="Sender email address", required=True)
    parser.add_argument("--sender-name", help="Display name", default="HR Department")
    parser.add_argument("--recipients", help="Comma-separated recipient emails", required=True)
    parser.add_argument("--subject", help="Email subject", default="HR Policy Meeting Invitation")
    parser.add_argument("--summary", help="ICS meeting title", default="Company-Wide HR Policy Meeting")
    parser.add_argument("--description", help="HTML body text (meeting details)", default="""
Dear colleague,

We invite you to an important HR meeting regarding recent policy changes. Please find the agenda and join via the Teams link.

Regards,  
HR Department
    """)
    parser.add_argument("--event-url", help="Link to join the meeting", required=True)
    parser.add_argument("--output-dir", help="Directory to export ICS and HTML", default="./output")
    parser.add_argument("--send-email", action='store_true', help="Send email using SMTP")

    return parser.parse_args()


def main():
    args = parse_args()

    # Time setup
    now = datetime.datetime.utcnow()
    dtstamp = now.strftime("%Y%m%dT%H%M%SZ")
    dtstart = (now + datetime.timedelta(minutes=15)).strftime("%Y%m%dT%H%M%SZ")
    dtend = (now + datetime.timedelta(hours=1)).strftime("%Y%m%dT%H%M%SZ")

    # Load templates
    html_template = load_template(EMAIL_TEMPLATE_FILE)
    ics_template = load_template(ICS_TEMPLATE_FILE)

    # Generate final content
    email_html = generate_email_html(html_template, args)
    calendar_ics = generate_ics(ics_template, args, dtstart, dtend, dtstamp)

    # Export to disk
    export_files(args.output_dir, email_html, calendar_ics)

    # Optionally send
    if args.send_email:
        if not args.smtp:
            print("[-] Missing --smtp argument for sending email")
            sys.exit(1)
        send_email(args, email_html, calendar_ics)


if __name__ == "__main__":
    main()
