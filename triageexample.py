import json

from mailsuite.utils import parse_email, from_trusted_domain
from yaramail import MailScanner


def beautify_report(report: dict):
    return json.dumps(report, indent=2)


def escalate_to_incident_response(reported_email: dict, priority: str):
    reported_email = beautify_report(reported_email)
    # TODO: Do something!
    pass


malicious_verdicts = ["social engineering", "credential harvesting",
                      "fraud", "malware"]

# Load list of trusted domains
with open("trusted-domains.txt") as trusted_domains_file:
    trusted_domains = trusted_domains_file.read().split("\n")

# Initialize the scanner
scanner = MailScanner(header_rules="header.yar",
                      body_rules="body.yar",
                      header_body_rules="header_body.yar",
                      attachment_rules="attachments.yar")


# TODO: Do something to fetch emails
emails = []

for email in emails:
    # TODO: Send user a "Thanks for sending a report" email
    verdict = None
    parsed_email = parse_email(email)
    trusted = from_trusted_domain(email, trusted_domains)
    parsed_email["from_trusted_domain"] = trusted
    matches = scanner.scan_email(email)
    parsed_email["yara_matches"] = matches
    # This assumes that every rule has a meta value named "category"
    categories = []
    for match in matches:
        if "category" in match["meta"]:
            categories.append(match["meta"]["category"])
    categories = list(set(categories))
    # Ignore matches in multiple categories
    if len(categories) == 1:
        verdict = categories[0]
    if trusted and verdict == "safe":
        verdict = "trusted"
    parsed_email["verdict"] = verdict
    if verdict == "trusted":
        # TODO: Let the user know the email is safe and close the ticket
        # TODO: Move the report to the trusted folder
        pass
    elif verdict == "junk":
        # TODO: Tell the user how to add an address to their spam filter
        # TODO: Close the ticket and move the report to the junk folder
        pass
    elif verdict in malicious_verdicts:
        # TODO: Instruct the user to delete the malicious email
        # TODO: Maybe do something different for each verdict?
        escalate_to_incident_response(parsed_email, "high")
    else:
        escalate_to_incident_response(parsed_email, "normal")
