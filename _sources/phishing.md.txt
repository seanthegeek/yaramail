# Automating phishing report inbox triage

Through a combination authentication header parsing and YARA rules,
[mailsuite][mailsuite] and `yaramail` can be used to create customized 
automation for triaging phishing reports from users. `mailsuite` is installed
as a dependency of `yaramail`.

## Getting started

It is **strongly recommended** to develop, store, and maintain YARA rules,
trusted domain lists, and sample emails in a private Git repository
(GitHub is great!), for a number of reasons.

- Version control tracks who made what change when, with easy rollback
- Automations can (and should) pull a fresh copy of the repository
  before scanning
- CI/CD workflows can run tests against a collection of emails samples before
  allowing the rules into production

When automating phishing inbox triage, it is **vital** to continually build
and maintain a collection of real-world malicious, safe, and junk emails
that have been sent to the inbox. That way new samples can be tested against
existing automation, and changes in automation can be checked for effectiveness
against new samples and regressions with existing samples.

Production material should be kept in the `master` branch. Any development
should be done in a rule developer's fork of the repository. New samples for
testing must always be added when adjusting for new content. Each commit should
trigger automated testing of the changes. Whe the rule  developer is ready to
submit their changes for review, they create a Pull Request, and a project
maintainer reviews the proposed  changes before squashing and merging commits
into the upstream `master` branch.

```{tip}
Use the [include][include] directive in the YARA rule files that you pass to
`MailScanner` to include rules from other files. That way, rules can be
divided into separate files as you see fit.
```

The `MailScanner` class in the [`yaramail` API][API] provides a YARA scanner 
that is specifically designed for emails.

To scan an email, pass the output from 
[`mailsuite.utils.parse_email()`][parse_email] to `MailScanner.scan_email()`, 
Take a look at the [API documentation][API] to learn about the returned value.

## Practical examples

### Checking if an email is trusted

Use the [from_trusted_domain()][trusted] function in 
[mailsuite.utils][mailsuite.utils] to check the results of DKIM and/or DMARC
in the `Authentication-Results` header against a list of trusted domains.

```{warning}
Authentication results are not verified by this function, so only use it on
emails that have been received by trusted mail servers, and not on
third-party emails.
```

The `Authentication-Results` header is added by the receiving mail server
as a way of logging the results of authentication checks that prove that
the domain in the message `From` header was not spoofed. Most email services
— including Microsoft 365 and Gmail — use a single `Authentication-Results`
header to log the results of all authentication checks. By default,
[from_trusted_domain()][trusted] will return `False` if multiple
`Authentication-Results` headers are found in an email. This is done to
avoid false positives when an attacker adds their own
`Authentication-Results` header to an email before it reaches the destination
mail server.

Postfix mail servers use a separate `Authentication-Results` header for each
authentication check. If your mail service does this, set the
`allow_multiple_authentication_results` parameter to `True`.
This allows multiple headers, but will return `False` if multiple DMARC
results are found, to avoid malicious results.

```{warning}
Set `allow_multiple_authentication_results` to `True` **if and only if**
the receiving mail service splits the results of each authentication method
in separate `Authentication-Results` headers **and always** includes DMARC
results.
```

```{warning}
Set `use_authentication_results_original` to `True`
**if and only if** you use an email security gateway that adds an
`Authentication-Results-Original` header, such as Proofpoint or Cisco
IronPort. This **does not** include API-based email security solutions,
such as Abnormal Security.
```

For stronger security, check the content of emails in addition to checking
authentication results. This adds another layer of defense when phishing emails
are sent by a trusted sender. [YARA rules][rules] provide a flexable method of
checking the contents of email headers, body, and attachment content against
known malicious and trusted patterns.

For example, the following YARA body rule could be used to ensure that all URLs
in an email body match the domain of a vendor.

```yara
rule all_urls_example_vendor : urls {

// YARA rules can include C-style comments like this one

/*
The " : urls" after the rule name sets an optional namespace
that can be useful for organizing rules.
The default namespace is "default".

The meta section contains arbitrary key-value pairs that are
included in matches. That way the scanner has more context about
the meaning of the rule.
*/

meta:
  author = "Sean Whalen"
  date = "2022-07-13"
  category = "safe"
  description = "All URLs are for the example.com domain"

/*
The strings section defines the patterns that can be used in the rule.
These can be strings, byte patterns, or even regular expressions!
*/

strings:
  // Match ASCII and wide strings and ignore the case
  $http = "http" ascii wide nocase
  $example_url = "https://example.com" ascii wide nocase

condition:
  // The total number of URLs must match the number of example.com URls
  #http == #example
}
```

### Checking if an email is malicious

Impersonating a top executive is a classic social engineering technique. Even
if a target organisation has fully implemented DMARC to prevent domain
spoofing, people can still be impersonated in the display name of the
message `From` header, or in the email body. A YARA rule can check for this.
[Regular Expressions][regex] (regex) are handy, because one string can match a
wide variety of name variations.

```{tip}
Use a local copy of [CyberChef][CyberChef] to quickly and privately test
regular expressions.
```

Most organisations add something to the beginning of an email subject or body
to let the user know that the email came from an external, untrusted source.
This can be leveraged in a YARA rule to identify external emails that include
the name of an executive or board member in the email headers or body. You can
also add patterns to make exceptions to the rule. This is useful for dealing
with false positives. An exemption to a malicious rule **does not** mean that
the content is safe — it only means that the rule cannot be used for that
content.

```{tip}
If an external email tag is not in use, an alternative approach is using the
previously mentioned `from_trusted_domain()` function in Python when an
analyzing an email.
```

```yara
rule exec_impersonation {
  meta:
      author = "Sean Whalen"
      date = "2022-07-14"
      category = "social engineering"
      description = "Impersonation of key employees of Planet Express in an external email"

  /*
  /(Hubert|Hugh|Prof\.?(lessor)?) ((Hubert|Hugh) )?Farnsworth/

  Hubert Farnsworth
  Hugh Farnsworth
  Professor Farnsworth
  Prof. Farnsworth
  Prof Farnsworth
  Professor Hubert Farnsworth
  Professor Hugh Farnsworth
  Prof. Hubert Farnsworth
  Prof Hubert Farnsworth
  Prof. Hugh Farnsworth
  Prof Hugh Farnsworth

  /Phil(ip)? (J\.? )?Fry/

  Philip Fry
  Philip J. Fry
  Philip J Fry
  Phil Fry
  Phil J. Fry
  Phil J Fry
  */

  strings:
      $external = "[EXT]" ascii wide nocase
      $s1 = /(Hubert|Hugh|Prof\.?(lessor)?) ((Hubert|Hugh) )?Farnsworth/ ascii wide nocase
      $s2 = "Hermes Conrad" ascii wide nocase
      $s3 = "Turanga Leela" ascii wide nocase
      $s4 = "Amy Wong" ascii wide nocase
      $s5 = /Phil(ip)? (J\.? )?Fry/
      $except_slug = "Brain Slug Fundraiser" ascii wide

  condition:
      $external and any of ($s*) and not any of ($except_*)
}
```

```{tip}
Full names (often including middle initials) of executives at
publicly-traded US companies can be found in SEC filings, which are
[publicly searchable][EDGAR] on EDGAR.
```

Rules in the `header_body` ruleset are checked against combined email header
and email body content. A rule like the one above should be added to the
 `header_body` ruleset. That way it can identify impersonation in the `From`
header display name and/or the email body.

This was a very simple, practical example. YARA was developed to identify and
classify malware, so it is capable of much more complex pattern matching.
That the time to read over YARA's documentation and other resources.

### Checking if an email is junk

Users will often send marketing (i.e., junk) mail to a phishing report inbox,
which can be a significant contributor to alert fatigue for those who are
triaging the inbox. YARA rules can help reduce this noise.

Start by looking through junk emails that have been reported. Make note of
words or phrases that are common across different marketing campaigns,
businesses, and industries. Some common examples include:

- discount
- trial
- coupon
- webinar
- subscribe
- ROI
- development
- offer
- price
- cost

Also include a list of words and phrases common to junk email campaigns
targeted to your specific industry.

Then, use condition statements and boolean logic similar to the previous
examples to count the total number of marketing terms/buzzwords/phrases, the
number of URLs, and any exception strings. The boolean logic can be as complex
as needed. For example, you could set a threshold of matches that must occur,
and potentially lower that threshold if a count of URLs meets another
threshold — because bulk marketing emails tend to have at least several
links, and maybe even a tracking image.

Finding the right combination of strings and condition logic may take some
time, but the reduction in alert fatigue is well worth the effort.

### Putting it all together

Here's a complete example of triage code.

```python
import logging
from typing import Dict

from mailsuite.utils import parse_email, from_trusted_domain
from yaramail import MailScanner

logger = logging.getLogger("scanner")


def escalate_to_incident_response(reported_email: Dict, priority: str):
  logger.info(f"Escalating {priority} email: {reported_email['subject']}")
  # TODO: Do something!
  pass

malicious_verdicts = ["social engineering", "credential harvesting",
                      "fraud", "malware"]

# Load list of trusted domains
with open("trusted-domains.txt") as trusted_domains_file:
  trusted_domains = trusted_domains_file.read().split("\n")

# Initialize the scanner
try:
  scanner = MailScanner(header_rules="header.yar",
                        body_rules="body.yar",
                        header_body_rules="header_body.yar",
                        attachment_rules="attachment.yar")
except Exception as e:
  logger.error(f"Error parsing YARA rules: {e}")
  scanner = None
  exit(-1)

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

```

[mailsuite]: https://seanthegeek.github.io/mailsuite/
[rules]: https://yara.readthedocs.io/en/stable/writingrules.html
[include]: https://yara.readthedocs.io/en/stable/writingrules.html#including-files
[API]: index.md#api
[regex]: https://yara.readthedocs.io/en/stable/writingrules.html#regular-expressions
[trusted]: https://seanthegeek.github.io/mailsuite/api.html#mailsuite.utils.from_trusted_domain
[mailsuite.utils]: https://seanthegeek.github.io/mailsuite/api.html#mailsuite.utils.from_trusted_domain
[parse_email]: https://seanthegeek.github.io/mailsuite/api.html#mailsuite.utils.parse_email
[CyberChef]: https://github.com/gchq/CyberChef/releases
[EDGAR]: https://www.sec.gov/edgar/searchedgar/companysearch.html
