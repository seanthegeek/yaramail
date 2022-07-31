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
[mailsuite.utils.parse_email()][parse_email] to `MailScanner.scan_email()`,
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
  from_domain = "example.com" // Optionally make a rule only apply to a specific email from domain 
  description = "All URLs point to the example.com domain"

/*
The strings section defines the patterns that can be used in the rule.
These can be strings, byte patterns, or even regular expressions!
*/

strings:
  // Match ASCII and wide strings and ignore the case
  $http = "http" ascii wide nocase
  $example_url = "https://example.com" ascii wide nocase

condition:
  /*
  The total number of URLs must match the number of example.com URls
  Require at least one URL for this rule, otherwise all email with no URLs
  would match*/

  #http > 0 and #http == #example
}
```

### Checking for impersonation

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

Most organizations add something to the beginning of an email subject or body
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
rule planet_express_vip_impersonation {
  meta:
      author = "Sean Whalen"
      date = "2022-07-14"
      category = "fraud"
      description = "Impersonation of key employees of Planet Express in an external email"

  /*
  /(Hubert|Hugh|Prof\\.?(essor)?) ((Hubert|Hugh) )?Farnsworth/

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

  /Phil(ip)? (J\\.? )?Fry/

  Philip Fry
  Philip J. Fry
  Philip J Fry
  Phil Fry
  Phil J. Fry
  Phil J Fry
  */

  strings:
      $external = "[EXT]" ascii wide nocase // Whatever warns users that an email came from an external source
      $vip_ceo = /(Hubert|Hugh|Prof\\.?(essor)?) ((Hubert|Hugh) )?Farnsworth/ ascii wide nocase
      $vip_cfo = "Hermes Conrad" ascii wide nocase
      $vip_cto = "Turanga Leela" ascii wide nocase
      $vip_admin = "Amy Wong" ascii wide nocase
      $svip_cdo = /Phil(ip)? (J\\.? )?Fry/ ascii wide nocase
      $except_slug = "Brain Slug Fundraiser" ascii wide

  condition:
      $external and any of ($vip_*) and not any of ($except_*)
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

### Checking attachment content

As demonstrated by the previous examples, YARA rules don't need
to be complex to be effective. The same is true for file/attachment rules.
Sometimes attackers will store malicious files inside ISO files, because the
content of ISO files are often not scanned by email security controls.
Although `yaramail` does not scan the contents of malicious ISO files, it can
be used to identify small ISO files.

Legitimate ISO files are large. They are disk images that are most commonly
used as bootable operating system installers that range from hundreds of
megabytes to several gigabytes in size. Malicious ISO files are much
smaller, because they only contain malware payloads.

File types can be identified by looking for a known sequence of bytes at a
particular location/offset in a file (usually at offset `0`, the very beginning
of a file). These file signatures are often called magic bytes or magic
numbers.

```{tip}
A helpful list of [file signatures][file signatures] can be found on Wikipedia.
``` 
ISO files contain the bytes `43 44 30 30 31` at offset `0`. This information
can be combined with the special YARA variable `fiilesize` to look for small
ISO files

```yara
rule small_iso {
  meta:
    author = "Sean Whalen"
    date = "2022-07-21"
    category = "malware"
    discription = "Small ISO file"

  strings:
    $iso = {43 44 30 30 31} // Magic bytes for ISO files

  condition:
    $iso at 0 and filesize < 100MB
}
```

```{tip}
These types of conditions can also help to make YARA more efficient when it is
being used as a filesystem scanner.
```

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

from publicsuffix2 import get_sld
from mailsuite.utils import parse_email, from_trusted_domain
from yaramail import MailScanner

logger = logging.getLogger("scanner")


def escalate_to_incident_response(reported_email: Dict, priority: str):
    m = f"Escalating {priority} priority email: {reported_email['subject']}"
    logger.info(m)
    # TODO: Do something!


malicious_verdicts = ["credential harvesting", "fraud", "malware"]

# Load list of trusted domains that require a safe YARA rule too
with open("trusted_domains_yara_required.txt") as trusted_domains_file:
    yara_required_trusted_domains = trusted_domains_file.read().split("\\n")

# Load list of trusted domains that *do not* require a safe YARA
with open("trusted_domains.txt") as trusted_domains_file:
    trusted_domains = trusted_domains_file.read().split("\\n")

# Initialize the scanner
scanner = None  # Avoid an IDE warning
try:
    scanner = MailScanner(header_rules="header.yar",
                          body_rules="body.yar",
                          header_body_rules="header_body.yar",
                          attachment_rules="attachment.yar")
except Exception as e:
    logger.error(f"Error parsing YARA rules: {e}")
    exit(-1)

# TODO: Do something to fetch emails
emails = []

for email in emails:
    # TODO: Send user a "Thanks for sending a report" email
    verdict = None
    parsed_email = parse_email(email)
    trusted_domain = from_trusted_domain(email, trusted_domains)
    trusted_domain_yara_safe_required = from_trusted_domain(
        email,
        yara_required_trusted_domains)
    matches = scanner.scan_email(email)
    parsed_email["yara_matches"] = matches
    skip_auth_check = False
    categories = []
    for match in matches:
        if "from_domain" in match["meta"]:
            sld = parsed_email["from"]["sld"]
            if sld != get_sld(match["meta"]["from_domain"]):
                continue
        if "skip_auth_check" in match["meta"] and not skip_auth_check:
            skip_auth_check = match["meta"]["skip_auth_check"]
        if "category" in match["meta"]:
            categories.append(match["meta"]["category"])
    categories = list(set(categories))
    # Ignore matches in multiple categories
    if len(categories) == 1:
        verdict = categories[0]
    authenticated = any([trusted_domain, trusted_domain_yara_safe_required,
                         skip_auth_check])
    if verdict == "safe" and not authenticated:
        verdict = "yara_safe_auth_fail"
    if verdict != "safe" and trusted_domain_yara_safe_required:
        verdict = "auth_pass_not_yara_safe"
    if verdict is None and authenticated:
        verdict = "safe"
    parsed_email["verdict"] = verdict
    if verdict == "safe":
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
[file signatures]: https://en.wikipedia.org/wiki/List_of_file_signatures
[filesize]: https://yara.readthedocs.io/en/stable/writingrules.html#file-size
