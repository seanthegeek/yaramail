# Tutorial

`yaramail` provides a workflow for automated triage of phishing reports.

## Best practices

it is **strongly recommended** to create a private Git repository as a place
to develop, store, and maintain  YARA rules, trusted domain lists, and sample
emails, for a number of reasons.

- Version control tracks who made what change when, with easy rollback
- Automation can (and should) pull a fresh copy of the repository
  before scanning
- CI/CD workflows can [run tests](#testing-a-collection-of-samples)
  against a collection of emails samples before allowing the rules into
  production

When automating phishing inbox triage, it is **vital** to continually [build
and maintain a collection](collecting_samples) of real-world malicious, safe,
and junk emails that have been sent to the inbox. That way, new samples can be
tested against existing automation processes, and changes in automation can be
checked for regressions with existing samples.

Production material should be kept in the `main` branch. Any development
should be done in a rule developer's fork of the repository. New samples for
testing must always be added when adjusting for new content. Each commit should
trigger automated testing of the changes. When the rule developer is ready to
submit their changes for review, they create a Pull Request, and a project
maintainer reviews the proposed changes before squashing and merging commits
into the upstream `main` branch.

It is recommended to use [Visual Studio Code][vscode] as a YARA rule
editor, with the following extensions installed:

- [Email][email-extension]
- [GitLens][gitlens-extension]
- [Python][python-extension]
- [Remote Development][remote-development-extension]
- [YARA][yara-extension]

:::{note}
If you use Visual Studio Code on Windows Subsystem for Linux (WSL) or remote
host, Visual Studio Code Extensions must be installed in Visual Studio Code for
Windows, and installed again in the WSL distribution or remote host once a new
WSL or remote host window is open.
:::

## Getting started

Follow the [installation guide](installation).

Import `MailScanner` from `yaramail`, and create a new
[`MailScanner` object](api)

```python
import logging

from yaramail import MailScanner

logger = logging.getLogger("scanner")
logging.basicConfig(level=logging.INFO)

# Initialize the scanner
scanner = None  # Avoid an IDE warning
try:
  scanner = MailScanner(
    header_rules="header.yar",
    body_rules="body.yar",
    header_body_rules="header_body.yar",
    attachment_rules="attachment.yar",
    implicit_safe_domains="implicit_safe_domains.txt")
except Exception as e:
  logger.error(f"Could not initialize the scanner: {e}")
  exit(-1)
```

To scan an email, pass email content, a file-like object, or a file path to
`MailScanner.scan_email()`. Take a look at the [API documentation](api) to
learn about the returned objects.

## Methodology

The `yaramail` module contains a `MailScanner` class. When `MailScanner` scans
an email, it attempts to use a combination of email authentication results and
YARA rule matches to categorize an email and reach a `verdict`. To do this, it
does several things.

First, the `Authentication-Results` header of the email is parsed. The
`Authentication-Results` header is added by the receiving mail server as a way
of logging the results of authentication checks that prove that the domain
in the message `From` header was not spoofed. Most email services — including
Microsoft 365, and Gmail — use a single `Authentication-Results` header
to log the results of all authentication checks. By default,
all `Authentication-Results` headers will be ignored if multiple
`Authentication-Results` headers are found in an email. This is done to avoid
false positives when an attacker adds their own `Authentication-Results`
header to an email before it reaches the destination mail server.

Postfix mail servers use a separate `Authentication-Results` header for each
authentication check. If your mail service does this, set the
`allow_multiple_authentication_results` parameter to `True`.
This allows multiple headers, but all `Authentication-Results` headers will
be ignored if multiple DMARC results are found, to avoid spoofed results.

:::{warning}
`Authentication-Results` are not verified by `yaramail`. This is by design.
Most receiving organizations modify the message subject and/or body prior to
delivery to warn users that an email came from an external source. As a
result, DKIM signatures are not valid after delivery to end user mailboxes.
Only use `yaramail` on emails that have been received by trusted mail
servers, and not on emails received by third parties.
:::

:::{warning}
Set `allow_multiple_authentication_results` to `True` **if and only if**
the receiving mail service splits the results of each authentication method
in separate `Authentication-Results` headers **and always** includes DMARC
results.
:::

:::{warning}
Set `use_authentication_results_original` to `True`
**if and only if** you use an email security gateway that adds an
`Authentication-Results-Original` header, such as Proofpoint or Cisco
IronPort. This **does not** include API-based email security solutions,
such as Abnormal Security.
:::

:::{tip}
Read [Demystifying DMARC][DMARC] for more details about SPF, DKIM, and DMARC.
:::

Then, the message header, body, and attachment content is scanned with
user-provided [YARA rules][yara_rules] that provide a flexible method of
checking content against known malicious and trusted patterns.

### Deduplication

The purpose of `yaramail` is to identify known safe, known malicious, and
likely junk email samples in phishing reporting inboxes. It will not catch
everything. For proper automation, It is important to implement some form of
deduplication for emails for reported emails that have been manually triaged.
Consider using fuzzy matching approaches such as [ssdeep][ssdeep], or use
machine learning capabilities included in many Security Orchestration Automation
and Response (SOAR) platforms.

## Anatomy of a YARA rule

YARA rules consist of three sections: `meta`, `strings`, and `condition`.

:::{tip}
For better organization of rules, use the [include directive][yara_include] to
include content from other rule files.
:::

### meta

The [meta section][yara_meta] specifies arbitrary metadata key-value
pairs of metadata that can be useful to humans and/or the scanner application.
`yaramail` uses a few specific `meta` keys.

The `meta` section of each matching rule is checked
for an optional `category` key. Each match category is added to a
deduplicated list of `categories`, if the additional criteria specified in
the rule's `meta` section is met.

If a single category is in the list of `categories`, the `verdict` is set to
that category. If multiple categories are listed, the verdict is set to
`ambiguous`. If no categories are listed, the verdict is set to `None`.

:::{note}
In extremely rare cases, a trusted domain may send a wide variety of automated
emails that do not fit into patterns, making YARA rules impractical.
To account for this, a domain can be added to the `implicit_safe_domains`
list, which will add a `category` of `safe` to every email from that
domain, as long as the domain is authenticated. The emails will still be
scanned by YARA, so any YARA category matches other than `safe` will still
return an `ambiguous` verdict.

**Only do this as a last resort**, because implicitly trusting all emails from
a domain would cause a malicious email to be categorized as `safe`.
:::

#### auth_optional

Do not require domain authentication for the rule's category to apply.

:::{note}
This only applies when `from_domain` is set.
:::

:::{important}
Only set the `auth_optional` key to `true` if the sender is known to not
properly DKIM sign their email.
:::

:::{warning}
Emails without proper authentication may have a spoofed message `From`
domain, so take extra care to write YARA rules matching known safe content as
detailed and narrow as possible.
:::

#### authentication_optional

Alias of `auth_optional`.

#### category

The `category` of the rule. This can be any string, but the value `safe` is
special. Rules without a `category` key are considered informational, and do
not contribute to the `verdict`.

#### from_domain

:::{important}
This key **must** be set for rules with a category of `safe`.
:::

If this key is set, the rule’s `category` only applies to emails when the
message `From` domain that matches this value exactly. Multiple domains can be
specified in this value by separating them with spaces.

Domain authentication must pass, unless that rule has an `auth_optional` meta
key with the value set to `true`.

#### from_domains

Alias of `from_domain`.

#### no_attachment

If this key is `true`, the rule’s `category` only applies to emails with no
attachments.

#### no_attachments

Alias of `no_attachment`.

### strings

The [strings section][yara_strings] specifies strings to match.

- [Text strings][yara_text_strings] are surrounded by `"`
- [Hexadecimal strings][yara_hex_strings] are surrounded by `{}`
- [Regular expressions][yara_regex] are surrounded by `/`

[String modifiers][yara_string_modifiers] set case sensitivity, full word match
only, and more.

### condition

The [condition section][yara_condition] consists of a Boolean expression that
describes when the rule should match.

## Practical YARA rule examples

Here are some of the ways YARA can be put to good use.

### Checking if an email is safe

The following YARA body rule could be used to ensure that all URLs
in an email body match the domain of a vendor.

```yara
rule all_urls_example_vendor : urls {
    // YARA rules can include C-style comments like this one

    /*
    The " : urls" after the rule name sets an optional namespace
    that can be useful for organizing rules.
    The default namespace is "default".
    */

    meta:
        author = "Sean Whalen"
        date = "2022-07-13"
        category = "safe"
        from_domain = "example.com" // Only applies to emails from example.com
        description = "All URLs point to the example.com domain"
    strings:
        $url = "://" ascii wide nocase
        $example_url = "https://example.com" ascii wide nocase
    condition:
        /*
        Require at least one URL for this rule, otherwise all emails with no
        URLs would match.

        The total number of URLs must match the number of example.com URls.
        */

        $url and #url == #example_url
}
```

### Informational rules

To add additional context without affecting categorization or verdicts, write
a rule without including a `category` value in the `meta` section. Any matches
will still appear in the returned `matches`.

```yara
rule short_url {
    meta:
        author = "Sean Whalen"
        date = "2022-08-04"
        description = "Contains a short URL"
    strings:
        $s = /https?:\/\/[\w.]{3,12}\/\w{5,14}[\s|"|)|#|>]/ ascii wide nocase
    condition:
        any of them
}
```

### Checking for impersonation

Impersonating a top executive is a classic social engineering technique. Even
if a target organization has fully implemented DMARC to prevent domain
spoofing, people can still be impersonated in the display name of the
message `From` header, or in the email body. A YARA rule can check for this.
[regular expressions][yara_regex] (regex) are handy, because one string can
match a wide range of name variations.

:::{tip}
Use a local copy of [CyberChef][CyberChef] to quickly and privately test
regular expressions.
:::

Most organizations add something to the beginning of an email subject or body
to let the user know that the email came from an external, untrusted source.
This can be leveraged in a YARA rule to identify external emails that include
the name of an executive or board member in the email headers or body. You can
also add patterns to make exceptions to the rule. This is useful for dealing
with false positives. An exemption to a malicious rule **does not** mean that
the content is safe — it only means that the rule cannot be used for that
content.

```yara
rule planet_express_vip_impersonation {
    meta:
        author = "Sean Whalen"
        date = "2022-07-14"
        category = "fraud"
        description = "Impersonation of key employees of Planet Express"
    strings:
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
        $external = "[EXT]" ascii wide nocase // External email warning
        $vip_ceo = /(Hubert|Hugh|Prof\\.?(essor)?) ((Hubert|Hugh) )?Farnsworth/ ascii wide nocase
        $vip_cfo = "Hermes Conrad" ascii wide nocase
        $vip_cto = "Turanga Leela" ascii wide nocase
        $vip_admin = "Amy Wong" ascii wide nocase
        $vip_cdo = /Phil(ip)? (J\\.? )?Fry/ ascii wide nocase
        $except_slug = "Brain Slug Fundraiser" ascii wide
    condition:
        $external and any of ($vip_*) and not any of ($except_*)
}
```

:::{tip}
Full names (often including middle initials) of executives at
publicly-traded US companies can be found in SEC filings, which are
[publicly searchable][EDGAR] on EDGAR.
:::

Rules in the `header_body` ruleset are checked against combined email header
and email body content. A rule like the one above should be added to the
`header_body` ruleset. That way it can identify impersonation in the `From`
header display name and/or the email body.

This was a very simple, practical example. YARA was developed to identify and
classify malware, so it is capable of much more complex pattern matching.
Take the time to read over YARA's documentation and other resources.

### Checking attachment content

As demonstrated by the previous examples, YARA rules don't need
to be complex to be effective. The same is true for file/attachment rules.

File types can be identified by looking for a known sequence of bytes at a
particular location/offset in a file (usually at offset `0`, the very beginning
of a file). These file signatures are often called magic bytes or magic
numbers. YARA rules can use these file signatures to target specific file
types.

:::{tip}
A helpful list of [file type signatures][file signatures] can be found on
Wikipedia. The [Library of Congress][LOC] maintains extensive descriptions of
many different file types.
:::

#### Small ISO files

Sometimes attackers will store malicious files inside ISO files, because the
content of ISO files are often not scanned by email security controls.
Although `yaramail` does not scan the contents of malicious ISO files, it can
be used to identify small ISO files.

Legitimate ISO files are large. They are disk images that are most commonly
used as bootable operating system installers that range from hundreds of
megabytes to several gigabytes in size. Malicious ISO files are much
smaller, because they only contain malware payloads.

ISO files contain the bytes `43 44 30 30 31` (which is `CD001` in ASCII) at
offsets `0x8001`, `0x8801`, or `0x9001`. This information can be combined with
the special YARA variable [filesize] to look for small ISO files.

```yara
rule small_iso {
    meta:
        author = "Sean Whalen"
        date = "2022-07-21"
        category = "malware"
        description = "A small ISO file"
    strings:
        $iso = {43 44 30 30 31} // CD001
    condition:
        ($iso at 8001 or $iso at 8801 or $iso at 9001)
        and filesize < 200MB
}
```

:::{tip}
These types of conditions can also help to make YARA more efficient when it is
being used as a filesystem scanner.
:::

#### Credential harvesting PDFs

Attackers will sometimes create phishing lures and links inside an attached
PDF file instead of the email body. If attackers are not careful about their
Operational Security (OPSEC) when creating PDFs, file metadata will be
embedded into the document, including an `author` field. Even if this field
value is not a real name, it can still be used as a weak method of attribution
if it is used in multiple PDFs in a campaign.

:::{tip}
[exiftool][exiftool] can show metadata for a wide variety of file
types, including PDFs.
:::

The YARA rule below identifies PDFs created by `The Robot Devil` that contain
at least one clickable link.

```yara
rule robot_devil_pdf {
    meta:
        author = "Sean Whalen"
        date = "2022-08-09"
        category = "credential-harvesting"
        description = "Robot Devil credential harvesting PDF"
    strings:
        $pdf = {25 50 44 46 2D} // %PDF-
        $s_author = "Author(The Robot Devil)" ascii wide
        $s_uri = /URI\(.+\)/
    condition:
        $pdf at 0 and all of ($s_*)
}
```

:::{note}
Although `/URI(` as a text string could have been used to check for clickable
links, using a regular expression is better in this situation, because it will
show full URLs in the list of matches.
:::

### Real world example: Workday

Workday is a SaaS platform for HR management that is used by many large
enterprises. Emails from Workday are very consistent.

Every Workday notification email

- Has the message `From` domain `myworkday.com`
- Is DKIM signed by a key at the domain `myworkday.com`
- The organization's logo as a remote image
- Contains at least one link, and all links start with
  `https://www.myworkday.com/`
- Contains the string "Powered by Workday: A New Day, A Better Way."

Because of this, `myworkday.com` can be added to the
`trusted_domains_yara_safe_required_list`, and a `body` YARA rule can be used
to verify that the emails contain the expected content, with no unexpected
links or attachments.

```yara
rule workday {
    meta:
        author = "Sean Whalen"
        date = "2022-09-06"
        category = "safe"
        from_domain = "myworkday.com"
        no_attachments = true
    strings:
        $footer = "Powered by Workday: A New Day, A Better Way." ascii wide
        $url = /https?\:\/\// ascii wide nocase
        $redacted_url = /https?\:\/\/(www\.)?REDACTED.com\// ascii wide nocase
        $workday_url = "https://www.myworkday.com/REDACTED/" ascii wide nocase
    condition:
        all of them and #url == (#redacted_url + #workday_url)
}
```

### Checking if an email is junk

Users will often send marketing (i.e., junk) mail to a phishing report inbox,
which can be a significant contributor to alert fatigue for those who are
doing inbox triage. YARA rules can help reduce this noise.

Start by looking through junk emails that have been reported. Make note of
words or phrases that are common across different marketing campaigns,
businesses, and industries. For example:

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

:::{tip}
Use a separate junk/marketing rule for each language spoken by your users.
:::

## Using the CLI

<script id="asciicast-529801" src="https://asciinema.org/a/529801.js" async></script>

the [`yaramail` CLI](cli) has built-in support for scanning  individual
samples, or an entire collection of samples.

Use the `--rules`option to specify a path to a directory where the following
files can be found:

- `header.yar` - Rules that apply to email header content
- `body.yar` - Rules that apply to email body content
- `header_body.yar` - Rules that apply to header and/or body content
- `attachment.yar` - Rules that apply to email attachment content
- `passwords.txt` - A list of passwords to try on password-protected attachments
- `implicit_safe_domains.txt` - a list of message From domains that return
  a safe verdict if the domain is authenticated and no
  YARA categories match other than safe

:::{note}
The expected names of these files can be changed using command-line arguments.
:::

:::{note}
If any of these files are missing or blank, the CLI will issue a warning, but
the scanner will still run using the data it does have.
:::

:::{note}
Starting in version 1.2.0, the contents of the message body will always be
tried as ZIP passwords, along with `infected` and `malware`.
:::

### Scanning an individual sample

To scan an individual sample, pass a path to the sample to `yaramail`.
The scan results will be printed to the terminal's standard output.

:::{tip}
To scan standard input (stdin) use `-` as the path to scan.
:::

### Scanning multiple samples

The `yaramail CLI` accepts wildcards (i.e., `*`) in the scan path to scan
multiple files at once. This is useful for seeing what samples have in common.

### Testing a collection of samples

To test `verdict` values across an entire collection of email samples, use the
`-t/--test` option, and pass in a path to a directory of samples that are
sorted into subdirectories by expected verdict.

`yaramail` will output the test results as JSON, and use the number of test
failures as the return code. This is designed for developer use, and for CI/CD
testing pipelines.

To see more details about the emails that failed, including headers, body
content, URLs, and attachment names, add the `-v/--verbose` option.

## Automating phishing report triage

Here's a complete example of triage code.

```python
import logging
from typing import Dict

from mailsuite.utils import parse_email
from yaramail import MailScanner

logger = logging.getLogger("scanner")
logging.basicConfig(level=logging.INFO)


def escalate_to_incident_response(_report_email: Dict,
                                  priority: str = "normal"):
  m = f"Escalating {priority} priority email"
  logger.debug(m)
  # TODO: Do something!


malicious_categories = ["credential-harvesting", "fraud", "malware"]
malicious_categories = set(malicious_categories)

# Initialize the scanner
scanner = None  # Avoid an IDE warning
try:
  scanner = MailScanner(
    header_rules="header.yar",
    body_rules="body.yar",
    header_body_rules="header_body.yar",
    attachment_rules="attachment.yar",
    implicit_safe_domains="implicit_safe_domains.txt")
except Exception as e:
  logger.error(f"Could not initialize the scanner: {e}")
  exit(-1)


def scan_email(email_sample):
  email_sample["yaramail"] = scanner.scan_email(email_sample)
  return email_sample


# TODO: Do something to fetch emails
emails = []

for email in emails:
  attached_email = None
  report_email = parse_email(email)
  report_email["valid_report"] = True
  if report_email["automatic_reply"]:
    # TODO: Move automatic replies to the trash
    continue
  for attachment in report_email["attachments"]:
    if attachment["filename"].lower().endswith(".eml"):
      if attached_email:
        # TODO: Tell the user to only send one attached email
        report_email["valid_report"] = False
        escalate_to_incident_response(report_email)
        # TODO: Move report email to the invalid folder or trash
        attachment = None
        break
      attached_email = attachment
  if attached_email is None and report_email["valid_report"]:
    report_email["valid_report"] = False
    # TODO: Tell use user how to properly send a sample as an attachment
    escalate_to_incident_response(report_email)
    # TODO: Move report email to the invalid folder or trash
    continue
  try:
    sample = scan_email(attached_email["payload"])
    #TODO: Do something to deduplicate manually triaged emails
  except Exception as _e:
    logger.warning(f"Invalid email sample: {_e}")
    report_email["valid_report"] = False
    escalate_to_incident_response(report_email)
    # TODO: Move report email to the invalid folder or trash
    continue

  report_email["sample"] = sample

  is_malicious = bool(len(list(
    malicious_categories.intersection(sample["yaramail"]["categories"]))))

  if is_malicious:
    # TODO: Instruct the user to delete the malicious email
    # TODO: Move report email to the malicious folder or trash
    # TODO: Maybe do something different for each verdict?
    escalate_to_incident_response(report_email, "high")
  elif sample["yaramail"]["verdict"] == "safe":
    # TODO: Let the user know the email is safe and close the ticket
    # TODO: Move the report to the safe folder or trash
    pass
  elif sample["yaramail"]["verdict"] == "junk":
    # TODO: Tell the user how to add an address to their spam filter
    # TODO: Close the ticket and move the report to the junk/trash folder
    pass
  else:
    escalate_to_incident_response(report_email)

```

[vscode]: https://code.visualstudio.com/
[email-extension]: https://marketplace.visualstudio.com/items?itemName=leighlondon.eml
[gitlens-extension]: https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens
[python-extension]: https://marketplace.visualstudio.com/items?itemName=ms-python.python
[remote-development-extension]: https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack
[yara-extension]: https://marketplace.visualstudio.com/items?itemName=infosec-intern.yara
[DMARC]: https://seanthegeek.net/459/demystifying-dmarc/
[yara_rules]: https://yara.readthedocs.io/en/stable/writingrules.html
[ssdeep]: https://pypi.org/project/ssdeep/
[yara_include]: https://yara.readthedocs.io/en/stable/writingrules.html#including-files
[yara_meta]: https://yara.readthedocs.io/en/stable/writingrules.html#metadata
[yara_strings]: https://yara.readthedocs.io/en/stable/writingrules.html#strings
[yara_text_strings]: https://yara.readthedocs.io/en/stable/writingrules.html#text-strings
[yara_hex_strings]: https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings
[yara_regex]: https://yara.readthedocs.io/en/stable/writingrules.html#regular-expressions
[yara_string_modifiers]: https://yara.readthedocs.io/en/stable/writingrules.html#string-modifier-summary
[yara_condition]: https://yara.readthedocs.io/en/stable/writingrules.html#conditions
[CyberChef]: https://github.com/gchq/CyberChef/releases
[EDGAR]: https://www.sec.gov/edgar/searchedgar/companysearch.html
[file signatures]: https://en.wikipedia.org/wiki/List_of_file_signatures
[LOC]: https://www.loc.gov/preservation/digital/formats/fdd/browse_list.shtml
[filesize]: https://yara.readthedocs.io/en/stable/writingrules.html#file-size
[exiftool]: https://exiftool.org/
