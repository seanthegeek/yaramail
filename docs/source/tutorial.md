# Tutorial

`yaramail` provides a workflow for automated triage of phishing reports.

## Best practices

it is **strongly recommended** to create a private Git repository as a place
to develop, store, and maintain  YARA rules, trusted domain lists, and sample
emails, for a number of reasons.

- Version control tracks who made what change when, with easy rollback
- Automations can (and should) pull a fresh copy of the repository
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

## Methodology

The `yaramail` module contains a `MailScanner` class. When `MailScanner` scans
an email, it attempts to use a combination of email authentication results and
YARA rule matches to categorize an email and reach a `verdict`. To do this, it
does several things. First, it scans the contents of the email headers, body,
and attachments with user-provided YARA rules. Then, the `meta` section of each
matching rule is checked for a `category` value. Each match category is added
to a deduplicated list of `categories`. If a single category is listed the
`verdict` is set to that category. If multiple categories are listed the
verdict is set to `ambiguous`.

Then, the `Authentication-Results` of the email is parsed. The
`Authentication-Results` header is added by the receiving mail server as a way
of logging the results of authentication checks that prove that the domain
in the message `From` header was not spoofed. Most email services — including
Microsoft 365 and Gmail — use a single `Authentication-Results` header 
to log the results of all authentication checks. By default,
all `Authentication-Results` headers will be ignored if multiple
`Authentication-Results` headers are found in an email. This is done to avoid
false positives when an attacker adds their own`Authentication-Results`
header to an email before it reaches the destination mail server.

Postfix mail servers use a separate `Authentication-Results` header for each
authentication check. If your mail service does this, set the
`allow_multiple_authentication_results` parameter to `True`.
This allows multiple headers, but all `Authentication-Results` headers will
be ignored if multiple DMARC results are found, to avoid spoofed results.

```{warning}
Authentication results are not verified by `yaramail`, so only use it on
emails that have been received by trusted mail servers, and not on
third-party emails.
```

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

```{tip}
Read [Demystifying DMARC][DMARC] for more details about SPF, DKIM, and DMARC.
```

The `safe` verdict is special. In order to reach a `safe` verdict, one of the
following sets of conditions must be met.

1. An authenticated domain is in the `trusted_domains` list **and** the categories list is empty **or** only contains `safe`
2. **Any** of the matching rules have a meta value `auth_optional` set to `true` **and** the categories list contains one value, `safe`
3. An authenticated domain is in the `trusted_domains_yara_safe_required` list **and** the categories list contains one value, `safe`

The first scenario is useful in situations where the sending domain is
trusted, but the email content is not consistent enough for a YARA rule.

The second scenario is useful is situations where the sender can't or won't
use DKIM properly, but very specific email content traits can be identified.

The third scenario is the most trusted, because the email from domain has been
authenticated **and** the email includes known safe content.

## Getting started

Follow the [installation guide](installation).

Import `MailScanner` from `yaramail`, and create a new 
[`MailScanner` object](api)

```python
import logging

from yaramail import MailScanner

logger = logging.getLogger("scanner")

# Initialize the scanner
scanner = None  # Avoid an IDE warning
try:
    scanner = MailScanner(
        header_rules="header.yar",
        body_rules="body.yar",
        header_body_rules="header_body.yar",
        attachment_rules="attachment.yar",
        trusted_domains="trusted_domains.txt",
        trusted_domains_yara_safe_required="trusted_yara_safe_required.txt")
except Exception as e:
    logger.error(f"Could not initialize the scanner: {e}")
    exit(-1)
```

```{tip}
Use the [include][include] directive in the YARA rule files that you pass to
`MailScanner` to include rules from other files. That way, rules can be
divided into separate files as you see fit.
```

To scan an email, pass email content, a file-like object, or a file path to 
`MailScanner.scan_email()`. Take a look at the [API documentation](api) to
learn about the returned objects.

## Practical YARA rule examples

[YARA rules][rules] provide a flexable method of checking email header, body,
and attachment content against known malicious and trusted patterns.

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
    
    /*
    The total number of URLs must match the number of example.com URls.
    Require at least one URL for this rule, otherwise all email with no URLs would match.
    */
    
    condition:
    #http > 0 and #http == #example
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
    $short_url = /https?:\/\/[\w.]{3,12}\/\w{5,14}[\s|"|)|#|>]/ ascii wide nocase
    
    condition:
    any of them
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
Take the time to read over YARA's documentation and other resources.

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
A helpful list of [file type signatures][file signatures] can be found on
Wikipedia.
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
    discription = "A small ISO file"
    
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

## Using the CLI

the [`yaramail` CLI](cli) has built-in support for scanning  individual
samples, or an entire collection of samples.

```{tip}
Most CLI options can also be set using environment variables. See the CLI
documentation for details.
```

Use the `--rules`option to specify a path to a directory where the following 
files can be found:

- `header.yar` - Rules that apply to email header content
- `body.yar` - Rules that apply to email body content
- `header_body.yar` - Rules that apply to header and/or body content
- `attachments.yar` - Rules that apply to email attachment content
- `passwords.txt` - A list of passwords to try on password-protected attachments
- `trusted_domains.txt` - A list of message from domains that return a `safe` verdict if the domain is authenticated and no YARA categories match other than safe
- `trusted_domains_yara_safe_required.txt` - A list of message From domains that return a `safe` verdict if the domain is authenticated *and* the email itself has a YARA `safe` verdict

```{note}
The expected names of these files can be changed using command-line arguments
or environment variables.
```

```{note}
If any of these files are missing or blank, the CLI will issue a warning, but
the scanner will still run using the data it does have.
```

### Scanning an individual sample

To scan an individual sample, pass a path to the sample to `yaramail`.
The scan results will be printed to the terminal's standard output.

```{tip}
To scan standard input (stdin) use `-` as the path to scan.
```

### Scanning multiple samples

The `yaramail CLI` accepts wildcards (i.e., `*`) in the scan path to scan
multiple files at once. This is useful for seeing what samples have in common.

### Testing a collection of samples

To test `verdict` values across an entire collection of email samples, use the
`-t/--test` option, and pass in a path to a directory of samples that are
sorted into subdirectories by expected verdict.

`yaramail` will print any test failures to standard error (stderr), print 
passed/total numbers to standard output (stdout), and use the number of test
failures as the return code. This is designed for developer use, and for CI/CD
testing pipelines.

## Automating phishing report triage

Here's a complete example of triage code.

```python
import logging
from typing import Dict

from mailsuite.utils import parse_email
from yaramail import MailScanner

logger = logging.getLogger("scanner")


def escalate_to_incident_response(_report_email: Dict,
                                  priority: str = "normal"):
    m = f"Escalating {priority} priority email"
    logger.debug(m)
    # TODO: Do something!


malicious_categories = ["credential harvesting", "fraud", "malware"]
malicious_categories = set(malicious_categories)

# Initialize the scanner
scanner = None  # Avoid an IDE warning
try:
    scanner = MailScanner(
        header_rules="header.yar",
        body_rules="body.yar",
        header_body_rules="header_body.yar",
        attachment_rules="attachment.yar",
        trusted_domains="trusted_domains.txt",
        trusted_domains_yara_safe_required="trusted_yara_safe_required.txt")
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

[DMARC]: https://seanthegeek.net/459/demystifying-dmarc/
[rules]: https://yara.readthedocs.io/en/stable/writingrules.html
[include]: https://yara.readthedocs.io/en/stable/writingrules.html#including-files
[regex]: https://yara.readthedocs.io/en/stable/writingrules.html#regular-expressions
[CyberChef]: https://github.com/gchq/CyberChef/releases
[EDGAR]: https://www.sec.gov/edgar/searchedgar/companysearch.html
[file signatures]: https://en.wikipedia.org/wiki/List_of_file_signatures
[filesize]: https://yara.readthedocs.io/en/stable/writingrules.html#file-size
