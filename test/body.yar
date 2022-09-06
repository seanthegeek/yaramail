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
        $http = "http" ascii wide nocase
        $example_url = "https://example.com" ascii wide nocase
    condition:
        /*
        The total number of URLs must match the number of example.com URls.
        Require at least one URL for this rule, otherwise all email with no
        URLs would match.
        */
        #http > 0 and #http == #example_url
}

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

rule sans_newsletter {
    meta:
        author = "Sean Whalen"
        date = "2022-08-08"
        category = "safe"
        from_domain = "email.sans.org"
    strings:
        $s1 = "SANS NewsBites"
        $s2 = "https://www.sans.org/preference-center"
    condition:
        all of them
}
