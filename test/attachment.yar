rule small_iso {
    meta:
        author = "Sean Whalen"
        date = "2022-07-21"
        category = "malware"
        description = "A small ISO file"
    strings:
        $iso = "CD001"
    condition:
        ($iso at 8001 or $iso at 8801 or $iso at 9001)
        and filesize < 200MB
}

rule robot_devil_pdf {
    meta:
        author = "Sean Whalen"
        date = "2022-08-09"
        category = "cred-harvesting"
        description = "Robot Devil credential harvesting PDF"
    strings:
        $pdf = {25 50 44 46 2D}
        $s_author = "Author(The Robot Devil)" ascii wide
        $s_uri = /URI\(.+\)/
    condition:
        $pdf at 0 and all of ($s_*)
}

