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

rule robot_devil_pdf {
    meta:
        author = "Sean Whalen"
        date = "2022-08-09"
        category = "credential-harvesting"
        description = "Robot Devil credential harvesting PDF"
    strings:
        $pdf = {25 50 44 46 2D}
        $s_author = "Author(The Robot Devil)" ascii wide
        $s_uri = /URI\(.+\)/
    condition:
        $pdf at 0 and all of ($s_*)
}

