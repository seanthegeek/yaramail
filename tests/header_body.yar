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

