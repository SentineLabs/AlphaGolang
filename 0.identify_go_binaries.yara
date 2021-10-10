rule TTP_GoBuildID
{
	meta:  
		desc = "Quick rule to identify Golang binaries (PE,ELF,Macho)"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "10.06.2021"

	strings:
		$GoBuildId = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
	
	condition:
		(
			(uint16(0) == 0x5a4d) or 
			(uint32(0)==0x464c457f) or 
			(uint32(0) == 0xfeedfacf) or 
			(uint32(0) == 0xcffaedfe) or 
			(uint32(0) == 0xfeedface) or 
			(uint32(0) == 0xcefaedfe) 
		)
		and
		#GoBuildId == 1
}
