/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-10-17
   Identifier: Backdoor
   MITRE ATT&CK: https://attack.mitre.org/tactics/TA0003/, https://attack.mitre.org/tactics/TA0004/
   
*/

/* Rule Set ----------------------------------------------------------------- */

rule nil0x42_phpsploit_suidbackdoor {
   meta:
      description = "phpsploit suid backdoor"
      author = "faisalfs10x"
      reference = "https://raw.githubusercontent.com/nil0x42/phpsploit/master/plugins/system/suidroot/backdoor.c"
      date = "2021-10-17"
      
   strings:
      $s1 = ".note.gnu.build-id" fullword ascii
      $s2 = "__FRAME_END__" fullword ascii
      $s3 = "_IO_stdin_used" fullword ascii
      $s4 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s5 = ".eh_frame_hdr" fullword ascii
      $s6 = "__frame_dummy_init_array_entry" fullword ascii
      $s7 = "frame_dummy" fullword ascii
      $s8 = ".note.ABI-tag" fullword ascii
      $s9 = "__init_array_start" fullword ascii
      $s10 = "/lib64/ld-linux-x86-64.so.2" fullword ascii
      $s11 = "deregister_tm_clones" fullword ascii
      $s12 = "_ITM_deregisterTMCloneTable" fullword ascii
      $s13 = "__libc_start_main" fullword ascii
      $s14 = "__do_global_dtors_aux" fullword ascii
      $s15 = "__init_array_end" fullword ascii
      $s16 = "__data_start" fullword ascii
      $s17 = ".plt.got" fullword ascii
      $s18 = "_ITM_registerTMCloneTable" fullword ascii
      $s19 = "libc.so.6" fullword ascii
      $s20 = "__do_global_dtors_aux_fini_array_entry" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}
