/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-10-17
   Identifier: Backdoor Setuid
   Reference: https://raw.githubusercontent.com/nil0x42/phpsploit/master/plugins/system/suidroot/backdoor.c
   MITRE ATT&CK: https://attack.mitre.org/techniques/T1548/001/
   
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
      $s2 = "_IO_stdin_used" fullword ascii
      $s3 = "__frame_dummy_init_array_entry" fullword ascii
      $s4 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s5 = "[kthreadH" fullword ascii
      $s6 = "completed.0" fullword ascii
      $s7 = "system@GLIBC_2.2.5" fullword ascii
      $s8 = "__FRAME_END__" fullword ascii
      $s9 = ".eh_frame_hdr" fullword ascii
      $s10 = ".note.ABI-tag" fullword ascii
      $s11 = "frame_dummy" fullword ascii
      $s12 = "__libc_start_main" fullword ascii
      $s13 = "GLIBC_2.2.5" fullword ascii
      $s14 = "__gmon_start__" fullword ascii
      $s15 = "Scrt1.o" fullword ascii
      $s16 = "libc.so.6" fullword ascii
      $s17 = "memset@GLIBC_2.2.5" fullword ascii
      $s18 = "/lib64/ld-linux-x86-64.so.2" fullword ascii
      $s19 = "__do_global_dtors_aux_fini_array_entry" fullword ascii
      $s20 = "__libc_csu_init" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}
