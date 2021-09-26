/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-09-27
   Identifier: Hacktool Indicator
   Reference: https://github.com/jamesbarlow/icmptunnel
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_icmptunnel_Tunneling {

   meta:
      description = "Detect icmptunnel tunneling tool - file icmptunnel"
      author = "faisalfs10x"
      reference = "https://github.com/jamesbarlow/icmptunnel"
      date = "2021-09-27"
      hash1 = "57afc84d2562bbec551620065fbdc4f3f427cd8b88f9b9395dd22482ae301181"
      
   strings:
      $str1 = "  -e               emulate the microsoft ping utility."  ascii
      $str2 = "  -d               run in the background as a daemon."  ascii
      $str3 = "opening raw icmp sockets requires root privileges."  ascii
      $str4 = "handle_keep_alive_request.part.1"  ascii
   
      $blacklist1 = "gethostbyname" ascii //network
      $blacklist2 = "srand" ascii //cryptography
      $blacklist3 = "recvfrom" ascii //network
      $blacklist4 = "sendto" ascii //network

   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      2 of ($str*) and 4 of ($blacklist*)

}
