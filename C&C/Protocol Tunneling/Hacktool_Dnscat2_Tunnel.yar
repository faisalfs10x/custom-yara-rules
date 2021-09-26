/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-09-27
   Identifier: Hacktool Indicator
   Reference: https://github.com/iagox86/dnscat2
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_Dnscat2_Tunnel {

   meta:
      description = "Detect dnscat2 tunneling tool - file dnscat"
      author = "faisalfs10x"
      reference = "https://github.com/iagox86/dnscat2"
      date = "2021-09-27"
      hash1 = "62e93e470e2e4af93743948045b9a5315f6469db59c6a3f020e5f8080dd340c7"
      
   strings:
      $str1 = " --exec -e <process>     Execute the given process and link it to the stream." fullword ascii
      $str2 = "exec driver shut down; killing process %d" fullword ascii
      $str3 = "COMMAND_EXEC [response] :: request_id: 0x%04x :: session_id: 0x%04x" fullword ascii
      $str4 = "COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s" fullword ascii
      $str5 = "exec: couldn't create process (%d)" fullword ascii
      $str6 = "Starting: /bin/sh -c '%s'" fullword ascii
      $str7 = "exec: couldn't create pipe (%d)" fullword ascii
      $str8 = "COMMAND_SHELL [response] :: request_id: 0x%04x :: session_id: 0x%04x" fullword ascii
      $str9 = "[Tunnel %d] connection to %s:%d closed by the client: %s" fullword ascii
      $str10 = "[Tunnel %d] connection to %s:%d closed by the server!" fullword ascii
      $str11 = "By default, a --dns driver on port 53 is enabled if a hostname is" fullword ascii
      $str12 = "It looks like you used --dns and also passed a domain on the commandline." fullword ascii
      $str13 = "Error: dropped user account has root privileges; please specify a better" fullword ascii
      $str14 = " --command               Start an interactive 'command' session (default)." fullword ascii
      $str15 = "Creating a exec('%s') session!" fullword ascii
      $str16 = "exec: execlp failed (%d)" fullword ascii
      $str17 = "COMMAND_DOWNLOAD [request] :: request_id: 0x%04x :: filename: %s" fullword ascii
      $str18 = "** Peer verified with pre-shared secret!" fullword ascii
      $str19 = "COMMAND_DOWNLOAD [response] :: request_id: 0x%04x :: data: 0x%x bytes" fullword ascii
      $str20 = "Received FIN: (reason: '%s') - closing session" fullword ascii

   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

