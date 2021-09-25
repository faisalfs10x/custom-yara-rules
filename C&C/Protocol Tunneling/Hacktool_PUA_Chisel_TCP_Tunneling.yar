/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-09-24
   Identifier: Hacktool Indicator
   Reference: https://github.com/jpillora/chisel/
   MITRE ATT&CK: https://attack.mitre.org/techniques/T1572/
   
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_PUA_Chisel_PE32_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling tool - file chisel_1.7.6_windows_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
   strings:
      $str1 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $str2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $str3 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $str4 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $str5 = "%s flag redefined: %s, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
      $str6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $str7 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $str8 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $str9 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $str10 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $str11 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $str12 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $str13 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $str14 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $str15 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $str16 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $str17 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $str18 = "tls: failed to send closeNotify alert (but connection was closed anyway): %wcrypto/tls: ExportKeyingMaterial is unavailable when" ascii
      $str19 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $str20 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii

      $x10 = "(error %s) (targetpc= ErrCode=%v KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock,  nBSSRoots=" ascii

   condition:
      uint16(0) == 0x5a4d and $x10 and filesize < 25000KB and
      1 of ($str*)
}

rule Hacktool_PUA_Chisel_Elf_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling tool - file chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $str1 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $str2 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $str3 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $str4 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $str5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $str6 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $str7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $str8 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $str9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $str10 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF465661287307739257" ascii
      $str11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: unk" ascii
      $str12 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $str13 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $str14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $str15 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $str16 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $str17 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $str18 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $str19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $str20 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii

      $x10 = "(error %s) (targetpc= ErrCode=%v KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock,  nBSSRoots=" ascii

   condition:
      uint16(0) == 0x457f and $x10 and filesize < 24000KB and
      1 of ($str*)
}
