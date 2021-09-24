/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-09-24
   Identifier: Hacktool Indicator
   Reference: https://github.com/jpillora/chisel/
   MITRE ATT&CK: https://attack.mitre.org/techniques/T1572/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.0"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
   strings:
      $x1 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x3 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x4 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x5 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x6 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x7 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x8 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii
      $x9 = "x509: PKCS#8 wrapping contained private key with unknown algorithm: %vdecoding string array or slice: length exceeds input size " ascii
      $x10 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii
      $x12 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii
      $x16 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x17 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x19 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii
      $x20 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii
   condition:
      uint16(0) == 0x457f and filesize < 25000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chisel_1.7.6_windows_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
   strings:
      $x1 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x3 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x4 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x5 = "%s flag redefined: %s, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x7 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x8 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x9 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x10 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x11 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x12 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x13 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x14 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x15 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x16 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x17 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x18 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x19 = "tls: failed to send closeNotify alert (but connection was closed anyway): %wcrypto/tls: ExportKeyingMaterial is unavailable when" ascii
      $x20 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.0.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
   strings:
      $x1 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x3 = "%s flag redefined: %s%s.%s.ka.acme.invalid, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAl" ascii
      $x4 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x6 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x7 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x8 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x9 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x10 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x11 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 p" ascii
      $x12 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x13 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x14 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x15 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x16 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x17 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x19 = "slice bounds out of range [:%x] with length %yssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status !=" ascii
      $x20 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.4.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
   strings:
      $x1 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x4 = "%s flag redefined: %s%s.%s.ka.acme.invalid, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAl" ascii
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x6 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x7 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x8 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x9 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x10 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x11 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 p" ascii
      $x12 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x13 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x14 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x15 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x16 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x17 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x19 = "slice bounds out of range [:%x] with length %yssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status !=" ascii
      $x20 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.5"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
   strings:
      $x1 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x2 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x4 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x6 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x8 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x10 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF465661287307739257" ascii
      $x11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: unk" ascii
      $x12 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x15 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x16 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x17 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x18 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x20 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii
   condition:
      uint16(0) == 0x457f and filesize < 24000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.4"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
   strings:
      $x1 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x3 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x4 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x5 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x6 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x7 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x8 = "x509: PKCS#8 wrapping contained private key with unknown algorithm: %vdecoding string array or slice: length exceeds input size " ascii
      $x9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x10 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii
      $x11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii
      $x12 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii
      $x16 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x17 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x19 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii
      $x20 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii
   condition:
      uint16(0) == 0x457f and filesize < 26000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $x1 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x3 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x4 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x5 = "%s flag redefined: %s, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x7 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x8 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x9 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x10 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x11 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x12 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x13 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x14 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x15 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x16 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x17 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x18 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x19 = "tls: failed to send closeNotify alert (but connection was closed anyway): %wcrypto/tls: ExportKeyingMaterial is unavailable when" ascii
      $x20 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $x1 = "Unable to marshal ECDSA private key: %vacme/autocert: invalid authorization %qacme/autocert: unknown private key typeasn1: Unmar" ascii
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x3 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x4 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x5 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x6 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeSao Tome Standard TimeSec-WebSocket-Prot" ascii
      $x7 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x8 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x9 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x10 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x11 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x12 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x13 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x14 = "Reverse tunnelling enabledSaint Pierre Standard TimeServer cannot listen on %sSetFileInformationByHandleSouth Africa Standard Ti" ascii
      $x15 = "unclosed commentunexpected type unknown network unknown node: %sworkbuf is emptywww-authenticate (protocol error) initialHeapLiv" ascii
      $x16 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x17 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x18 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x19 = "tls: failed to send closeNotify alert (but connection was closed anyway): %wcrypto/tls: ExportKeyingMaterial is unavailable when" ascii
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*)
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - file chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $x1 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x2 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x4 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x6 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x8 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x10 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF465661287307739257" ascii
      $x11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: unk" ascii
      $x12 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x15 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x16 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x17 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x18 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x20 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii
   condition:
      uint16(0) == 0x457f and filesize < 24000KB and
      1 of ($x*)
}

/* Super Rules ------------------------------------------------------------- */

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_windows_386, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash4 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash5 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash6 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash7 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash8 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
      hash9 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $x1 = "github.com/jpillora/chisel/share/settings.(*Users).Get" fullword ascii
      $x2 = "github.com/jpillora/chisel/share/cio.(*Logger).Errorf" fullword ascii
      $s3 = "ter-alignedhpack: invalid Huffman-encoded datahttp2: server processing setting %vhttp2: server: client %v said hellohttp: server" ascii
      $s4 = "text/template.ExecError.Error" fullword ascii
      $s5 = "github.com/jpillora/chisel/share/cio.(*Logger).Debugf" fullword ascii
      $s6 = "github.com/jpillora/chisel/share/cio.(*Logger).IsDebug" fullword ascii
      $s7 = "github.com/jpillora/chisel/share/cio/logger.go" fullword ascii
      $s8 = "github.com/jpillora/chisel/share/cio.(*Logger).Fork" fullword ascii
      $s9 = "github.com/jpillora/chisel/share/cio.(*Logger).Infof" fullword ascii
      $s10 = "github.com/jpillora/chisel/share/cio.NewLoggerFlag" fullword ascii
      $s11 = "github.com/jpillora/chisel/share/cio.(*Logger).Prefix" fullword ascii
      $s12 = "text/template.ExecError.Unwrap" fullword ascii
      $s13 = "github.com/jpillora/chisel/share/cio.NewLogger" fullword ascii
      $s14 = "*template.ExecError" fullword ascii
      $s15 = "github.com/jpillora/chisel/share/cio.(*Logger).IsInfo" fullword ascii
      $s16 = "text/template.(*Template).Execute" fullword ascii
      $s17 = "text/template.(*Template).ExecuteTemplate" fullword ascii
      $s18 = "p2: Framer %p: read %vhttp2: invalid header: %vhttp2: unsupported schemeillegal number syntax: %qinconsistent poll.fdMutexinvali" ascii
      $s19 = "github.com/jpillora/chisel/share/settings.(*Users).Del" fullword ascii
      $s20 = "github.com/jpillora/chisel/share/settings.(*Users).Set" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.4"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
   strings:
      $s1 = "github.com/jpillora/chisel/share/settings.(*Users).RLocker" fullword ascii
      $s2 = "github.com/jpillora/chisel/share/settings.(*Users).Unlock" fullword ascii
      $s3 = "github.com/jpillora/chisel/share/settings.(*Users).RUnlock" fullword ascii
      $s4 = "github.com/jpillora/chisel/share/settings.UserIndex.Get" fullword ascii
      $s5 = "github.com/jpillora/chisel/share/settings.(*Users).Lock" fullword ascii
      $s6 = "github.com/jpillora/chisel/share/settings.(*UserIndex).Get" fullword ascii
      $s7 = "github.com/jpillora/chisel/share/settings.(*Users).RLock" fullword ascii
      $s8 = "github.com/jpillora/chisel/share/cnet.HTTPServer.ListenAndServe" fullword ascii
      $s9 = "github.com/jpillora/chisel/share/tunnel.(*udpListener).Errorf" fullword ascii
      $s10 = "github.com/jpillora/chisel/share/settings.UserIndex.Errorf" fullword ascii
      $s11 = "github.com/jpillora/chisel/share/cnet.(*HTTPServer).ListenAndServeTLS" fullword ascii
      $s12 = "github.com/jpillora/chisel/share/settings.(*UserIndex).Errorf" fullword ascii
      $s13 = "github.com/jpillora/chisel/share/cnet.(*HTTPServer).ListenAndServe" fullword ascii
      $s14 = "github.com/jpillora/chisel/share/cnet.(*HTTPServer).GoListenAndServe" fullword ascii
      $s15 = "github.com/jpillora/chisel/share/tunnel.udpListener.Errorf" fullword ascii
      $s16 = "github.com/jpillora/chisel/share/cnet.HTTPServer.ListenAndServeTLS" fullword ascii
      $s17 = "github.com/jpillora/chisel/share/cnet.(*HTTPServer).GoListenAndServeContext" fullword ascii
      $s18 = "ary HelloRetryRequest messagetype mismatch: no fields matched compiling decoder for %sx509: failed to parse EC private key embed" ascii
      $s19 = "github.com/jpillora/chisel/server.(*Server).ResetUsers" fullword ascii
      $s20 = "github.com/jpillora/chisel/share/cnet.HTTPServer.net/http.doKeepAlives" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.5, chiselv1.7.4, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash3 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash4 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $x1 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x2 = "ssh: GSSAPI authentication must use the Kerberos V5 mechanismtls: client certificate used with invalid signature algorithmtls: s" ascii
      $x3 = "net/http: invalid Cookie.Domain %q; dropping domain attributeruntime: may need to increase max user processes (ulimit -u)" fullword ascii
      $x4 = "Listening on %s://%s:%s%sLogin failed for user: %sOnly one stdio is allowedTLS verification disabledUnrecognized address type_cg" ascii
      $s5 = "turn no data or errornet/http: timeout awaiting response headersno multipart boundary param in Content-Typenon executable comman" ascii
      $s6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETNetw" ascii
      $s7 = " data: field numbers out of boundsgob: encoded unsigned integer out of rangehttp2: server connection error from %v: %vhttp: Cont" ascii
      $s8 = "Listening on %s://%s:%s%sLogin failed for user: %sOnly one stdio is allowedTLS verification disabledUnrecognized address type_cg" ascii
      $s9 = "d Content-Length of %qhttp: persistConn.readLoop exitinghttp: read on closed response bodyi/o operation on closed connectionille" ascii
      $s10 = " or Reject channelssh: private key unexpected lengthssh: publickey auth not configuredstream error: stream ID %d; %v; %vtimeout " ascii
      $s11 = "keys messagessh: unknown key algorithm: %vstream error: stream ID %d; %vsync: inconsistent mutex statesync: unlock of unlocked m" ascii
      $s12 = " runtime executionwebsocket: invalid compression negotiationx509: %q cannot be encoded as an IA5Stringx509: RSA modulus is not a" ascii
      $s13 = "serviceAcceptMsgshort response: sigaction failedssh: MAC failurestopped (signal)template: %s: %sterms-of-servicetime: bad [0-9]*" ascii
      $s14 = " error - misuse of itabinvalid network interface indexjson: invalid number literal %qmalformed time zone informationmergeRuneSet" ascii
      $s15 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $s16 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $s17 = "ixhttp: response.WriteHeader on hijacked connection from %s (%s:%d)net/http: Transport.DialTLS or DialTLSContext returned (nil, " ascii
      $s18 = "na mappointer to unknown type in field %d: %Tproxy: destination host name too long: reflect.MakeMapWithSize of non-map typerunti" ascii
      $s19 = "col '%s', expected '%s'internal error: attempt to send frame on a closed stream: %vmalformed response from server: missing statu" ascii
      $s20 = "github.com/jpillora/chisel/share/cos/signal.go" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.5, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash2 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $x1 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x2 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x4 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x6 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x8 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x10 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF465661287307739257" ascii
      $x11 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: unk" ascii
      $x12 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x14 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x15 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x16 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x17 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x18 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFloatPhoenici" ascii
      $x19 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii
      $x20 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625A server and least one remote is requiredClose" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.4"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
   strings:
      $x1 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error loading client cert and key pair: %vFa" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscrypto/rsa: input mus" ascii
      $x3 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x4 = "acme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing server nameacme/autocert: no public k" ascii
      $x5 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii
      $x6 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii
      $x7 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $x8 = "x509: PKCS#8 wrapping contained private key with unknown algorithm: %vdecoding string array or slice: length exceeds input size " ascii
      $x9 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii
      $x10 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x11 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x12 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii
      $x13 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x14 = "can't switch protocols using non-Hijacker ResponseWriter type %Tdecoding array or slice: length exceeds input size (%d elements)" ascii
      $x15 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625A server and least one remote is requiredClose" ascii
      $x16 = "%s flag redefined: %s%s.%s.ka.acme.invalid, levelBits[level] = 186264514923095703125931322574615478515625Anatolian_HieroglyphsAu" ascii
      $x17 = "\\[([^a-zA-Z]*)(0c|0n|3n|R)access-control-allow-originacme: rel=up link not foundacme: unexpected status: %sadd DATA on non-open" ascii
      $x18 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 p" ascii
      $x19 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x20 = " > (den<<shift)/2text/plain; charset=utf-16betext/plain; charset=utf-16leunexpected end of JSON inputunexpected protocol version" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 26000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash5 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $x1 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttarget must be an ab" ascii
      $x2 = "Kaliningrad Standard TimeListening on %s://%s:%s%sLogin failed for user: %sMiddle East Standard TimeNew Zealand Standard TimeNor" ascii
      $x3 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x4 = "SSH disconnectedSetFilePointerExSignatureScheme(Stream error: %sTerminateProcessUpgrade RequiredUser-Agent: %s" fullword ascii
      $x5 = "Kaliningrad Standard TimeListening on %s://%s:%s%sLogin failed for user: %sMiddle East Standard TimeNew Zealand Standard TimeNor" ascii
      $s6 = "atPhoenicianProcessingRIPEMD-160RST_STREAMSHA256-RSASHA384-RSASHA512-RSASaurashtraSet-CookieUser-AgentWSACleanupWSASocketWWSASta" ascii
      $s7 = "nd ClientHellotls: failed to create cipher while encrypting ticket: tls: found unknown private key type in PKCS#8 wrappingtls: s" ascii
      $s8 = "namenextnonenullopenpathpingpipepop3portprofquitreadrel=rootsbrkseeksmtpsse2sse3synctag:tcp4tcp6trueudp4uintunixvarywithxn--  -%" ascii
      $s9 = "sExWGetProcessMemoryInfoHTTP/%d.%d %03d %s" fullword ascii
      $s10 = "github.com/andrew-d/go-termutil@v0.0.0-20150726205930-009166a695a2/getpass_windows.go" fullword ascii
      $s11 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWConnection error: %sCreatePr" ascii
      $s12 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
      $s13 = " unexpected lengthssh: publickey auth not configuredstream error: stream ID %d; %v; %vtimeout waiting for client prefacetls: mal" ascii
      $s14 = "namenextnonenullopenpathpingpipepop3portprofquitreadrel=rootsbrkseeksmtpsse2sse3synctag:tcp4tcp6trueudp4uintunixvarywithxn--  -%" ascii
      $s15 = " statesync: unlock of unlocked mutextext/javascript; charset=utf-8transform: short source buffertype %s has no exported fieldsun" ascii
      $s16 = "arse DSA key: ssh: got bogus newkeys messagessh: unknown key algorithm: %vstream error: stream ID %d; %vsync: inconsistent mutex" ascii
      $s17 = "github.com/andrew-d/go-termutil.getConsoleMode" fullword ascii
      $s18 = "github.com/fsnotify/fsnotify.getIno" fullword ascii
      $s19 = "github.com/fsnotify/fsnotify.watchMap.get" fullword ascii
      $s20 = "github.com/fsnotify/fsnotify.getDir" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $x1 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125; challenge %q failed with error: %vGo pointer stored in" ascii
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x3 = "%s flag redefined: %s, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
      $x4 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x5 = "%sinteger not minimally-encodedinternal error: took too muchinvalid character class rangeinvalid header field value %qinvalid le" ascii
      $x6 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhmac-sha1-96host is downhttp2debug=1http2debug=2illegal seekimage/x-iconinvalid " ascii
      $x7 = "IP addressKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFlo" ascii
      $x8 = "unixpacketunknown pcuser-agentvalue for video/webmws2_32.dllwsarecvmsgwsasendmsg  of size   (error %s) (targetpc= ErrCode=%v KiB" ascii
      $x9 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueDisconnectedECDSA-SH" ascii
      $x10 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x11 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
      $x12 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x13 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x14 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
      $x15 = "flate: internal error: fsnotify queue overflowfunction %q not definedgarbage collection scangcDrain phase incorrectglobalRequest" ascii
      $x16 = " > (den<<shift)/2text/plain; charset=utf-16betext/plain; charset=utf-16leunexpected end of JSON inputunexpected protocol version" ascii
      $x17 = "alivemSpanDeadmSpanFreemap[%s]%snet/http.new-authznil erroromitemptypanicwaitpclmulqdqpreemptedprotocol psapi.dllpublickeyraw-wr" ascii
      $x18 = "atomicor8authoritybad indirbad prunebus errorchallengechan sendchisel-v3complex64connectexcopystackctxt != 0d.nx != 0debugLockem" ascii
      $x19 = "stack=[acceptexaddress authfileautocertavx512bwavx512cdavx512dqavx512eravx512pfavx512vlbad instbeEfFgGvboundarycgocheckcs      d" ascii
      $x20 = "GOAWAY close timer fired; closing conn from %vPSSWithSHA256PSSWithSHA384PSSWithSHA512Ed25519acme: no more retries for %s; tried " ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0.exe, chiselv1.7.4.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
   strings:
      $x1 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x2 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x4 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatchregexp: Compile(" ascii
      $x5 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x6 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 p" ascii
      $x7 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNo remot" ascii
      $x8 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: extra data followin" ascii
      $x9 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
      $x10 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii
      $x11 = "\\[([^a-zA-Z]*)(0c|0n|3n|R)access-control-allow-originacme: rel=up link not foundacme: unexpected status: %sadd DATA on non-open" ascii
      $x12 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in parse string failedparse uint32 failedproxy-authorizationreflect.Value." ascii
      $x13 = "acme: unknown key type; only RSA and ECDSA are supportedb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f" ascii
      $x14 = "flate: internal error: fsnotify queue overflowfunction %q not definedgarbage collection scangcDrain phase incorrectglobalRequest" ascii
      $x15 = "application/octet-streambad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertific" ascii
      $x16 = "CreateSymbolicLinkWCryptAcquireContextCryptReleaseContextEgypt Standard TimeFailed to parse keyGetCurrentProcessIdGetSystemDirec" ascii
      $x17 = "atomicor8authoritybad indirbad prunebroadcastbus errorchallengechan sendchisel-v3complex64connectexcopystackctxt != 0d.nx != 0de" ascii
      $x18 = " > (den<<shift)/2text/plain; charset=utf-16betext/plain; charset=utf-16leunexpected end of JSON inputunexpected protocol version" ascii
      $x19 = "stdio cannot be reversedstream %d already openedstreamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncompar" ascii
      $x20 = "asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %qwebsocket: the client " ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash4 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash5 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash6 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash7 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash8 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "math.log10" fullword ascii
      $s2 = "math.log2" fullword ascii
      $s3 = "runtime.makeHeadTailIndex" fullword ascii
      $s4 = "omitempt" fullword ascii
      $s5 = "runtime.mapassign_fast64ptr" fullword ascii
      $s6 = "type..eq.runtime.rwmutex" fullword ascii
      $s7 = "runtime.memhash128" fullword ascii
      $s8 = "vendor/golang.org/x/sys/cpu.xgetbv" fullword ascii
      $s9 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii
      $s10 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii
      $s11 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii
      $s12 = "publicke" fullword ascii
      $s13 = "crypto/elliptic.(*p256Curve).CombinedMult" fullword ascii
      $s14 = "crypto/elliptic.p256Curve.CombinedMult" fullword ascii
      $s15 = "publickef" fullword ascii
      $s16 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii
      $s17 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii
      $s18 = "{{templaH" fullword ascii
      $s19 = "ed4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f55ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d260" ascii
      $s20 = "runtime.settls" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.5, chiselv1.7.5.exe, chisel_1.7.6_windows_386, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash3 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash4 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
      hash5 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "http2: Transport failed to get client conn for %s: %vhttp: putIdleConn: too many idle connections for hostillegal use of AllowIl" ascii
      $s2 = "k lengthinvalid header field name %qinvalid proxy address %q: %vinvalid runtime symbol tableinvalid slice index: %d > %djson: Un" ascii
      $s3 = "marshal(non-pointer malformed MIME header line: mheap.freeSpanLocked - span missing required Host headermissing stack in shrinks" ascii
      $s4 = "51ssh: unable to authenticate, attempted methods %v, no supported methods remainunsupported socks proxy type: %s:// (only socks5" ascii
      $s5 = "s an incompatible key usagex509: failed to parse ECDSA parameters as named curvex509: trailing data after X.509 authority inform" ascii
      $s6 = "e %qtls: internal error: session ticket keys unavailabletls: private key type does not match public key typetls: received a sess" ascii
      $s7 = "2*struct { lock runtime.mutex; fn func(bool) bool }" fullword ascii
      $s8 = "rune availablegcControllerState.findRunnable: blackening not enabledhttp2: handler wrote more than declared Content-Lengthhttp2:" ascii
      $s9 = "ABCDEFGHIJ" fullword ascii /* reversed goodware string 'JIHGFEDCBA' */
      $s10 = "runtime.errorAddressString.RuntimeError" fullword ascii
      $s11 = "k attempts limit reached while verifying certificate chainhttp2: server closing client connection; error reading frame from clie" ascii
      $s12 = "runtime.errorAddressString.Addr" fullword ascii
      $s13 = "runtime.errorAddressString.Error" fullword ascii
      $s14 = "legalReads with ReadMetaHeadersmath/big: internal error: cannot find (D/n) = -1 for net/http: CloseNotify called after ServeHTTP" ascii
      $s15 = "text/template/parse.CommentNode.Type" fullword ascii
      $s16 = "2: Transport received %shttp2: client conn is closedhttp: no Host in request URLhttp: request body too largeinvalid byte in chun" ascii
      $s17 = "h:// or socks:// is supported)websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' headerx509: signature chec" ascii
      $s18 = "=*func(context.Context, *url.URL, string) (http.Header, error)" fullword ascii
      $s19 = "tackmspan.sweep: m is not lockedmultipart: boundary is emptymultipart: message too largeneed padding in bucket (key)negative n f" ascii
      $s20 = "text/template/parse.CommentNode.Position" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.5.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash3 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $x1 = "  Version: bufio: writer returned negative count from Writecan't install method/function %q with %d resultscould not find GetSys" ascii
      $x2 = "VirtualQuery for stack base failedacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii
      $x3 = "can't switch protocols using non-Hijacker ResponseWriter type %TcompileCallback: expected function with one uintptr-sized result" ascii
      $x4 = "span set block with unpopped elements found in resetssh: error parsing source-address restriction %q: %vssh: peer's curve25519 p" ascii
      $x5 = "tls: failed to send closeNotify alert (but connection was closed anyway): %wcrypto/tls: ExportKeyingMaterial is unavailable when" ascii
      $x6 = "slice bounds out of range [:%x] with length %yssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status !=" ascii
      $x7 = "\\[([^a-zA-Z]*)(0c|0n|3n|R)access-control-allow-originacme: rel=up link not foundacme: unexpected status: %sadd DATA on non-open" ascii
      $x8 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in parse string failedparse uint32 failedproxy-authorizationreflect.Value." ascii
      $x9 = "application/octet-streambad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertific" ascii
      $x10 = "CreateSymbolicLinkWCryptReleaseContextEgypt Standard TimeFailed to parse keyGC work not flushedGetCurrentProcessIdGetSystemDirec" ascii
      $x11 = "mstartbad sequence numberbad unicode format bad value for fieldclient disconnectedcontent-dispositiondevice not a streamdirector" ascii
      $x12 = "stdio cannot be reversedstream %d already openedstreamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncompar" ascii
      $s13 = "acme/autocert: host %q not configured in HostWhitelistbytes.Buffer: reader returned negative count from Readcertificate is not v" ascii
      $s14 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsquare r" ascii
      $s15 = ", goid=, j0 = 0.0.0.019531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625::1/128:method:scheme:statusAvestanBengaliBrailleCH" ascii
      $s16 = "&gt;&lt;'\\'') = ) m=+Inf+rsa-Inf.css.gif.htm.jpg.mjs.pdf.png.svg.xml/udp0x%x108031258080: p=:443<%s>ABRTACDTACSTAEDTAESTAKDTAKS" ascii
      $s17 = "oesn't have a SAN extension can only be decoded from remote interface type; received concrete type Invalid header (%s). Should b" ascii
      $s18 = "pop3sprintproxyrangerune scav schedsleepslicesockssse41sse42ssse3stdiosudogsvqxXsweeptext/tls: traceuint8usageusersutf-8valuewri" ascii
      $s19 = "m: %sacme/autocert: server name component count invalidattempt to execute system stack code on user stackchacha20: SetCounter at" ascii
      $s20 = "pop3sprintproxyrangerune scav schedsleepslicesockssse41sse42ssse3stdiosudogsvqxXsweeptext/tls: traceuint8usageusersutf-8valuewri" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.5, chiselv1.7.5.exe, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash3 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash4 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "vendor/golang.org/x/sys/cpu.processOptions" fullword ascii
      $s2 = "omitemptH9" fullword ascii
      $s3 = "ime: casgstatus: oldval=runtime: no module data for server to client compressionssh-dss-cert-v01@openssh.comssh-rsa-cert-v01@ope" ascii
      $s4 = ";\"'%2&'+2" fullword ascii /* hex encoded string '"' */
      $s5 = "unixpack" fullword ascii
      $s6 = "httponlyH9" fullword ascii
      $s7 = ":authoriI98" fullword ascii
      $s8 = "+*struct { F uintptr; p *runtime.pageAlloc }" fullword ascii
      $s9 = "4*struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii
      $s10 = "6*[]struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii
      $s11 = ":httpuCH" fullword ascii
      $s12 = "9*[136]struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii
      $s13 = "vendor/golang.org/x/sys/cpu/cpu.go" fullword ascii
      $s14 = "vendor/golang.org/x/sys/cpu.initOptions" fullword ascii
      $s15 = "vendor/golang.org/x/sys/cpu" fullword ascii
      $s16 = "vendor/golang.org/x/sys/cpu.archInit" fullword ascii
      $s17 = "localhos" fullword ascii
      $s18 = "9HEADf" fullword ascii
      $s19 = "acme_account+keyacme_account.keyafter object keyapplication/jsonapplication/wasmavx512vpclmulqdqbad SAN sequencebad g transition" ascii
      $s20 = "samesiteH91" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $x1 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii
      $x2 = "%s overflows int(?i)\\/(tcp|udp)$, not a function.WithValue(type 0123456789ABCDEF0123456789abcdef2384185791015625: value of type" ascii
      $s3 = "kdecryption failedentersyscallblockexec format errorfractional secondg already scannedglobalAlloc.mutexgp.waiting != nilhandshak" ascii
      $s4 = ", received remote type 0123456789aAbBcCdDeEfF_0123456789abcdefABCDEF_2006/01/02 15:04:05.00023283064365386962890625<invalid refl" ascii
      $s5 = "GetLongPathNameWHalfClosedRemoteImperial_AramaicInstRuneAnyNotNLMeroitic_CursiveMultiple ChoicesNetApiBufferFreeOpenProcessToken" ascii
      $s6 = "serviceAcceptMsgshort response: ssh: MAC failuretemplate: %s: %sterms-of-servicetime: bad [0-9]*unclosed commentunexpected type " ascii
      $s7 = "pc= throwing= until pc=%!Weekday(%s (%s):%d%s|%s%s|%s, bound = , limit = /dev/stdin012345678910.0.0.0/81220703125127.0.0.1:61035" ascii
      $s8 = "l32.dll" fullword ascii
      $s9 = "Accept error: %sAlready ReportedContent-EncodingContent-LanguageContent-Length: CreateDirectoryWDnsNameCompare_WDuplicateTokenEx" ascii
      $s10 = "i32.dll" fullword ascii
      $s11 = "rof.dll" fullword ascii
      $s12 = "nternal error - misuse of itabinvalid network interface indexjson: invalid number literal %qmalformed time zone informationmerge" ascii
      $s13 = "fullfatal error: getTypeInfo: gethostbynamegetservbynamegzip, deflatehmac-sha2-256http2client=0http2server=0if-none-matchimage/s" ascii
      $s14 = "_32.dll" fullword ascii
      $s15 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */
      $s16 = "FRAME_SIZE_ERRORFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerNameWGetCurrentThreadGetFullPathName" ascii
      $s17 = "baseinvalid kindinvalid portinvalid slotiphlpapi.dllkernel32.dllkexDHInitMsgkey exchangelfstack.pushlost channelmadvdontneedmax-" ascii
      $s18 = "olchannelEOFMsgcontent-rangedalTLDpSugct?debugCall2048define clausedisconnectMsgemail addressempty commandempty integerexchange " ascii
      $s19 = "ntdll.dlH" fullword ascii
      $s20 = "invalid bit size invalid stream IDkey align too biglocked m0 woke upmark - bad statusmarkBits overflowmissing closing )missing c" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.0.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
   strings:
      $s1 = "bad special kindbad summary databad symbol tablebinary.BigEndiancastogscanstatuscontent-encodingcontent-languagecontent-location" ascii
      $s2 = "*runtime.notInHeapSlice" fullword ascii
      $s3 = "9*struct { F uintptr; h *runtime.mheap; s *runtime.mspan }" fullword ascii
      $s4 = "MDDD@@@" fullword ascii
      $s5 = "@XIYYkO_K[@" fullword ascii
      $s6 = "AAAA@@@AA" fullword ascii
      $s7 = "serving" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "    R:<local-interface>:<local-port>:<remote-host>:<remote-port>" fullword ascii
      $s9 = "(*struct { F uintptr; c *runtime.mcache }" fullword ascii
      $s10 = "    <local-host>:<local-port>:<remote-host>:<remote-port>" fullword ascii
      $s11 = "    Fingerprint mismatches will close the connection." fullword ascii
      $s12 = "    You may provide just a prefix of the key or the entire string." fullword ascii
      $s13 = "---(((" fullword ascii /* Goodware String - occured 3 times */
      $s14 = ">stdiu" fullword ascii
      $s15 = "-,,,,(((---" fullword ascii
      $s16 = "! ### " fullword ascii
      $s17 = "%%%%%! !%%  %! % " fullword ascii
      $s18 = ";\"2V1\"2 " fullword ascii
      $s19 = "A@AACC" fullword ascii
      $s20 = "L$ H+A" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_windows_386, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash4 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash5 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash6 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
      hash7 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "github.com/jpillora/chisel/share/settings.EnvDuration" fullword ascii
      $s2 = "github.com/jpillora/chisel/share/settings.Env" fullword ascii
      $s3 = "github.com/jpillora/chisel/share/settings/env.go" fullword ascii
      $s4 = "github.com/jpillora/chisel/share/settings.EnvInt" fullword ascii
      $s5 = "github.com/jpillora/chisel/client.(*Client).verifyLegacyFingerprint" fullword ascii
      $s6 = "github.com/jpillora/chisel/server.init" fullword ascii
      $s7 = "Fingerprints are generated by hashing the ECDSA public key using" fullword ascii
      $s8 = "golang.org/x/sync/errgroup.(*Group).Wait-fm" fullword ascii
      $s9 = "net/http.(*http2ClientConn).roundTrip.func2" fullword ascii
      $s10 = "Fingerprint mismatches will close the connection." fullword ascii
      $s11 = "runtime.(*pollDesc).makeArg" fullword ascii
      $s12 = "tryChunkOf" fullword ascii
      $s13 = "makeArg" fullword ascii
      $s14 = "verifyLegacyFingerprint" fullword ascii
      $s15 = "parkingOnChan" fullword ascii
      $s16 = "waiterMux" fullword ascii
      $s17 = "SHA256 and encoding the result in base64." fullword ascii
      $s18 = "Fingerprints must be 44 characters containing a trailing equals (=)." fullword ascii
      $s19 = " protocol defaults to tcp." fullword ascii
      $s20 = "(*struct { F uintptr; R *errgroup.Group }" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.5, chiselv1.7.4, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash2 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash3 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $x1 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $s2 = "anProcessingRIPEMD-160RST_STREAMSHA256-RSASHA384-RSASHA512-RSASaurashtraSet-CookieUser-AgentWS_TIMEOUT[:^alnum:][:^alpha:][:^asc" ascii
      $s3 = "hostinvalid request descriptorinvalid value; expected %smalformed HTTP status codemalformed chunked encodingname not unique on n" ascii
      $s4 = "thinteger overflow on token internal error: bad Writerinvalid argument to Int31ninvalid argument to Int63ninvalid port %q after " ascii
      $s5 = "internal/poll.kernelVersion" fullword ascii
      $s6 = ": exceeds input sizeprotocol error: received DATA on a HEAD requestracy sudog adjustment due to parking on channelreflect.Value." ascii
      $s7 = "gc: unswept spangcshrinkstackoffglobalRequestMsghost unreachablehostLookupOrder=integer overflowinvalid argumentinvalid encoding" ascii
      $s8 = "ficate chaintls: incorrect renegotiation extension contentstls: internal error: pskBinders length mismatchtls: server selected T" ascii
      $s9 = "etworknet/http: request canceledno CSI structure availableno message of desired typenon sequence tagged as setnotewakeup - doubl" ascii
      $s10 = "runtime.sigsave" fullword ascii
      $s11 = "sed the connection; LastStreamID=%v, ErrCode=%v, debug=%qtls: handshake hash for a client certificate requested after discarding" ascii
      $s12 = "freedefer with d.fn != nilgob: local interface type http2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii
      $s13 = "9859f741e082542a385502f25dbf55296c3a545e3872760ab7b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed1" ascii
      $s14 = "invalid exchangeinvalid g statusinvalid rune %#Uinvalid spdelta length too largemSpanList.insertmSpanList.removemessage too long" ascii
      $s15 = "9d2a85c8edd3ec2aefHTTP/1.1 101 Switching Protocols" fullword ascii
      $s16 = " the handshake buffertls: unsupported certificate: private key is *ed25519.PrivateKey, expected ed25519.PrivateKey3617de4a96262c" ascii
      $s17 = "countered a cycle via %sentersyscall inconsistent expected complex; found %sexpected integer; found %sforEachP: P did not run fn" ascii
      $s18 = "e wakeupout of memory (stackalloc)persistentalloc: size == 0read from empty dataBufferreadLoopPeekFailLocked: %vreflect.Value.Ca" ascii
      $s19 = "rmat)Specified deprecated MD5 fingerprint (%s), please update to the new SHA256 fingerprint: %shttp2: server sent GOAWAY and clo" ascii
      $s20 = "6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5faa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash5 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash6 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "ebsocket protocol: request method is not GETx509: signature algorithm specifies an %s public key, but have public key of type %T" ascii
      $s2 = ".org/s/cgihttpproxywebsocket: application specific 'Sec-WebSocket-Extensions' headers are unsupportedx509: a root or intermediat" ascii
      $s3 = "http: WriteHeader called with both Transfer-Encoding of %q and a Content-Length of %dreflect.Value.Interface: cannot return valu" ascii
      $s4 = "eboxwebsocket: not a websocket handshake: 'Sec-WebSocket-Key' header is missing or blankwebsocket: the client is not using the w" ascii
      $s5 = "ut leaf contains unknown or unconstrained name: tls: downgrade attempt detected, possibly due to a MitM attack or a broken middl" ascii
      $s6 = "nable to satisfy %q for domain %q: no viable challenge type foundrefusing to use HTTP_PROXY value in CGI environment; see golang" ascii
      $s7 = "os/user.(*User).GroupIds" fullword ascii
      $s8 = "net.absDomainName" fullword ascii
      $s9 = "os/user.listGroups" fullword ascii
      $s10 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $s11 = "crypto/rand.warnBlocked" fullword ascii
      $s12 = "net/dnsclient.go" fullword ascii
      $s13 = "e certificate is not authorized to sign for this name:  (possibly because of %q while trying to verify candidate authority certi" ascii
      $s14 = "t be specified in the tls.Configx509: invalid signature: parent certificate cannot sign this kind of certificateacme/autocert: u" ascii
      $s15 = "@(H9J t" fullword ascii
      $s16 = "J H9H u" fullword ascii
      $s17 = "9chunf" fullword ascii
      $s18 = ";PATCf" fullword ascii
      $s19 = "ficate %q)json: invalid use of ,string struct tag, trying to unmarshal unquoted value into %vx509: issuer has name constraints b" ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0.exe, chiselv1.7.4.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $s1 = "ivedexpiresfloat32float64forcegcgctracehead = http-01http://integerinvalidkey of lookup mailto:new-regnil keynop -> nosniffnumbe" ascii
      $s2 = "acceptactivechan<-chiselclientclosedconfigcookiedefinedomainefenceempty expectformatgopherhangupheaderip+netkilledlistenmethodmi" ascii
      $s3 = "value=_getwchabortedalt -> any -> arcfourbackendbdoUxXvbooleancharsetchisel-chunkedcommandcomplexconn#%dconnectconsolecpuprofder" ascii
      $s4 = "expectedssh: public key not on curvessh: server has no host keysssh: unsupported key type %Tssh: unsupported key type %qstrconv:" ascii
      $s5 = "n tls: failed to sign handshake: tls: no certificates configuredtls: unsupported public key: %Ttoo many authentication methodsto" ascii
      $s6 = "o decode remote '%s': %sMapIter.Value called before NextWSAGetOverlappedResult not found\" not supported for cpu option \"acme: " ascii
      $s7 = "reflect: In of non-func type reflect: Key of non-map type reflect: Out of non-func typeruntime.semasleep wait_failedruntime: imp" ascii
      $s8 = "o commit pagesruntime: split stack overflow: signal_recv: inconsistent stateslice bounds out of range [%x:]slice bounds out of r" ascii
      $s9 = "nutenumberobjectpopcntprintfreadatremoverenamerune1 schemesecondselectserversocketsocks socks5statusstringstructsweep sysmonteln" ascii
      $s10 = "o many transfer encodings: %qunterminated character constantvalue has type %s; should be %swriteBytes with unfinished bitsx509: " ascii
      $s11 = "ossible type kindruntime: levelShift[level] = runtime: marking free object runtime: p.gcMarkWorkerMode= runtime: split stack ove" ascii
      $s12 = "ange [:%x]sotypeToNet unknown socket typessh: DH parameter out of boundsssh: elliptic.Unmarshal failuressh: max packet length ex" ascii
      $s13 = "ceededssh: remote side wrote too muchssh: unhandled elliptic curve: ssh: unsupported ecdsa key sizetime: missing unit in duratio" ascii
      $s14 = "of non-array type reflect: NumIn of non-func typeresetspinning: not a spinning mruntime: cannot allocate memoryruntime: failed t" ascii
      $s15 = "certificate is valid for {\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"} (types from different packages)2842170943040400743484497070" ascii
      $s16 = "-year does not match dayAssociate to %v blocked by rulesCertAddCertificateContextToStoreCertVerifyCertificateChainPolicyFailed t" ascii
      $s17 = "rtificate chain is emptybad input point: low order pointbootstrap type already present: bufio: invalid use of UnreadBytebufio: i" ascii
      $s18 = "nvalid use of UnreadRunebufio: tried to fill full buffercannot represent time as UTCTimechacha20: invalid buffer overlapchacha20" ascii
      $s19 = "9;&amp;+0330+0430+0530+0545+0630+0845+1030+1245+1345, ..., fp:-0930.eEpP.html.jpeg.json.wasm.webp1562578125:***@:\\d+$:http:path" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_windows_386, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash4 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash5 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash6 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
      hash7 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %qwebsocket: the client " ascii
      $s2 = "n switchedtls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the follow" ascii
      $s3 = "cket protocol: 'upgrade' token not found in 'Connection' headerhttp2: Transport: cannot retry err [%v] after Request.Body was wr" ascii
      $s4 = "h GODEBUG=x509ignoreCN=0HTTP/1.1 431 Request Header Fields Too Large" fullword ascii
      $s5 = "itten; define Request.GetBody to avoid this error3940200619639447921227904010014361380507973927046544666794829340424572177149687" ascii
      $s6 = "ef451fd46b503f0011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c" ascii
      $s7 = "24088be94769fd16650x509: certificate relies on legacy Common Name field, use SANs or temporarily enable Common Name matching wit" ascii
      $s8 = "wing types: %vtls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have bee" ascii
      $s9 = "e7e31c2e5bd66051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1" ascii
      $s10 = "8152294913554433653942643tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the fol" ascii
      $s11 = "internal/poll.ignoringEINTR" fullword ascii
      $s12 = "g types: %vc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97" ascii
      $s13 = "8CONNu" fullword ascii
      $s14 = "03290472660882589380018616069731123193940200619639447921227904010014361380507973927046544666794690527962765939911326356939895630" ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.4.exe, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $x1 = " is unavailable not a function()<>@,;:\\\"/[]?=,M3.2.0,M11.1.00601021504Z0700400 Bad Request476837158203125: cannot parse <inval" ascii
      $s2 = "CS1WithSHA384PKCS1WithSHA512Partial ContentProcess32FirstWPsalter_PahlaviRSA PRIVATE KEYRegCreateKeyExWRegDeleteValueWRequest Ti" ascii
      $s3 = "unreachableuserenv.dllvalue for \"websocket: wsarecvfrom (sensitive) = struct {  KiB total,  PRIVATE KEY [recovered] allocCount " ascii
      $s4 = "ailed to load FlushViewOfFileGateway TimeoutGetAdaptersInfoGetCommandLineWGetProcessTimesGetStartupInfoWHalfClosedLocalHanifi_Ro" ascii
      $s5 = "ime: P runtime: p scheddetailsecur32.dllshell32.dllshort writessh-ed25519stack tracetls-alpn-01tls: alert(tracealloc(traffic upd" ascii
      $s6 = "rsianOld_SogdianOpenProcessPRIVATE KEYPau_Cin_HauRegCloseKeyRetry-AfterReturn-PathSHA-512/224SHA-512/256SSH_TIMEOUTSetFileTimeSi" ascii
      $s7 = "hingyaIdempotency-KeyImpersonateSelfLength RequiredNot ImplementedOpenThreadTokenOther_LowercaseOther_UppercasePKCS1WithSHA256PK" ascii
      $s8 = "gc: unswept spangcshrinkstackoffglobalRequestMsghost unreachableinteger overflowinvalid argumentinvalid encodinginvalid exchange" ascii
      $s9 = "meoutUnbound proxiesUnmapViewOfFileX-Forwarded-For[ERR] socks: %v]" fullword ascii
      $s10 = "s Standard TimeNewfoundland Standard TimePostQueuedCompletionStatusReverse tunnelling enabledSaint Pierre Standard TimeServer ca" ascii
      $s11 = "found at *( gcscandone  m->gsignal= minTrigger= nDataRoots= nSpanRoots= pages/byte" fullword ascii
      $s12 = "gnWritingSoft_DottedTESTING KEYTTL expiredVirtualLockWSARecvFromWarang_CitiWhite_Space[:^xdigit:]alarm clockassistQueueaudio/bas" ascii
      $s13 = " Value>ASCII_Hex_DigitAccept-EncodingAccept-LanguageClientAuthType(CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find F" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $s1 = "rtCloseStoreContent-LengthCreateProcessWCryptGenRandomDkim-SignatureEC PRIVATE KEYFindFirstFileWFingerprint %sFormatMessageWGC a" ascii
      $s2 = "d remoteMAX_FRAME_SIZEMB; allocated NetUserGetInfoNot AcceptableOther_ID_StartPROTOCOL_ERRORPattern_SyntaxProcess32NextWQuotatio" ascii
      $s3 = "edcontent-lengthdata truncatedfile too largefinalizer waitgcstoptheworldgetprotobynameinternal errorinvalid configinvalid method" ascii
      $s4 = "connectionstack overflowstopm spinningstore64 failedsync.Cond.Waittext file busytoo many linkstoo many usersunexpected EOFunknow" ascii
      $s5 = "ssist waitGC worker initGetConsoleModeGetProcAddressGetUserNameExWHandshaking...INTERNAL_ERRORInstEmptyWidthInvalid JSON: Invali" ascii
      $s6 = "n_MarkRCodeNameErrorREFUSED_STREAMREQUEST_METHODRegSetValueExWSending configSetFilePointerTranslateNameW\" out of range\\.+*?()|" ascii
      $s7 = " such devicepollCache.lockprotocol errorread error: %sread error: %wruntime: full=s.allocCount= semaRoot queuesource-addressssh-" ascii
      $s8 = "default %q) (default %v) MB) workers= called from  flushedWork  heap_marked= idlethreads= in duration  in host name is nil, not " ascii
      $s9 = "invalid syntaxis a directorykey size wronglen of type %slevel 2 haltedlevel 3 haltedneed more datanil elem type!no module datano" ascii
      $s10 = "{}^$accept-charsetallocfreetracebad allocCountbad record MACbad span statebad stack sizechannelDataMsgchannelOpenMsgconnect fail" ascii
      $s11 = "n code: unknown error unknown methodunknown mode: unknown node: unreachable:  unsafe.Pointerwinapi error #work.full != 0x509igno" ascii
      $s12 = "reCN=0zero parameter  with GC prog" fullword ascii
      $s13 = " nStackRoots= out of range s.spanclass= span.base()= syscalltick= work.nproc=  work.nwait= , gp->status=, not pointer-byte block" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.4.exe, chiselv1.7.5.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash4 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $s1 = "agriTransmitFileUDP_DEADLINEUnauthorizedUnlockFileExWS_BUFF_SIZEX-ImforwardsX-Powered-Byabi mismatchadvapi32.dllaltmatch -> anyn" ascii
      $s2 = "ISEL_CONNECTChanDirConvertCopySidCreatedCypriotDeseretEd25519ElbasanElymaicExpiresGODEBUGGive upGranthaHEADERSHanunooIM UsedIO w" ascii
      $s3 = "Standard TimeFailed to authenticate: %vGODEBUG: can not disable \"GetFileInformationByHandleHTTP Version Not SupportedLine Islan" ascii
      $s4 = "isten on %sConfig verification failedDenied outbound connectionE. Australia Standard TimeECDSA verification failureEkaterinburg " ascii
      $s5 = "DSA-SHA1DecemberDuployanEthiopicExtenderFebruaryFullPathGeorgianGoStringGujaratiGurmukhiHTTP/1.1HTTP/2.0HiraganaInstFailInstRune" ascii
      $s6 = "aitInstAltInstNopJanuaryKannadaMD2-RSAMD5-RSAMUI_DltMUI_StdMakasarMandaicMarchenMultaniMyanmarOctoberOpen %sOsmanyaPRIVATERadica" ascii
      $s7 = "TifinaghTrailer:TypeAAAATypeAXFRUgariticUsernameWSAIoctl[:word:][signal " fullword ascii
      $s8 = "r slice using unaddressable value using zero Value argument(\\[[^\\[\\]]+\\]|[^\\[\\]:]+):?1455191522836685180664062572759576141" ascii
      $s9 = "Phags_PaQuestionReadFileReceivedSETTINGSSHA1-RSASHA3-224SHA3-256SHA3-384SHA3-512SSH_WAITSaturdayTagbanwaTai_ThamTai_VietThursday" ascii
      $s10 = "pper:][:xdigit:]_reserved1acme-tls/1aes128-cbcaes128-ctraes192-ctraes256-ctrarcfour128arcfour256arg %d: %satomicand8audio/aiffau" ascii
      $s11 = "rtupWS_TIMEOUT[:^alnum:][:^alpha:][:^ascii:][:^blank:][:^cntrl:][:^digit:][:^graph:][:^lower:][:^print:][:^punct:][:^space:][:^u" ascii
      $s12 = "033203125: day-of-year out of rangeBougainville Standard TimeCentral Asia Standard TimeCertFreeCertificateContextClient cannot l" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.4.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash2 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $s1 = "NFIG_TIMEOUTCertCloseStoreContent-LengthCreateProcessWCryptGenRandomDkim-SignatureEC PRIVATE KEYFindFirstFileWFingerprint %sForm" ascii
      $s2 = "d JSON: Invalid remoteMAX_FRAME_SIZEMB; allocated NetUserGetInfoNot AcceptableOther_ID_StartPROTOCOL_ERRORPattern_SyntaxProcess3" ascii
      $s3 = "chan receiveclose notifycontent-typecontext.TODOdumping heapend tracegc" fullword ascii
      $s4 = "sgconnect failedcontent-lengthdata truncatedfile too largefinalizer waitgcstoptheworldgetprotobynameinternal errorinvalid config" ascii
      $s5 = "mKeyExWRegEnumValueWRegOpenKeyExWReset ContentSHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSSSSH cancelledSSH connectedSTREAM_CLOSEDUsag" ascii
      $s6 = "atMessageWGC assist waitGC worker initGetConsoleModeGetProcAddressGetUserNameExWHandshaking...INTERNAL_ERRORInstEmptyWidthInvali" ascii
      $s7 = "2NextWQuotation_MarkRCodeNameErrorREFUSED_STREAMREQUEST_METHODRegSetValueExWSending configSetFilePointerTranslateNameW\" out of " ascii
      $s8 = "rolCertOpenStoreContent-RangeECDSAWithSHA1FQDN too longFindFirstFileFindNextFileWFreeAddrInfoWGC sweep waitGunjala_GondiIf-None-" ascii
      $s9 = "otnl -> bad flushGenbad g statusbad g0 stackbad recoveryblock clausec ap trafficc hs trafficcaller errorcan't happencas64 failed" ascii
      $s10 = "MatchLast-ModifiedLoop DetectedMapViewOfFileMasaram_GondiMende_KikakuiMissing portsOld_HungarianPKCS1WithSHA1RegDeleteKeyWRegEnu" ascii
      $s11 = "e of %s:" fullword ascii
      $s12 = "ange\\.+*?()|[]{}^$accept-charsetallocfreetracebad allocCountbad record MACbad span statebad stack sizechannelDataMsgchannelOpen" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.4.exe, chiselv1.7.4"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash2 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
   strings:
      $s1 = "D$htlH" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "%%%%%!! !%% %! " fullword ascii
      $s3 = ";\"4V3\"4 " fullword ascii
      $s4 = "0<0982" fullword ascii
      $s5 = "b&ffn>~." fullword ascii
      $s6 = "1M(NCM" fullword ascii
      $s7 = "2$1>4$31" fullword ascii
      $s8 = "%%$ !%%$" fullword ascii
      $s9 = "<<==>>" fullword ascii
      $s10 = "------()))))--" fullword ascii
      $s11 = "!)!#  " fullword wide
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash4 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash5 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash6 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "bad special kindbad summary databad symbol tablebinary.BigEndiancastogscanstatusconnection abortcontent-encodingcontent-language" ascii
      $s2 = "content-locationcontext canceleddecode error: %wdivision by zeroencode error: %sencode error: %wexpected integerexpected newline" ascii
      $s3 = "00004821" ascii
      $s4 = " \"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"" fullword ascii
      $s5 = "XPM9XHuZM" fullword ascii
      $s6 = ";stdiu" fullword ascii
      $s7 = "0846049" ascii
      $s8 = "-,,,,(((--" fullword ascii
      $s9 = "WPH9GXtTH" fullword ascii
      $s10 = "AAA@@AA" fullword ascii
      $s11 = "\" !0 0" fullword wide
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.5, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash3 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "6SHA-384SHA-512SharadaShavianSiddhamSignal SinhalaSogdianSoyomboSubjectSwapperTagalogTibetanTirhutaTrailerTuesdayTypeALLTypeOPTT" ascii
      $s2 = "ypePTRTypeSOATypeSRVTypeTXTTypeWKSUNKNOWNUpgradeUsage:" fullword ascii
      $s3 = "setReadRemaining0" fullword ascii
      $s4 = "advanceFrame0" fullword ascii
      $s5 = "handleProtocolError0" fullword ascii
      $s6 = "beginMessage0" fullword ascii
      $s7 = "writeFatal0" fullword ascii
      $s8 = "writeBufs0" fullword ascii
      $s9 = "write0" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "33WTTT" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.5.exe, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash5 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash6 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=-byte limit" fullword ascii
      $s2 = "generaliL9" fullword ascii
      $s3 = "helpuGH" fullword ascii
      $s4 = "HHH9JH" fullword ascii
      $s5 = "9HxtaH" fullword ascii
      $s6 = "L$(uyH" fullword ascii
      $s7 = "K(H9H(" fullword ascii
      $s8 = "Z0H9J(t" fullword ascii
      $s9 = "D$PH9D$" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash2 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash3 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash4 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "tls: client sent invalid key share in second ClientHellotls: no cipher suite supported by both client and serverviolation of Wri" ascii
      $s2 = " cannot include pseudo header %qptrEncoder.encode should have emptied ptrSeen via defersssh: client attempted to negotiate for u" ascii
      $s3 = "nown errorunknown timerunsupported: user canceledvalue method xadd64 failedxchg64 failed}" fullword ascii
      $s4 = "teScheduler interface: unknown stream %dwebsocket: client sent data before handshake is completex509: internal error: empty chai" ascii
      $s5 = "nknown service: strings: illegal use of non-zero Builder copied by valuetls: TLS 1.3 client supports illegal compression methods" ascii
      $s6 = "n when appending CA certGobDecoder: invalid data length %d: exceeds input size %dacme/autocert: invalid new order status %q; ord" ascii
      $s7 = "lue net/http: abort Handlernetwork not implementedno application protocolno space left on devicenon-function of type %snon-zero " ascii
      $s8 = "er URL: %qbackend tried to switch protocol %q when %q was requestedcan't handle assignment of %s to empty interface argumentgent" ascii
      $s9 = "PH9PHt(L9" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.4, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash4 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash5 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash6 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $s1 = "9httpf" fullword ascii
      $s2 = "H9L$Pw" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "rPH9JX" fullword ascii
      $s4 = "H 9J u" fullword ascii /* Goodware String - occured 4 times */
      $s5 = "L$XH9L$ t=H" fullword ascii
      $s6 = "L$XH9L$ tIH" fullword ascii
      $s7 = "t$BfE9" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.5, chiselv1.7.4, chisel_1.7.6_windows_386, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash3 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash4 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash5 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash6 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
      hash7 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "with %d args; should be 1 or 2http2: Transport creating client conn %p to %vhttps://acme-v02.api.letsencrypt.org/directoryintern" ascii
      $s2 = "s than one physical page of memoryrequest Content-Type isn't multipart/form-dataruntime: failed to create new OS thread (have ru" ascii
      $s3 = "tes)math/big: mismatched montgomery number lengthsmemory reservation exceeds address space limitnet/http: internal error: misuse" ascii
      $s4 = "al error: cannot create stream with id 0invalid slice length %d: exceeds input size %dlength of string exceeds input size (%d by" ascii
      $s5 = " of tryDelivernet/http: too many 1xx informational responsespanicwrap: unexpected string after type name: reflect.Value.Slice: s" ascii
      $s6 = "lice index out of boundsreflect: nil type passed to Type.ConvertibleToreflect: slice capacity out of range in SetCapreleased les" ascii
      $s7 = "ust equal block sizecrypto/rand: prime size must be at least 2-bitfirst path segment in URL cannot contain colonfunction called " ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash4 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash5 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $s1 = "esk-ssh-ed25519-cert-v01@openssh.comssh: extended code %d unimplementedssh: failed to unmarshal public keyssh: invalid packet le" ascii
      $s2 = "s (main called runtime.Goexit) - deadlock!quotedprintable: invalid unescaped byte 0x%02x in bodyread loop ending; caller owns wr" ascii
      $s3 = "ngth multiplessh: junk character in version linessh: no key material for msgNewKeysssh: parse error in message type %dstrings.Re" ascii
      $s4 = "ader.Seek: invalid whencesuperfluous leading zeros in lengthtls: invalid or missing PSK binderstls: server selected an invalid P" ascii
      $s5 = "SKtls: too many non-advancing recordstoo many Questions to pack (>65535)traceback did not unwind completelytransform: short dest" ascii
      $s6 = "nic during mallocpanic during panic" fullword ascii
      $s7 = "overflow on character value pending ASN.1 child too longprotocol driver not attachedreflect.MakeSlice: len > capreflect: In of n" ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.5, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_linux_amd64"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "1ce4f6c3d7a7cfec944c54de9bbd55e4658a500019e93fc66cdfb4dcae914e8b"
      hash4 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash5 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash6 = "15617edf0c8fc4c75814f7ea6695441015829afcd5ce3ceabf7ee08c2e8d8cad"
   strings:
      $s1 = "nssh.comssh: padding not as expectedssh: public key not on curvessh: server has no host keysssh: unsupported key type %Tssh: uns" ascii
      $s2 = "upported key type %qstrconv: " fullword ascii
      $s3 = ":HEADf" fullword ascii
      $s4 = "9tcp4f" fullword ascii
      $s5 = "O09H0v0H9x" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.4, chiselv1.7.5.exe"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash4 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
   strings:
      $s1 = ") (abnormal closure) (policy violation) (unsupported data) already registered called using nil *,  g->atomicstatus=, gp->atomics" ascii
      $s2 = "sPH9rPu" fullword ascii
      $s3 = "H9PHt(L9" fullword ascii
      $s4 = "H9Q0umH" fullword ascii
      $s5 = "9CONNf" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule Hacktool_PUA_Chisel_TCP_Tunneling {
   meta:
      description = "Detect Chisel TCP tunneling (stock version) - from files chiselv1.7.0, chisel_1.7.6_windows_amd64, chiselv1.7.0.exe, chiselv1.7.4.exe, chiselv1.7.4, chiselv1.7.5.exe, chisel_1.7.6_windows_386"
      author = "faisalfs10x"
      reference = "https://github.com/jpillora/chisel/"
      date = "2021-09-24"
      hash1 = "9a13f1911088f749d136fc6693f448a134384635d6fa0e2e4681521ac40e74fc"
      hash2 = "4afa5fde76f1f3030cf7dbd12e37b717e1f902ac95c8bdf54a2e58a64faade04"
      hash3 = "acaf8d55ffcb950880172d71623349dc7fd5449a61c7fb09fa0ee25bb1df4b90"
      hash4 = "b6ecdcc0b98932f1cfeb0ac051a4f16eb445cb1fc36ce37afb2f601a0df4d880"
      hash5 = "aa573683db4ac3771729b378f282d9827856b0c48237a29019d8649b408f6e56"
      hash6 = "2b46dbbe5f9ddd3cbf096cf0263a49e37d23c225c689e65627d08f983437ec25"
      hash7 = "fb01b1be5585a6ed51f4181c978c0dbb5383eccfc348cdb385a74d3a622ee5a5"
   strings:
      $s1 = "oPointerMask: overflowrange can't iterate over %vreflect.Value.OverflowFloatrunlock of unlocked rwmutexruntime: asyncPreemptStac" ascii
      $s2 = "of rangemakeslice: cap out of rangemakeslice: len out of rangemap has no entry for key %qmspan.sweep: bad span statenet/http: in" ascii
      $s3 = "valid method %qnet/http: use last responsenot a XENIX named type fileonly TCP SOCKS is supportedpointer to unsupported typeprogT" ascii
      $s4 = "k=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: corrupted polldescruntime: netpollinit failedruntime: thread ID" ascii
      $s5 = " overflowruntime" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

