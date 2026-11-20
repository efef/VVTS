<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Types\DnsTransactionMapEntry;

class DnsMitm extends Subscribable implements IUnblockable {
    function Signal($szSignal, ...$aArguments) {
        if ($szSignal === "dns_err") {
            self::Log("ERROR: %s", isset($aArguments[0]) ? $aArguments[0] : "(no message)");
        } else {
            self::Log("signal %s", $szSignal);
        }
        return parent::Signal($szSignal, ...$aArguments);
    }

    var $hListeningSocket;
    var $hClientSocket;
    var $szNextDns;
    var $aTransactionMap;
    var $aOverridesA;
    var $aOverridesAAAA;
    var $dwBindAddr;
    var $abBindIpv6Addr;

    /* Debug logging. Prints to the console, and also appends to the file named in
     * the VVTS_DNS_LOG environment variable when set (e.g. VVTS_DNS_LOG=/tmp/vvts-dns.log). */
    static function Log($szFormat, ...$aArgs) {
        $szLine = sprintf("[dns %s] ", date("H:i:s")) . vsprintf($szFormat, $aArgs) . "\n";
        echo $szLine;
        $szFile = getenv("VVTS_DNS_LOG");
        if ($szFile !== false && $szFile !== "") {
            @file_put_contents($szFile, $szLine, FILE_APPEND);
        }
    }

    static function LastPhpError() {
        $aErr = error_get_last();
        return ($aErr === null) ? "no further detail from php" : $aErr["message"];
    }

    static function DescribeQuery(&$abBuf) {
        if (strlen($abBuf) < 12) {
            return sprintf("short packet (%d bytes)", strlen($abBuf));
        }
        $wFlags = (ord($abBuf[2]) << 8) | ord($abBuf[3]);
        $wQd = (ord($abBuf[4]) << 8) | ord($abBuf[5]);
        $wAn = (ord($abBuf[6]) << 8) | ord($abBuf[7]);
        $szName = "?";
        $szType = "?";
        if ($wQd > 0) {
            $dwOffset = 12;
            $szName = @self::ParseDomainName($abBuf, $dwOffset);
            if ($dwOffset + 1 < strlen($abBuf)) {
                $wType = (ord($abBuf[$dwOffset]) << 8) | ord($abBuf[$dwOffset + 1]);
                $aTypes = [1 => "A", 28 => "AAAA", 5 => "CNAME", 12 => "PTR", 15 => "MX", 16 => "TXT", 33 => "SRV", 65 => "HTTPS", 64 => "SVCB"];
                $szType = isset($aTypes[$wType]) ? $aTypes[$wType] : strval($wType);
            }
        }
        $aRcodes = [0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED"];
        $wRcode = $wFlags & 0xf;
        return sprintf("id=0x%04x %s %s%s", (ord($abBuf[0]) << 8) | ord($abBuf[1]), $szName, $szType,
            ($wFlags & 0x8000) ? sprintf(" rcode=%s answers=%d%s", isset($aRcodes[$wRcode]) ? $aRcodes[$wRcode] : $wRcode, $wAn, ($wFlags & 0x0200) ? " TRUNCATED" : "") : "");
    }

    function __construct() {
        parent::__construct();
        $this->aTransactionMap = [];
        $this->aOverridesA = [];
        $this->aOverridesAAAA = [];

        MainLoop::GetInstance()->RegisterObject($this);
    }

    static function ParseDomainName(&$abRequest, &$dwOffset) {
        $szName = "";
        $bSetOffset = true;
        $dwCurOffset = $dwOffset;

        for(;;) {
            $bSegmentLength = ord($abRequest[$dwCurOffset]); $dwCurOffset++;
            if ($bSegmentLength == 0) {
                break;
            }
            if (($bSegmentLength & 0xc0) == 0xc0) {
                if ($bSetOffset) {
                    $dwOffset = $dwCurOffset + 1;
                    $bSetOffset = false;
                }
                $dwCurOffset = (($bSegmentLength & 0x3f) << 8) | ord($abRequest[$dwCurOffset]);
                continue;
            }
            $szName .= (strlen($szName) == 0) ? "" : ".";
            for($j = 0; $j < $bSegmentLength; $j++, $dwCurOffset++) {
                $szName .= $abRequest[$dwCurOffset];
            }
        }

        if ($bSetOffset) {
            $dwOffset = $dwCurOffset;
        }
        return $szName;
    }

    function GenerateResponse(&$abRequest, $szPeer) {
        $wQdCount = (ord($abRequest[4]) << 8) | ord($abRequest[5]);
        $dwOffset = 12;
        $wFlags = (ord($abRequest[2]) << 8) | ord($abRequest[3]);
        $wOffsetCorrect = 0;
        $wAdCount = (ord($abRequest[6]) << 8) | ord($abRequest[7]);

        $bIsARequested = false;
        $bIsAAAARequested = false;
        $szDomainName = null;
        $dwDomainNameOffset = null;

        for ($i = 0; $i < $wQdCount; $i++) {
            $dwOffsetPreDomainName = $dwOffset;
            $szName = self::ParseDomainName($abRequest, $dwOffset);
            $wType = (ord($abRequest[$dwOffset]) << 8) | ord($abRequest[$dwOffset+1]);
            $dwOffset += 2;
            $wClass = (ord($abRequest[$dwOffset]) << 8) | ord($abRequest[$dwOffset+1]);
            $dwOffset += 2;

            // printf ("[i] received DNS %s from %s for %s type=%s class=%s\n", ($wFlags & 0x8000) ? "response" : "request", $szPeer, $szName, ($wType == 1) ? "A" : "unknown", ($wClass == 1) ? "IN" : "unknown");

            if ($wType !== 1 && $wType !== 28) {
                continue;
            }

            if ($szDomainName !== null && $szName !== $szDomainName) {
                printf("[!] received single DNS query for both %s and %s from %s -- not supported\n", $szDomainName, $szName, $szPeer);
                return null;
            }
            $szDomainName = $szName;
            $dwDomainNameOffset = $dwOffsetPreDomainName;
            if ($wType === 1 && isset($this->aOverridesA[strtolower($szName)])) {
                $bIsARequested = true;
            } else if ($wType === 28 && isset($this->aOverridesAAAA[strtolower($szName)])) {
                $bIsAAAARequested = true;
            }
        }

        if ($szDomainName === null || $wFlags & 0x8000 || (
            !isset($this->aOverridesA[strtolower($szDomainName)]) &&
            !isset($this->aOverridesAAAA[strtolower($szDomainName)])
        )) {
            /* no overrides set for this domain -> pass through to real DNS server */
            return null;
        }

        $wResponseFlags = $wFlags | 0x8080; /* 0x8000 -> is dns response, 0x80 -> recursion supported */

        $abResponse = substr($abRequest, 0, 2); /* transaction id */
        $abResponse .= chr($wResponseFlags >> 8) . chr($wResponseFlags); /* flags */
        $abResponse .= substr($abRequest, 4, 2); /* number of queries */
        $abResponse .= "\x00" . chr($bIsAAAARequested + $bIsARequested); /* number of answers */
        $abResponse .= "\x00\x00"; /* number of authority RRs */
        $abResponse .= "\x00\x00"; /* number of additional RRs */
        $abResponse .= substr($abRequest, 12, $dwOffset - 12);
        
        if ($bIsARequested) {
            $szOverride = $this->aOverridesA[strtolower($szDomainName)];
            printf("[i] applying DNS response override for %s: %s\n", $szDomainName, $szOverride);
            $dwOverride = MiscNet::Ipv4StringToDword($szOverride);
            $abOverride = chr($dwOverride >> 24) . chr($dwOverride >> 16) . chr($dwOverride >> 8) . chr($dwOverride);

            $abResponse .= "\xc0" . chr($dwDomainNameOffset); /* refer to domain name in query */
            $abResponse .= "\x00\x01"; /* type: A */
            $abResponse .= "\x00\x01"; /* class: IN */
            $abResponse .= "\x00\x00\x0e\x10"; /* TTL: 3600s */
            $abResponse .= "\x00\x04"; /* data len: 4 */
            $abResponse .= $abOverride;
        }
        if ($bIsAAAARequested) {
            $szOverride = $this->aOverridesAAAA[strtolower($szDomainName)];
            printf("[i] applying DNS response override for %s: %s\n", $szDomainName, $szOverride);
            $abOverride = MiscNet::Ipv6StringToBinary($szOverride);

            $abResponse .= "\xc0" . chr($dwDomainNameOffset); /* refer to domain name in query */
            $abResponse .= "\x00\x1c"; /* type: AAAA */
            $abResponse .= "\x00\x01"; /* class: IN */
            $abResponse .= "\x00\x00\x0e\x10"; /* TTL: 3600s */
            $abResponse .= "\x00\x10"; /* data len: 16 */
            $abResponse .= $abOverride;
        }

        return $abResponse;
    }

    function SetOverride($szDomainName, $szAddress) {
        if (MiscNet::Ipv4StringToDword($szAddress) !== false) {
            $this->aOverridesA[strtolower($szDomainName)] = $szAddress;
        } else if (MiscNet::Ipv6StringToBinary($szAddress) !== false) {
            $this->aOverridesAAAA[strtolower($szDomainName)] = $szAddress;
        }
    }

    function Sockets() {
        $ahSockets = [];
        if ($this->hListeningSocket != null) {
            array_push($ahSockets, $this->hListeningSocket);
        }
        if ($this->hListeningIpv6Socket != null) {
            array_push($ahSockets, $this->hListeningIpv6Socket);
        }
        if ($this->hClientSocket != null) {
            array_push($ahSockets, $this->hClientSocket);
        }
        return $ahSockets;
    }

    function BringUp() {
        if (!isset($this->szNextDns) || $this->szNextDns == null) {
            $szResolvConf = file_get_contents("/etc/resolv.conf");
            if (
                preg_match('/^nameserver\s+([0-9\.]+|[0-9a-f:]+)\s*$/im', $szResolvConf, $aMatch) && (
                    MiscNet::Ipv4StringToDword($aMatch[1]) !== false ||
                    MiscNet::Ipv6StringToBinary($aMatch[1]) !== false
                )
            ) {
                $this->szNextDns = $aMatch[1];
                self::Log("upstream DNS server taken from /etc/resolv.conf: %s", $this->szNextDns);
            } else {
                self::Log("no usable 'nameserver' line in /etc/resolv.conf:\n%s", $szResolvConf === false ? "(unreadable)" : $szResolvConf);
                $this->Signal("dns_err", "Don't know where to forward DNS packets to");
                $this->Teardown();
                return;
            }
        }

        $dwBindAddr = ($this->dwBindAddr === null) ? 0 : $this->dwBindAddr;
        $abBindIpv6Addr = ($this->abBindIpv6Addr === null) ? str_repeat("\x00", 16) : $this->abBindIpv6Addr;
        $szBind4 = "udp://" . MiscNet::DwordToIpv4String($dwBindAddr) . ":53";
        $this->hListeningSocket = @stream_socket_server($szBind4, $dwErrno, $szErrstr, STREAM_SERVER_BIND);
        self::Log("listen %s: %s", $szBind4, $this->hListeningSocket === false ? "FAILED (errno $dwErrno: $szErrstr)" : "ok");
        $szBind6 = "udp://[" . MiscNet::BinaryToIpv6String($abBindIpv6Addr) . "]:53";
        $this->hListeningIpv6Socket = @stream_socket_server($szBind6, $dwErrno, $szErrstr, STREAM_SERVER_BIND);
        self::Log("listen %s: %s%s", $szBind6, $this->hListeningIpv6Socket === false ? "FAILED (errno $dwErrno: $szErrstr)" : "ok",
            ($this->abBindIpv6Addr === null) ? " (optional, ignored on failure)" : "");
        if (MiscNet::Ipv4StringToDword($this->szNextDns) !== false) {
            $this->hClientSocket = @stream_socket_client("udp://" . $this->szNextDns . ":53", $dwErrno, $szErrstr);
        } else {
            $this->hClientSocket = @stream_socket_client("udp://[" . $this->szNextDns . "]:53", $dwErrno, $szErrstr);
        }
        self::Log("upstream socket to %s:53: %s", $this->szNextDns, $this->hClientSocket === false ? "FAILED (errno $dwErrno: $szErrstr)" : "ok");
        foreach ($this->aOverridesA as $szName => $szAddr) { self::Log("override A    %s -> %s", $szName, $szAddr); }
        foreach ($this->aOverridesAAAA as $szName => $szAddr) { self::Log("override AAAA %s -> %s", $szName, $szAddr); }

        if (
            ($this->dwBindAddr !== null && $this->hListeningSocket === false) ||
            ($this->abBindIpv6Addr !== null && $this->hListeningIpv6Socket === false) ||
            $this->hClientSocket === false
        ) {
            $this->Signal("dns_err", "Could not create DNS sockets");
            $this->Teardown();
            return;
        } else {
            $this->Signal("dns_up");
        }
    }

    function Onunblock($hSocket) {
        foreach ($this->aTransactionMap as $dwTrid => $oEntry) {
            if ($oEntry->dwExpire < intval(microtime(1) * 1000)) {
                self::Log("TIMEOUT: no answer from upstream %s within 10s for id=0x%04x (asked by %s)", $this->szNextDns, $dwTrid, $oEntry->szPeer);
                unset($this->aTransactionMap[$dwTrid]);
            }
        }

        error_clear_last();
        $abBuf = @stream_socket_recvfrom($hSocket, 65536, 0, $szPeer);
        if ($abBuf === "" || $abBuf === false) {
            self::Log("receive failed on %s socket (got %s): %s%s",
                ($hSocket === $this->hClientSocket) ? "upstream" : "listening",
                ($abBuf === false) ? "false" : "empty packet",
                self::LastPhpError(),
                ($hSocket === $this->hClientSocket) ? " -- upstream " . $this->szNextDns . " probably refused the query (ICMP port unreachable)" : "");
            $this->Signal("dns_err", "DNS socket closed");
            $this->Teardown();
            return;
        }
        $wTransactionId = (ord($abBuf[0]) << 8) | ord($abBuf[1]);

        if ($hSocket === $this->hListeningSocket || $hSocket === $this->hListeningIpv6Socket) {
            // printf("[i] incoming dns request\n");
            $abResponse = $this->GenerateResponse($abBuf, $szPeer);
            if ($abResponse !== null) {
                self::Log("query from %s: %s -> answered locally (override)", $szPeer, self::DescribeQuery($abBuf));
                error_clear_last();
                $res = @stream_socket_sendto($hSocket, $abResponse, 0, $szPeer);
                if ($res === false || $res < 0) { self::Log("send to client %s failed: %s", $szPeer, self::LastPhpError()); }
            } else {
                /* forward DNS query */
                self::Log("query from %s: %s -> forwarding to %s", $szPeer, self::DescribeQuery($abBuf), $this->szNextDns);
                if (isset($this->aTransactionMap[$wTransactionId])) {
                    self::Log("WARNING: transaction id 0x%04x already pending; earlier query will lose its answer", $wTransactionId);
                }
                $this->aTransactionMap[$wTransactionId] = new DnsTransactionMapEntry($hSocket, $szPeer, intval(microtime(1) * 1000) + 10000);
                error_clear_last();
                $res = @stream_socket_sendto($this->hClientSocket, $abBuf, 0, $this->szNextDns . ":53");
                if ($res === false || $res < 0) { self::Log("send to upstream %s failed: %s", $this->szNextDns, self::LastPhpError()); }
            }
        } else {
            // printf("[i] incoming dns response\n");
            if (!isset($this->aTransactionMap[$wTransactionId])) {
                self::Log("response from upstream with unknown id: %s (late, duplicate, or already timed out)", self::DescribeQuery($abBuf));
            } else {
                self::Log("response from upstream: %s -> to %s", self::DescribeQuery($abBuf), $this->aTransactionMap[$wTransactionId]->szPeer);
                stream_socket_sendto($this->aTransactionMap[$wTransactionId]->hSocket, $abBuf, 0, $this->aTransactionMap[$wTransactionId]->szPeer);
                unset($this->aTransactionMap[$wTransactionId]);
            }
        }
    }

    function Teardown() {
        if ($this->hListeningSocket != null) {
            fclose($this->hListeningSocket);
            $this->hListeningSocket = null;
        }
        if ($this->hListeningIpv6Socket != null) {
            fclose($this->hListeningIpv6Socket);
            $this->hListeningIpv6Socket = null;
        }
        if ($this->hClientSocket != null) {
            fclose($this->hClientSocket);
            $this->hClientSocket = null;
        }
        $this->CancelAllSubscriptions();
    }
}



?>