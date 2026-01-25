from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple
import json
import base64

import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.dnssec


@dataclass
class DnsQueryLog:
    """
    Un rand de jurnal pentru fiecare intrebare DNS trimisa.
    Te ajuta sa vezi "cine" ai intrebat, "ce" ai intrebat, si "ce" ti-a raspuns.
    """
    serverIp: str
    qname: str
    qtype: str
    usedTcp: bool
    rcode: str
    aa: bool
    tc: bool
    answerRrsets: int
    authorityRrsets: int
    additionalRrsets: int
    error: Optional[str] = None


@dataclass
class RrsigInfo:
    """
    Informatii utile dintr-un RRSIG:
    - algorithm: ca sa detectezi algoritmi slabi (mai tarziu)
    - inception/expiration: ca sa detectezi expirari
    """
    owner: str
    coveredType: str
    algorithm: int
    keyTag: int
    signer: str
    inception: int
    expiration: int


@dataclass
class DsDenialProof:
    """
    Dovada DNSSEC ca "nu exista DS".
    In DNSSEC, un raspuns negativ corect vine cu NSEC/NSEC3 + RRSIG in Authority,
    adica "authenticated denial of existence". (RFC 4035)
    """
    rcode: str
    qname: str
    qtype: str
    soaPresent: bool
    nsecRrsets: List[str] = field(default_factory=list)
    nsec3Rrsets: List[str] = field(default_factory=list)
    rrsigInfo: List[RrsigInfo] = field(default_factory=list)


@dataclass
class DelegationLink:
    """
    Un hop (pas) din lantul de delegare: parentZone -> childZone.
    Exemplu: "." -> "com." sau "com." -> "google.com."
    """
    parentZone: str
    childZone: str

    dsRecords: List[dict] = field(default_factory=list)
    dnskeyRecords: List[dict] = field(default_factory=list)

    dsMatchesDnskey: Optional[bool] = None
    status: str = "UNKNOWN"
    details: Optional[str] = None

    dsDenialProof: Optional[DsDenialProof] = None


@dataclass
class InspectorTrace:
    """
    Raportul final pe care il poti salva in JSON.
    Contine:
    - queryLog: toti pasii (audit/debug)
    - delegationChain: fiecare hop + rezultatul DS<->DNSKEY
    - finalAnswerRrsets: raspunsul final (A/AAAA/MX etc.)
    - rrsigInfo: metadate RRSIG colectate pe drum (pentru expirare/algoritmi)
    """
    targetName: str
    targetType: str

    queryLog: List[DnsQueryLog] = field(default_factory=list)
    delegationChain: List[DelegationLink] = field(default_factory=list)

    cnameChain: List[str] = field(default_factory=list)
    finalAnswerRrsets: List[str] = field(default_factory=list)

    rrsigInfo: List[RrsigInfo] = field(default_factory=list)

    chainVerdict: str = "UNKNOWN"
    chainBreakAt: Optional[str] = None
    notes: List[str] = field(default_factory=list)


DEFAULT_ROOT_HINTS_V4 = [
    "198.41.0.4",       # a.root-servers.net
    "170.247.170.2",    # b.root-servers.net
    "192.33.4.12",      # c.root-servers.net
    "199.7.91.13",      # d.root-servers.net
    "192.203.230.10",   # e.root-servers.net
    "192.5.5.241",      # f.root-servers.net
    "192.112.36.4",     # g.root-servers.net
    "198.97.190.53",    # h.root-servers.net
    "192.36.148.17",    # i.root-servers.net
    "192.58.128.30",    # j.root-servers.net
    "193.0.14.129",     # k.root-servers.net
    "199.7.83.42",      # l.root-servers.net
    "202.12.27.33",     # m.root-servers.net
]


class DnssecChainCollector:
    """
    Task-uri Ionut:
    1) Face rezolvare iterativa ca un resolver real:
       pleaca de la root, primeste referral la TLD, apoi la zona finala.
    2) Pune DO bit ca sa primeasca recorduri DNSSEC (RRSIG/DNSKEY/DS/NSEC/NSEC3).
    3) La fiecare delegare, compara DS (din parinte) cu DNSKEY (din copil):
       - daca DS exista si se potriveste: hop-ul e OK (secure delegation)
       - daca DS lipseste: delegare "insecure" (nu e neaparat greseala)
       - daca DS exista dar nu se potriveste: lant rupt (broken)
    4) Cand DS lipseste, salveaza si dovada DNSSEC (NSEC/NSEC3 + RRSIG) ca DS nu exista.
    5) Nu valideaza criptografic semnaturile (asta e Membrul 2), dar colecteaza tot ce trebuie.
    """

    def __init__(
        self,
        rootHintsV4: Optional[List[str]] = None,
        timeoutSeconds: float = 2.5,
        maxReferralDepth: int = 30,
        maxCnameHops: int = 10,
        ednsUdpPayload: int = 1232,
        preferIpv4: bool = True,
    ):
        self.rootHintsV4 = rootHintsV4 or DEFAULT_ROOT_HINTS_V4
        self.timeoutSeconds = timeoutSeconds
        self.maxReferralDepth = maxReferralDepth
        self.maxCnameHops = maxCnameHops
        self.ednsUdpPayload = ednsUdpPayload
        self.preferIpv4 = preferIpv4

        self.nsIpCache: Dict[str, List[str]] = {}

    def sendDnsQuery(self, serverIp: str, qname: dns.name.Name, qtype: dns.rdatatype.RdataType, trace: InspectorTrace):
        """
        Trimite o intrebare DNS catre un server (serverIp).
        - want_dnssec=True inseamna DO bit: "vreau si DNSSEC records".
        - udp_with_fallback: daca raspunsul UDP e trunchiat, trece pe TCP automat.
        """
        query = dns.message.make_query(
            qname,
            qtype,
            use_edns=True,
            want_dnssec=True,
            payload=self.ednsUdpPayload,
        )

        try:
            response, usedTcp = dns.query.udp_with_fallback(query, serverIp, timeout=self.timeoutSeconds)
            trace.queryLog.append(
                DnsQueryLog(
                    serverIp=serverIp,
                    qname=str(qname),
                    qtype=dns.rdatatype.to_text(qtype),
                    usedTcp=usedTcp,
                    rcode=dns.rcode.to_text(response.rcode()),
                    aa=bool(response.flags & dns.flags.AA),
                    tc=bool(response.flags & dns.flags.TC),
                    answerRrsets=len(response.answer),
                    authorityRrsets=len(response.authority),
                    additionalRrsets=len(response.additional),
                )
            )
            return response
        except Exception as e:
            trace.queryLog.append(
                DnsQueryLog(
                    serverIp=serverIp,
                    qname=str(qname),
                    qtype=dns.rdatatype.to_text(qtype),
                    usedTcp=False,
                    rcode="ERROR",
                    aa=False,
                    tc=False,
                    answerRrsets=0,
                    authorityRrsets=0,
                    additionalRrsets=0,
                    error=repr(e),
                )
            )
            return None

    def findRrset(self, section: List[dns.rrset.RRset], name: dns.name.Name, rdtype: int):
        """
        Cauta un RRset exact (name + type) intr-o sectiune (Answer/Authority/Additional).
        Returneaza RRset sau None.
        """
        for rrset in section:
            if rrset.name == name and rrset.rdtype == rdtype:
                return rrset
        return None

    def findReferralNsRrset(self, response: dns.message.Message):
        """
        Cand un server nu stie raspunsul final, iti da un "referral".
        Referral-ul vine de obicei ca un RRset NS in sectiunea Authority.
        """
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                return rrset
        return None

    def extractAdditionalBootstrapIpsForNs(self, response: dns.message.Message, nsNames: List[dns.name.Name]) -> List[str]:
        """
        Asta este ce in mod clasic se numeste "glue".
        Eu ii spun additionalBootstrapIps ca e fix rolul lui: te "porneste" mai departe.

        Pe inteles:
        - In Authority primesti numele nameserverelor (NS).
        - In Additional primesti uneori si IP-urile lor (A/AAAA).
        - IP-urile din Additional te ajuta sa nu ramai blocat intr-un cerc vicios
          (nu poti rezolva IP-ul NS-ului fara sa ajungi la zona care depinde de acel NS).

        Daca nu gasim aceste IP-uri in Additional, atunci trebuie sa rezolvam separat hostname-ul NS-ului.
        """
        wanted = {str(n).lower() for n in nsNames}
        ips: List[str] = []

        for rrset in response.additional:
            owner = str(rrset.name).lower()
            if owner not in wanted:
                continue

            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    ips.append(rdata.address)
            elif (not self.preferIpv4) and rrset.rdtype == dns.rdatatype.AAAA:
                for rdata in rrset:
                    ips.append(rdata.address)

        return list(dict.fromkeys(ips))

    def captureRrsigMetadataFromSection(self, section: List[dns.rrset.RRset], trace: InspectorTrace) -> None:
        """
        Extrage metadate din RRSIG (fara verificare criptografica).
        Ne intereseaza: algoritm + inception/expiration, ca sa le raportezi.
        """
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                for sig in rrset:
                    trace.rrsigInfo.append(
                        RrsigInfo(
                            owner=str(rrset.name),
                            coveredType=dns.rdatatype.to_text(sig.type_covered),
                            algorithm=sig.algorithm,
                            keyTag=sig.key_tag,
                            signer=str(sig.signer),
                            inception=sig.inception,
                            expiration=sig.expiration,
                        )
                    )

    def buildDenialProofFromAuthority(self, qname: dns.name.Name, qtype: dns.rdatatype.RdataType, response: dns.message.Message):
        """
        Construieste dovada ca "nu exista X" din Authority:
        - NSEC / NSEC3: recordurile care dovedesc non-existenta
        - RRSIG: semnaturile peste acele recorduri
        RFC 4035 spune ca NSEC + RRSIG trebuie incluse in Authority pentru astfel de cazuri.
        """
        soaPresent = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)

        proof = DsDenialProof(
            rcode=dns.rcode.to_text(response.rcode()),
            qname=str(qname),
            qtype=dns.rdatatype.to_text(qtype),
            soaPresent=soaPresent,
        )

        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
                proof.nsecRrsets.append(rrset.to_text())
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                proof.nsec3Rrsets.append(rrset.to_text())
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                for sig in rrset:
                    proof.rrsigInfo.append(
                        RrsigInfo(
                            owner=str(rrset.name),
                            coveredType=dns.rdatatype.to_text(sig.type_covered),
                            algorithm=sig.algorithm,
                            keyTag=sig.key_tag,
                            signer=str(sig.signer),
                            inception=sig.inception,
                            expiration=sig.expiration,
                        )
                    )

        return proof

    def responseLooksLikeAuthoritativeNoData(self, response: dns.message.Message) -> bool:
        """
        Detecteaza NODATA tipic:
        - rcode NOERROR
        - Answer gol
        - SOA prezent in Authority
        Asta inseamna: numele exista, dar tipul cerut nu exista.
        """
        if response.rcode() != dns.rcode.NOERROR:
            return False
        if len(response.answer) != 0:
            return False
        soaPresent = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)
        return soaPresent

    def responseHasNsecOrNsec3(self, response: dns.message.Message) -> bool:
        """
        Verifica daca raspunsul are NSEC/NSEC3 in Authority.
        Daca da, e un indiciu puternic ca avem "authenticated denial".
        """
        for rrset in response.authority:
            if rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                return True
        return False

    def resolveNameserverIps(self, nsName: dns.name.Name, trace: InspectorTrace) -> List[str]:
        """
        Daca nu avem additionalBootstrapIps, trebuie sa aflam IP-ul unui NS hostname.
        Asta e o rezolvare iterativa separata pentru nsName (A, si eventual AAAA).
        Punem cache ca sa nu repetam aceeasi munca.
        """
        cacheKey = str(nsName).lower()
        if cacheKey in self.nsIpCache:
            return self.nsIpCache[cacheKey]

        ips: List[str] = []
        qtypes = [dns.rdatatype.A] + ([] if self.preferIpv4 else [dns.rdatatype.AAAA])

        for qt in qtypes:
            msg = self.iterativeLookup(nsName, qt, trace, collectChain=False)
            if not msg:
                continue
            rrset = self.findRrset(msg.answer, nsName, qt)
            if rrset:
                for rdata in rrset:
                    ips.append(rdata.address)

        ips = list(dict.fromkeys(ips))
        self.nsIpCache[cacheKey] = ips
        return ips

    def fetchDsFromParent(self, parentAuthoritativeIps: List[str], childZone: dns.name.Name, trace: InspectorTrace):
        """
        Intrebam parintele: "ai DS pentru copil?"
        Returnam (dsList, dsDenialProofOrNone).

        Ne oprim devreme cand primim un raspuns autoritativ (AA=1) care arata clar ca DS nu exista:
        - NOERROR + Answer gol + SOA in Authority (NODATA) sau
        - NSEC/NSEC3 prezent in Authority
        In acest caz, salvam si dovada (NSEC/NSEC3 + RRSIG).
        """
        lastProof: Optional[DsDenialProof] = None

        for ip in parentAuthoritativeIps:
            resp = self.sendDnsQuery(ip, childZone, dns.rdatatype.DS, trace)
            if not resp:
                continue

            dsRrset = self.findRrset(resp.answer, childZone, dns.rdatatype.DS)
            if dsRrset:
                return list(dsRrset), None

            isAa = bool(resp.flags & dns.flags.AA)
            if isAa and (self.responseLooksLikeAuthoritativeNoData(resp) or self.responseHasNsecOrNsec3(resp)):
                lastProof = self.buildDenialProofFromAuthority(childZone, dns.rdatatype.DS, resp)
                return [], lastProof

            if isAa:
                lastProof = self.buildDenialProofFromAuthority(childZone, dns.rdatatype.DS, resp)

        return [], lastProof

    def fetchDnskeyFromChild(self, childAuthoritativeIps: List[str], childZone: dns.name.Name, trace: InspectorTrace):
        """
        Intrebam zona copil: "da-mi DNSKEY".
        DNSKEY e necesar ca sa verificam daca DS-ul din parinte chiar "point-eaza" spre o cheie reala.
        """
        for ip in childAuthoritativeIps:
            resp = self.sendDnsQuery(ip, childZone, dns.rdatatype.DNSKEY, trace)
            if not resp:
                continue
            rrset = self.findRrset(resp.answer, childZone, dns.rdatatype.DNSKEY)
            if rrset:
                return list(rrset)
        return []

    def digestTypeToHashName(self, digestType: int) -> Optional[str]:
        """
        Mapare digestType din DS la numele hash-ului folosit pentru make_ds.
        """
        if digestType == 1:
            return "SHA1"
        if digestType == 2:
            return "SHA256"
        if digestType == 4:
            return "SHA384"
        return None

    def evaluateDsDnskeyMatch(self, childZone: dns.name.Name, dsList: List, dnskeyList: List) -> Tuple[Optional[bool], str]:
        """
        Verifica DS <-> DNSKEY:
        - DS este un digest al unei DNSKEY din copil.
        - Calculam DS-uri candidat din DNSKEY-uri (pentru digest types prezente in dsList)
          si vedem daca vreunul se potriveste cu DS-urile din parinte.
        """
        if not dsList:
            return None, "NO_DS_IN_PARENT"
        if not dnskeyList:
            return False, "NO_DNSKEY_IN_CHILD"

        dsFingerprints = {(d.key_tag, d.algorithm, d.digest_type, d.digest) for d in dsList}
        digestTypes = sorted({d.digest_type for d in dsList})

        for key in dnskeyList:
            for dt in digestTypes:
                hashName = self.digestTypeToHashName(dt)
                if not hashName:
                    continue
                try:
                    generatedDs = dns.dnssec.make_ds(childZone, key, hashName)
                    fp = (generatedDs.key_tag, generatedDs.algorithm, generatedDs.digest_type, generatedDs.digest)
                    if fp in dsFingerprints:
                        return True, "OK"
                except Exception:
                    continue

        return False, "DS_MISMATCH"

    def extractCnameTarget(self, answerSection: List[dns.rrset.RRset], qname: dns.name.Name):
        """
        Daca raspunsul contine CNAME pentru qname, il urmam ca sa ajungem la tinta finala.
        """
        for rrset in answerSection:
            if rrset.name == qname and rrset.rdtype == dns.rdatatype.CNAME:
                for rdata in rrset:
                    return rdata.target
        return None

    def iterativeLookup(self, qname: dns.name.Name, qtype: dns.rdatatype.RdataType, trace: InspectorTrace, collectChain: bool):
        """
        Rezolvare iterativa:
        - incepe cu rootHints
        - daca primeste referral, merge mai departe pe NS-urile indicate
        - repeta pana ajunge la raspuns final (Answer) sau la un raspuns negativ stabil
        """
        currentAuthoritativeIps = list(self.rootHintsV4)

        currentParentZone = dns.name.root
        seenZoneCuts: Set[str] = set()

        for depth in range(self.maxReferralDepth):
            response = None
            for ip in currentAuthoritativeIps:
                response = self.sendDnsQuery(ip, qname, qtype, trace)
                if response:
                    break

            if not response:
                trace.notes.append(f"No response at depth={depth}.")
                return None

            self.captureRrsigMetadataFromSection(response.authority, trace)

            if response.answer:
                self.captureRrsigMetadataFromSection(response.answer, trace)
                return response

            referralNs = self.findReferralNsRrset(response)
            if not referralNs:
                return response

            childZone = referralNs.name
            childZoneKey = str(childZone).lower()
            if childZoneKey in seenZoneCuts:
                trace.notes.append(f"Zone-cut loop at {childZone}.")
                return response
            seenZoneCuts.add(childZoneKey)

            delegatedNsNames = [r.target for r in referralNs]

            additionalBootstrapIps = self.extractAdditionalBootstrapIpsForNs(response, delegatedNsNames)

            if not additionalBootstrapIps:
                resolvedIps: List[str] = []
                for nsName in delegatedNsNames:
                    resolvedIps.extend(self.resolveNameserverIps(nsName, trace))
                additionalBootstrapIps = list(dict.fromkeys(resolvedIps))

            if collectChain:
                link = DelegationLink(parentZone=str(currentParentZone), childZone=str(childZone))

                dsList, dsProof = self.fetchDsFromParent(currentAuthoritativeIps, childZone, trace)
                dnskeyList = self.fetchDnskeyFromChild(additionalBootstrapIps, childZone, trace)

                link.dsRecords = [
                    {
                        "keyTag": d.key_tag,
                        "algorithm": d.algorithm,
                        "digestType": d.digest_type,
                        "digestHex": d.digest.hex(),
                    }
                    for d in dsList
                ]

                link.dnskeyRecords = [
                    {
                        "flags": k.flags,
                        "protocol": k.protocol,
                        "algorithm": k.algorithm,
                        "publicKeyB64": base64.b64encode(k.key).decode("ascii"),
                    }
                    for k in dnskeyList
                ]

                match, status = self.evaluateDsDnskeyMatch(childZone, dsList, dnskeyList)
                link.dsMatchesDnskey = match
                link.status = status

                if status == "DS_MISMATCH":
                    link.details = "Parent has DS, but DS does not match any child DNSKEY => broken chain."
                    trace.chainVerdict = "BROKEN_CHAIN"
                    trace.chainBreakAt = str(childZone)

                elif status == "NO_DS_IN_PARENT":
                    link.details = "No DS in parent => insecure delegation (DNSSEC cannot build chain to child)."
                    link.dsDenialProof = dsProof
                    if trace.chainVerdict == "UNKNOWN":
                        trace.chainVerdict = "INSECURE_DELEGATION"

                elif status == "NO_DNSKEY_IN_CHILD":
                    link.details = "Parent has DS, but child has no DNSKEY => broken chain."
                    trace.chainVerdict = "BROKEN_CHAIN"
                    trace.chainBreakAt = str(childZone)

                else:
                    link.details = "DS <-> DNSKEY OK for this hop."

                trace.delegationChain.append(link)

                if trace.chainVerdict == "BROKEN_CHAIN":
                    return response

                currentParentZone = childZone

            if not additionalBootstrapIps:
                trace.notes.append(f"Could not obtain nameserver IPs for {childZone}.")
                if trace.chainVerdict == "UNKNOWN":
                    trace.chainVerdict = "ERROR"
                return response

            currentAuthoritativeIps = additionalBootstrapIps

        trace.notes.append("Max depth reached.")
        return None

    def inspectDomain(self, domain: str, rrtype: str = "A") -> InspectorTrace:
        """
        Functia pe care o apelezi tu.
        - face lookup iterativ
        - urmareste CNAME (daca exista)
        - produce trace complet pentru raport
        """
        trace = InspectorTrace(targetName=domain, targetType=rrtype)

        qname = dns.name.from_text(domain)
        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        qtype = dns.rdatatype.from_text(rrtype)

        currentName = qname

        for hop in range(self.maxCnameHops + 1):
            response = self.iterativeLookup(currentName, qtype, trace, collectChain=True)
            if not response:
                if trace.chainVerdict == "UNKNOWN":
                    trace.chainVerdict = "ERROR"
                trace.notes.append("No final response.")
                return trace

            for rrset in response.answer:
                trace.finalAnswerRrsets.append(rrset.to_text())

            cnameTarget = self.extractCnameTarget(response.answer, currentName)
            if cnameTarget:
                trace.cnameChain.append(f"{currentName} -> {cnameTarget}")
                currentName = cnameTarget
                continue

            break

        if trace.chainVerdict == "UNKNOWN":
            trace.chainVerdict = "SECURE_CHAIN_CANDIDATE"

        return trace


if __name__ == "__main__":
    collector = DnssecChainCollector(timeoutSeconds=2.5, preferIpv4=True)
    result = collector.inspectDomain("google.com", "A")
    print(json.dumps(asdict(result), indent=2))