


# DNSSEC Inspector

DNSSEC Inspector este un tool care analizeaza un domeniu din perspectiva DNSSEC si genereaza un raport JSON care explica de ce un domeniu este:

\- validabil DNSSEC (lant coerent),

\- nesemnat DNSSEC (insecure delegation),

\- sau are lantul DNSSEC rupt (broken chain).

# Descrierea proiectului

DNS transforma un nume de domeniu intr-o adresa IP. DNSSEC adauga mecanisme criptografice (chei, semnaturi si dovezi) care permit verificarea autenticitatii si integritatii raspunsurilor DNS. DNSSEC Inspector colecteaza aceste informatii si le structureaza intr-un raport.

# Functionalitati

## 1\) Verificare DNSSEC pentru domenii (chain inspection)

Tool-ul face rezolvare iterativa (pornind de la root) si construieste lantul de delegare pe baza relatiei DS (din parinte) ↔ DNSKEY (din copil).

## 2\) RRSIG (semnaturi)

Tool-ul colecteaza metadate RRSIG: algorithm, keyTag, signer, inception, expiration (utile pentru validare completa ulterioara).

## 3\) Expirare

Metadatele inception/expiration permit marcarea semnaturilor expirate sau care expira curand.

## 4\) Lanturi rupte

Tool-ul poate marca hopuri problematice, de exemplu:

\- DS exista, dar nu se potriveste cu nicio DNSKEY (DS\_MISMATCH),

\- DS exista, dar zona copil nu publica DNSKEY (NO\_DNSKEY\_IN\_CHILD).

## 5\) Algoritmi slabi

Raportul include digest type-ul DS si algoritmii RRSIG pentru clasificare. (Ex: SHA-1 pentru DS este considerat nerecomandat in registrul IANA)

## 6\) Raport automatizat

Tool-ul produce un raport complet: query log + delegation chain + dovezi pentru NSEC/NSEC3 + RRSIG și un raspuns final.

# Fluxul de lucru

## Rezolvare iterativa

Tool-ul porneste de la o lista de root servers si urmeaza referral-urile pana ajunge la zona autoritativa a domeniului tinta.

Cand un server returneaza un referral:

\- sectiunea Authority contine name serverele (NS) pentru zona urmatoare,

\- sectiunea Additional poate contine IP-urile acelor NS (A/AAAA).

Aceste IP-uri din Additional sunt folosite ca bootstrap pentru a continua rezolvarea fara a intra intr-o dependenta circulara. Acest mecanism este cunoscut ca glue. IP-urile sunt denumite additionalBootstrapIps.

Daca parintele nu publica DS pentru copil, DNSSEC poate furniza dovezi semnate de non-existenta folosind NSEC/NSEC3 + RRSIG. Se salveaza aceste dovezi in dsDenialProof pentru hop-ul respectiv.

# Instalare

## Cerinte

\- Python 3.10+ recomandat

\- dependinta principala: dnspython

\- se recomandă rularea python inspector.py dintr-un mediu virtualizat python

Exemplu de utilizare: google.com (non-DNSSEC), cloudflare.com (DNSSEC)

##  Rulare Interfață Grafică (GUI)
python gui.py

## Rulare în Linia de Comandă (CLI)
Pentru utilizare avansată, automatizare sau export JSON.
python cli.py <domeniu> [--type TIP] [--format json|text]

ex. python cli.py google.com --type MX --format json



# Structura raportului

queryLog: lista tuturor interogarilor (server, qname, qtype, rcode, AA, TC, erori) - arata exact ce servere au fost intrebate si ce raspuns a venit

delegationChain: lista hop-urilor parentZone -> childZone, fiecare cu: dsRecords, dnskeyRecords, dsMatchesDnskey, status, details

dsDenialProof (cand lipseste DS si exista dovada NSEC/NSEC3)

finalAnswerRrsets: RRset-urile finale (ex: A/AAAA/MX)

rrsigInfo: metadate RRSIG (algoritm, keyTag, signer, inception, expiration)

chainVerdict: verdict final (SECURE\_CHAIN\_CANDIDATE / INSECURE\_DELEGATION / BROKEN\_CHAIN / ERROR)

# Legenda:

DNS: Domain Name System (mapare nume -> IP)

DNSSEC: DNS Security Extensions (semnaturi si validare pentru DNS)

RR: Resource Record (un record DNS: A, NS, DS, DNSKEY etc.)

RRset: set de RR-uri de acelasi tip pentru acelasi nume

RRSIG: semnatura digitala peste un RRset

DNSKEY: cheia publica a zonei

DS: Delegation Signer (digest/amprenta unei DNSKEY din copil, publicata in parinte)

NSEC / NSEC3: dovezi semnate de non-existenta (“recordul nu exista”)

CNAME: Cannonical Name - alias DNS (un nume care indica spre alt nume)

EDNS0: extensii DNS folosite pentru optiuni suplimentare (inclusiv DNSSEC)

DO bit: “DNSSEC OK” (bit EDNS care indica faptul ca se doresc recorduri DNSSEC)

RCODE: cod de raspuns (NOERROR, NXDOMAIN etc.)

AA: Authoritative Answer (raspuns autoritativ)

TC: Truncated (raspuns trunchiat; de obicei se reincearca prin TCP)

NS: Name Server (server autoritativ pentru o zona)

glue (termen standard): A/AAAA pentru nameserverele dintr-un referral, oferite in Additional ca sa permita continuarea rezolvarii

# Setari default:

timeoutSeconds=2.5: compromis intre viteza si performanta

maxReferralDepth=30: protectie anti bucle / configurari neobisnuite

maxCnameHops=10: protectie anti lanturi CNAME excesive sau loop

ednsUdpPayload=1232: valoare conservatoare folosita frecvent pentru a reduce fragmentarea UDP

preferIpv4=True: util in medii fara conectivitate IPv6 (reduce erori si timpi morti)

