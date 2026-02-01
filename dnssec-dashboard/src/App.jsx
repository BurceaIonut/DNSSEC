import { useState } from 'react'
import { 
  Shield, Search, Lock, AlertTriangle, CheckCircle, 
  XCircle, ArrowDown, Server, FileText, Key, ShieldCheck, ShieldAlert, ShieldOff
} from 'lucide-react'
import './App.css'

// --- MAPĂRI STANDARDE IANA PENTRU DNSSEC ---
const DNS_ALGORITHMS = {
  0: 'None (Unsigned)',       
  1: 'RSA-MD5 (Deprecated)',
  3: 'DSA-SHA1 (Deprecated)',
  5: 'RSA-SHA1',
  6: 'DSA-NSEC3-SHA1',
  7: 'RSA-SHA1-NSEC3',
  8: 'RSA-SHA256',
  10: 'RSA-SHA512',
  12: 'GOST-R-34.10-2001',
  13: 'ECDSA-P256-SHA256',
  14: 'ECDSA-P384-SHA384',
  15: 'Ed25519',
  16: 'Ed448'
}

const DNS_DIGESTS = {
  0: 'None',                  
  1: 'SHA-1',
  2: 'SHA-256',
  4: 'SHA-384'
}

function App() {
  const [domain, setDomain] = useState('')
  const [type, setType] = useState('A')
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  // Funcții helper pentru nume
  const getAlgoName = (id) => DNS_ALGORITHMS[id] || `Unknown Algo (${id})`
  const getDigestName = (id) => DNS_DIGESTS[id] || `Unknown Digest (${id})`

  const handleScan = async (overrideDomain = null) => {
    const targetDomain = overrideDomain || domain;
    if (!targetDomain) return
    
    setDomain(targetDomain);
    setLoading(true)
    setError(null)
    setData(null)

    try {
      const response = await fetch('http://127.0.0.1:5000/api/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: targetDomain, type })
      })
      const result = await response.json()
      if (result.error) throw new Error(result.error)
      setData(result)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status) => {
    if (status === 'OK' || status === 'VALID') return 'var(--success)'
    if (status === 'BOGUS' || status === 'FAIL' || status.includes('MISMATCH')) return 'var(--danger)'
    return 'var(--warning)'
  }

  return (
    <div className="container">
      {/* HEADER */}
      <header className="header">
        <div className="title">
          <h1>DNSSEC Inspector</h1>
          <div className="subtitle">Enterprise Chain of Trust Analysis</div>
        </div>
        <span className="badge-pro">v2.0 </span>
      </header>

      {/* SEARCH BOX */}
      <div className="search-box">
        <input 
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter domain (e.g. ietf.org)"
          onKeyDown={(e) => e.key === 'Enter' && handleScan()}
        />
        <select value={type} onChange={(e) => setType(e.target.value)} style={{width: '120px'}}>
          <option value="A">A</option>
          <option value="MX">MX</option>
          <option value="NS">NS</option>
          <option value="TXT">TXT</option>
        </select>
        <button onClick={() => handleScan()} disabled={loading}>
          {loading ? 'ANALYZING...' : 'INSPECT'}
        </button>
      </div>

      {/* SCENARIOS */}
      {!data && !loading && (
        <div className="scenarios-grid">
          <div className="scenario-card sc-secure" onClick={() => handleScan('ietf.org')}>
             <div className="sc-title"><ShieldCheck className="sc-icon" size={18}/> Test Secure Chain</div>
             <div className="sc-domain">ietf.org</div>
          </div>
          <div className="scenario-card sc-broken" onClick={() => handleScan('dnssec-failed.org')}>
             <div className="sc-title"><ShieldAlert className="sc-icon" size={18}/> Test Broken Chain</div>
             <div className="sc-domain">dnssec-failed.org</div>
          </div>
          <div className="scenario-card sc-insecure" onClick={() => handleScan('cnn.com')}>
             <div className="sc-title"><ShieldOff className="sc-icon" size={18}/> Test Insecure</div>
             <div className="sc-domain">cnn.com</div>
          </div>
        </div>
      )}

      {error && (
        <div style={{padding:'1rem', background:'rgba(239,68,68,0.2)', border:'1px solid var(--danger)', borderRadius:'8px', color:'var(--danger)', marginBottom:'2rem'}}>
          [X] System Error: {error}
        </div>
      )}

      {data && (
        <main>
          {/* VERDICT */}
          <div className="verdict-banner" style={{borderColor: getStatusColor(data.chainVerdict).replace('var', '')}}>
             <div className="verdict-title" style={{color: getStatusColor(data.chainVerdict)}}>
                {data.chainVerdict.includes('SECURE') && <CheckCircle size={40}/>}
                {data.chainVerdict.includes('BROKEN') && <XCircle size={40}/>}
                {data.chainVerdict.includes('INSECURE') && <AlertTriangle size={40}/>}
                {data.chainVerdict.replace('_', ' ')}
             </div>
             <div>{data.chainVerdict === 'SECURE_CHAIN_CANDIDATE' 
                ? "The Chain of Trust is fully valid from Root (.) to the target."
                : "Validation failed or the chain is incomplete."}
             </div>
          </div>

          {/* 1. CHAIN OF TRUST */}
          <h2 className="section-title"><Server style={{marginBottom:-4, marginRight:10}}/> 1. Chain of Trust (Delegation Path)</h2>
          
          <div className="chain-container">
            {data.delegationChain.length === 0 && <p>No delegation chain found.</p>}
            
            {data.delegationChain.map((link, idx) => (
              <div key={idx} style={{width: '100%'}}>
                <div className="chain-step">
                  <div className="step-header">
                     <span className="step-number">HOP #{idx + 1}</span>
                     <div className="zones-flow">
                        {link.parentZone} <span style={{color:'var(--text-secondary)'}}>→</span> {link.childZone}
                     </div>
                     <div className={link.status === 'OK' ? 'status-ok' : 'status-err'}>
                        [{link.status}]
                     </div>
                  </div>

                  <div className="step-body">
                    <div className="detail-row">
                       <span className="label">Details:</span>
                       <span className="value">{link.details || "Delegation verified successfully."}</span>
                    </div>
                    {link.dsDenialProof && (
                       <div className="proof-box">
                          <AlertTriangle size={18}/>
                          <strong>Authenticated Denial of Existence:</strong> NSEC/NSEC3 proof found showing NO DS record exists here.
                       </div>
                    )}
                  </div>
                </div>
                <div className="arrow-connector"><ArrowDown size={32}/></div>
              </div>
            ))}

            <div className="chain-step final-box">
               <div className="step-header" style={{borderBottom:'none', marginBottom:0}}>
                  <span className="step-number" style={{borderColor:'var(--accent)', color:'var(--accent)'}}>TARGET</span>
                  <div className="zones-flow" style={{color:'var(--accent)'}}>{data.targetName} ({data.targetType})</div>
                  <CheckCircle size={20} color="var(--accent)"/>
               </div>
               <div style={{marginTop:'1rem', padding:'1rem', background:'var(--bg-dark)', borderRadius:'6px', fontFamily:'monospace'}}>
                  {data.finalAnswerRrsets.length > 0 ? (
                    data.finalAnswerRrsets.map((line, i) => <div key={i}>&gt;&gt; {line}</div>)
                  ) : (
                    <div style={{color:'var(--warning)'}}>[!] No Data / Query Failed</div>
                  )}
               </div>
            </div>
          </div>

          {/* 2. Algorithm / Digest */}
          <h2 className="section-title"><Lock style={{marginBottom:-4, marginRight:10}}/> 2. Algorithms & Digests</h2>
          <table className="full-table">
             <thead>
               <tr>
                 <th>Scope (Zone)</th>
                 <th>Algorithm / Digest</th>
                 <th>Verdict</th>
                 <th>Notes</th>
               </tr>
             </thead>
             <tbody>
               {data.algoAssessments.map((algo, i) => (
                 <tr key={i}>
                   <td>{algo.owner}</td>
                   <td>
                     {/* Afișăm Numele (și ID-ul mic în paranteză) */}
                     <span style={{fontWeight: 600}}>
                       {algo.kind === 'DS_DIGEST' ? getDigestName(algo.value) : getAlgoName(algo.value)}
                     </span>
                    
                   </td>
                   <td className={algo.verdict === 'OK' ? 'status-ok' : 'status-err'}>
                      {algo.verdict}
                   </td>
                   <td>{algo.notes}</td>
                 </tr>
               ))}
               {data.algoAssessments.length === 0 && <tr><td colSpan="4">No algorithms assessed.</td></tr>}
             </tbody>
          </table>

          {/* 3. SIGNATURES */}
          <h2 className="section-title"><FileText style={{marginBottom:-4, marginRight:10}}/> 3. Signatures (RRSIG)</h2>
          <table className="full-table">
             <thead>
               <tr>
                 <th>Status</th>
                 <th>Owner / Key</th>
                 <th>Algorithm</th>
                 <th>Details</th>
               </tr>
             </thead>
             <tbody>
               {data.signatureChecks.map((sig, i) => (
                 <tr key={i}>
                   <td className={getStatusColor(sig.cryptoStatus) === 'var(--success)' ? 'status-ok' : 'status-err'}>
                      {sig.cryptoStatus === 'VALID' ? ' VALID' : '[X] ' + sig.cryptoStatus}
                   </td>
                   <td>
                      <div style={{fontWeight:'bold'}}>{sig.owner} <span style={{fontWeight:'normal', color:'gray'}}>({sig.rrtype})</span></div>
                     
                   </td>
                   <td>
                     {getAlgoName(sig.algorithm)}
                   </td>
                   <td>
                      {sig.failureReason ? sig.failureReason : "Signature verified."}
                      {sig.timeStatus !== 'OK' && <span style={{color:'var(--warning)', marginLeft:10}}> ⚠ {sig.timeStatus}</span>}
                   </td>
                 </tr>
               ))}
                {data.signatureChecks.length === 0 && <tr><td colSpan="4">No signatures found.</td></tr>}
             </tbody>
          </table>
          
          <div style={{height: '50px'}}></div>
        </main>
      )}
    </div>
  )
}

export default App