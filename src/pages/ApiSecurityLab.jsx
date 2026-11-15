import { useState, useMemo } from 'react';
import {
  Shield,
  KeyRound,
  Lock,
  Unlock,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Terminal,
  RefreshCw,
  Copy,
  Check,
  FileCode,
  Database,
  ArrowRight,
  Zap,
} from 'lucide-react';
import { SectionTitle } from '../components/SectionTitle';
import { CyberCard } from '../components/CyberCard';
import { AnimatedButton } from '../components/AnimatedButton';
import { API_SECURITY_SCENARIOS, COMMON_WEAK_SECRETS } from '../data/apiSecurityScenarios';
import {
  base64UrlEncode,
  base64UrlDecode,
  parseJwt,
  generateJwt,
  verifyJwt,
  crackHmacSecret,
  calculateKeyEntropy,
  lookupRainbowTable,
  evaluateApiChallenge,
} from '../utils/apiSecurityEngine';

export const ApiSecurityLab = () => {
  const [activeTab, setActiveTab] = useState('inspector'); // 'inspector' | 'challenges' | 'cracker'
  const [selectedScenarioId, setSelectedScenarioId] = useState('jwt_alg_none');
  const [defenseActive, setDefenseActive] = useState(false);
  const [challengeResult, setChallengeResult] = useState(null);
  const [copied, setCopied] = useState(false);

  // Inspector State
  const [currentSecret, setCurrentSecret] = useState('super-secret-hmac-key');
  const [headerJson, setHeaderJson] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payloadJson, setPayloadJson] = useState(
    '{\n  "sub": "user_1042",\n  "name": "Alex Vance",\n  "role": "user",\n  "iat": 1700000000,\n  "exp": 1700003600\n}'
  );
  const [tokenInput, setTokenInput] = useState(() => {
    try {
      return generateJwt(
        { alg: 'HS256', typ: 'JWT' },
        { sub: 'user_1042', name: 'Alex Vance', role: 'user', iat: 1700000000, exp: 1700003600 },
        'super-secret-hmac-key'
      );
    } catch {
      return '';
    }
  });

  // Cracker State
  const [crackerToken, setCrackerToken] = useState(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzIwOTEiLCJuYW1lIjoiTWFyayBTbG9hbiIsInJvbGUiOiJ2aWV3ZXIifQ.sig_3a5047b74400cf2b'
  );
  const [crackResult, setCrackResult] = useState(null);
  const [entropyInputKey, setEntropyInputKey] = useState('secret123');
  const [rainbowHashInput, setRainbowHashInput] = useState('5f4dcc3b5aa765d61d8327deb882cf99');
  const [rainbowResult, setRainbowResult] = useState(null);

  // Active scenario definition
  const currentScenario = useMemo(
    () => API_SECURITY_SCENARIOS.find((s) => s.id === selectedScenarioId) || API_SECURITY_SCENARIOS[0],
    [selectedScenarioId]
  );

  // Parse current token in inspector
  const parsedToken = useMemo(() => parseJwt(tokenInput), [tokenInput]);

  // Verification in inspector
  const verificationResult = useMemo(
    () => verifyJwt(tokenInput, currentSecret, { allowedAlgorithms: ['HS256', 'RS256'] }),
    [tokenInput, currentSecret]
  );

  // Entropy rating for current secret
  const secretEntropy = useMemo(() => calculateKeyEntropy(currentSecret), [currentSecret]);
  const standaloneEntropy = useMemo(() => calculateKeyEntropy(entropyInputKey), [entropyInputKey]);

  // Sync token from JSON editors
  const handleUpdateFromEditors = () => {
    try {
      const hObj = JSON.parse(headerJson);
      const pObj = JSON.parse(payloadJson);
      const generated = generateJwt(hObj, pObj, currentSecret);
      setTokenInput(generated);
    } catch (err) {
      alert(`Invalid JSON in editors: ${err.message}`);
    }
  };

  // Sync editors from raw token input
  const handleTokenInputChange = (newToken) => {
    setTokenInput(newToken);
    const p = parseJwt(newToken);
    if (p.validFormat) {
      setHeaderJson(JSON.stringify(p.header, null, 2));
      setPayloadJson(JSON.stringify(p.payload, null, 2));
    }
  };

  // Preset token loader
  const loadPreset = (presetType) => {
    if (presetType === 'user') {
      const h = { alg: 'HS256', typ: 'JWT' };
      const p = { sub: 'user_1042', name: 'Alex Vance', role: 'user', iat: 1700000000, exp: 1700003600 };
      const key = 'super-secret-hmac-key';
      setCurrentSecret(key);
      setHeaderJson(JSON.stringify(h, null, 2));
      setPayloadJson(JSON.stringify(p, null, 2));
      setTokenInput(generateJwt(h, p, key));
    } else if (presetType === 'alg_none') {
      const h = { alg: 'none', typ: 'JWT' };
      const p = { sub: 'user_1042', name: 'Alex Vance', role: 'admin', iat: 1700000000, exp: 1700003600 };
      setHeaderJson(JSON.stringify(h, null, 2));
      setPayloadJson(JSON.stringify(p, null, 2));
      setTokenInput(generateJwt(h, p));
    } else if (presetType === 'weak') {
      const h = { alg: 'HS256', typ: 'JWT' };
      const p = { sub: 'user_2091', role: 'viewer', permissions: ['read:profile'] };
      const key = 'secret123';
      setCurrentSecret(key);
      setHeaderJson(JSON.stringify(h, null, 2));
      setPayloadJson(JSON.stringify(p, null, 2));
      setTokenInput(generateJwt(h, p, key));
    } else if (presetType === 'expired') {
      const h = { alg: 'HS256', typ: 'JWT' };
      const p = { sub: 'user_5012', email: 'cfo@corp.local', role: 'cfo_admin', exp: 1690000000 };
      const key = 'super-secret-hmac-key';
      setCurrentSecret(key);
      setHeaderJson(JSON.stringify(h, null, 2));
      setPayloadJson(JSON.stringify(p, null, 2));
      setTokenInput(generateJwt(h, p, key));
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(tokenInput);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Run challenge evaluation
  const handleRunChallenge = () => {
    let input = tokenInput;
    if (selectedScenarioId === 'crypto_unsalted_hashes') {
      input = currentScenario.initialHash;
    }
    const res = evaluateApiChallenge(selectedScenarioId, input, {
      defenseActive,
      secret: currentScenario.initialSecret,
    });
    setChallengeResult(res);
  };

  // Run offline dictionary cracker
  const handleRunCracker = () => {
    const res = crackHmacSecret(crackerToken, COMMON_WEAK_SECRETS);
    setCrackResult(res);
  };

  // Run rainbow table lookup
  const handleRainbowLookup = () => {
    const res = lookupRainbowTable(rainbowHashInput);
    setRainbowResult(res);
  };

  return (
    <div className="min-h-screen bg-cyber-black text-slate-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div>
          <SectionTitle
            title="API Security & Token Vulnerability Lab"
            subtitle="Hands-on interactive laboratory for JWT exploits, cryptographic tampering, weak secret cracking, and API defense validation."
          />
          <div className="flex flex-wrap items-center gap-3 mt-4">
            <span className="text-xs px-2.5 py-1 rounded bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/30 font-medium">
              OWASP API Security Top 10
            </span>
            <span className="text-xs px-2.5 py-1 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30 font-medium">
              RFC 7519 JSON Web Tokens
            </span>
            <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-medium">
              Cryptographic Defenses & Key Derivation
            </span>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="flex border-b border-cyber-border space-x-1 sm:space-x-4">
          <button
            onClick={() => setActiveTab('inspector')}
            className={`pb-3 px-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'inspector'
                ? 'border-neon-cyan text-neon-cyan'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-4 h-4" />
            Token Inspector & Tamper Playground
          </button>
          <button
            onClick={() => setActiveTab('challenges')}
            className={`pb-3 px-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'challenges'
                ? 'border-neon-cyan text-neon-cyan'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4" />
            Interactive Security Challenges
          </button>
          <button
            onClick={() => setActiveTab('cracker')}
            className={`pb-3 px-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'cracker'
                ? 'border-neon-cyan text-neon-cyan'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Zap className="w-4 h-4" />
            Offline Key Cracker & Hash Analysis
          </button>
        </div>

        {/* TAB 1: Token Inspector & Tamper Playground */}
        {activeTab === 'inspector' && (
          <div className="space-y-6">
            <CyberCard>
              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div>
                  <h3 className="text-white font-semibold flex items-center gap-2">
                    <KeyRound className="w-5 h-5 text-neon-cyan" />
                    Encoded Token Stream
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Paste an existing JWT or edit the Header, Payload, and Secret below to forge tokens in real-time.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-cyber-dark/80 hover:bg-cyber-dark text-slate-300 border border-cyber-border transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? 'Copied' : 'Copy Token'}
                  </button>
                </div>
              </div>

              {/* Presets */}
              <div className="flex flex-wrap items-center gap-2 mb-4">
                <span className="text-xs text-slate-400 mr-2">Presets:</span>
                <button
                  onClick={() => loadPreset('user')}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                >
                  Standard User
                </button>
                <button
                  onClick={() => loadPreset('alg_none')}
                  className="px-2.5 py-1 text-xs rounded bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800 transition"
                >
                  Admin (alg: none exploit)
                </button>
                <button
                  onClick={() => loadPreset('weak')}
                  className="px-2.5 py-1 text-xs rounded bg-amber-950/60 hover:bg-amber-900/60 text-amber-300 border border-amber-800 transition"
                >
                  Weak Secret Key
                </button>
                <button
                  onClick={() => loadPreset('expired')}
                  className="px-2.5 py-1 text-xs rounded bg-purple-950/60 hover:bg-purple-900/60 text-purple-300 border border-purple-800 transition"
                >
                  Expired CFO Session
                </button>
              </div>

              {/* Encoded Token Input with 3-part syntax coloring */}
              <div className="relative">
                <textarea
                  value={tokenInput}
                  onChange={(e) => handleTokenInputChange(e.target.value)}
                  rows={3}
                  className="w-full bg-cyber-black/90 p-3 rounded-lg border border-cyber-border font-mono text-xs text-slate-200 focus:outline-none focus:border-neon-cyan leading-relaxed"
                  placeholder="Paste JWT (header.payload.signature)..."
                />
              </div>

              {/* Signature Verification Status Pill */}
              <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Signature Status:</span>
                  {verificationResult.valid ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/70 text-emerald-400 border border-emerald-700 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Cryptographically Valid
                    </span>
                  ) : verificationResult.algBypassDetected ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/70 text-amber-400 border border-amber-700 font-medium">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Unsigned (alg: none)
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950/70 text-rose-400 border border-rose-700 font-medium">
                      <XCircle className="w-3.5 h-3.5" />
                      {verificationResult.error || 'Signature Mismatch'}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2 text-slate-400">
                  <span>Secret Key:</span>
                  <input
                    type="text"
                    value={currentSecret}
                    onChange={(e) => setCurrentSecret(e.target.value)}
                    className="px-2 py-1 rounded bg-cyber-dark border border-cyber-border text-slate-200 font-mono text-xs w-48 focus:outline-none focus:border-neon-cyan"
                    placeholder="Signing secret..."
                  />
                  <span className={`text-[11px] font-mono ${secretEntropy.labelColor}`}>
                    ({secretEntropy.rating} - {secretEntropy.bits} bits)
                  </span>
                </div>
              </div>
            </CyberCard>

            {/* 3-Part Interactive Token Inspector Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Header Box (Red/Rose) */}
              <div className="bg-cyber-dark/80 p-4 rounded-lg border border-rose-500/40 space-y-3">
                <div className="flex items-center justify-between text-xs text-rose-400 font-semibold">
                  <span className="flex items-center gap-1.5">
                    <FileCode className="w-4 h-4" />
                    Header (JOSE)
                  </span>
                  <span className="text-[10px] font-mono bg-rose-950/80 px-2 py-0.5 rounded">
                    alg: {parsedToken.header?.alg || 'none'}
                  </span>
                </div>
                <textarea
                  value={headerJson}
                  onChange={(e) => setHeaderJson(e.target.value)}
                  rows={8}
                  className="w-full bg-cyber-black p-2.5 rounded font-mono text-xs text-rose-300 border border-rose-900/50 focus:outline-none focus:border-rose-500"
                />
                <button
                  onClick={handleUpdateFromEditors}
                  className="w-full text-xs py-1.5 rounded bg-rose-950/50 hover:bg-rose-900/60 text-rose-200 border border-rose-800 transition"
                >
                  Apply Header Changes
                </button>
              </div>

              {/* Payload Box (Purple/Violet) */}
              <div className="bg-cyber-dark/80 p-4 rounded-lg border border-purple-500/40 space-y-3">
                <div className="flex items-center justify-between text-xs text-purple-400 font-semibold">
                  <span className="flex items-center gap-1.5">
                    <Database className="w-4 h-4" />
                    Payload (Claims)
                  </span>
                  <span className="text-[10px] font-mono bg-purple-950/80 px-2 py-0.5 rounded">
                    role: {parsedToken.payload?.role || 'none'}
                  </span>
                </div>
                <textarea
                  value={payloadJson}
                  onChange={(e) => setPayloadJson(e.target.value)}
                  rows={8}
                  className="w-full bg-cyber-black p-2.5 rounded font-mono text-xs text-purple-300 border border-purple-900/50 focus:outline-none focus:border-purple-500"
                />
                <button
                  onClick={handleUpdateFromEditors}
                  className="w-full text-xs py-1.5 rounded bg-purple-950/50 hover:bg-purple-900/60 text-purple-200 border border-purple-800 transition"
                >
                  Apply Payload Changes
                </button>
              </div>

              {/* Signature Box (Cyan/Emerald) */}
              <div className="bg-cyber-dark/80 p-4 rounded-lg border border-cyan-500/40 space-y-3">
                <div className="flex items-center justify-between text-xs text-cyan-400 font-semibold">
                  <span className="flex items-center gap-1.5">
                    <Lock className="w-4 h-4" />
                    Signature (HMAC-SHA256)
                  </span>
                  <span className="text-[10px] font-mono bg-cyan-950/80 px-2 py-0.5 rounded">
                    {parsedToken.signature ? 'Signed' : 'Unsigned'}
                  </span>
                </div>
                <div className="bg-cyber-black p-2.5 rounded font-mono text-xs text-cyan-300 border border-cyan-900/50 h-[178px] overflow-y-auto break-all">
                  {parsedToken.signature || (
                    <span className="text-slate-500 italic">No signature present (empty string for alg: none)</span>
                  )}
                </div>
                <button
                  onClick={handleUpdateFromEditors}
                  className="w-full text-xs py-1.5 rounded bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-200 border border-cyan-800 transition"
                >
                  Recalculate Signature
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Interactive Security Challenges */}
        {activeTab === 'challenges' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Challenge Scenarios List */}
            <div className="lg:col-span-4 space-y-3">
              <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-neon-cyan" />
                Select Challenge Scenario
              </h3>
              {API_SECURITY_SCENARIOS.map((scenario) => {
                const isSelected = scenario.id === selectedScenarioId;
                return (
                  <button
                    key={scenario.id}
                    onClick={() => {
                      setSelectedScenarioId(scenario.id);
                      setChallengeResult(null);
                      if (scenario.initialToken) {
                        setTokenInput(scenario.initialToken);
                        handleTokenInputChange(scenario.initialToken);
                      }
                      if (scenario.initialSecret) {
                        setCurrentSecret(scenario.initialSecret);
                      }
                    }}
                    className={`w-full text-left p-3.5 rounded-lg border transition-all ${
                      isSelected
                        ? 'bg-cyber-dark/90 border-neon-cyan/80 shadow-lg shadow-neon-cyan/5'
                        : 'bg-cyber-dark/40 border-cyber-border hover:bg-cyber-dark/60'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-semibold text-slate-200">{scenario.title}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/70 text-red-400 border border-red-800/60 font-mono">
                        {scenario.difficulty}
                      </span>
                    </div>
                    <div className="text-[11px] text-neon-cyan/80 font-mono mb-1">{scenario.owaspTag}</div>
                    <p className="text-xs text-slate-400 line-clamp-2">{scenario.summary}</p>
                  </button>
                );
              })}
            </div>

            {/* Right: Challenge Execution Console */}
            <div className="lg:col-span-8 space-y-6">
              {/* Mission Briefing */}
              <CyberCard>
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <h3 className="text-white font-semibold flex items-center gap-2">
                    <FileCode className="w-5 h-5 text-neon-cyan" />
                    Mission: {currentScenario.title}
                  </h3>
                  <span className="text-xs px-2.5 py-1 rounded bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/30 font-mono">
                    Target: {currentScenario.targetEndpoint}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mb-4">
                  {currentScenario.targetObjective}
                </p>

                {/* Vertically Stacked Code Comparison */}
                <div className="flex flex-col gap-4 mb-4">
                  <div className="bg-cyber-black/80 p-3 rounded-lg border border-red-500/40">
                    <div className="flex items-center gap-2 text-xs font-semibold text-red-400 mb-2">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Vulnerable API Implementation
                    </div>
                    <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre">
                      {currentScenario.vulnerableSnippet}
                    </pre>
                  </div>

                  <div className="bg-cyber-black/80 p-3 rounded-lg border border-emerald-500/40">
                    <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-2">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Hardened Defense Implementation
                    </div>
                    <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre">
                      {currentScenario.secureSnippet}
                    </pre>
                  </div>
                </div>

                {/* Hints */}
                <div className="bg-cyber-dark/60 p-3 rounded border border-cyber-border text-xs text-slate-400 space-y-1">
                  <span className="font-semibold text-neon-cyan">Tactical Guidance:</span>
                  <ul className="list-disc list-inside space-y-0.5 mt-1">
                    {currentScenario.hints.map((hint, idx) => (
                      <li key={idx}>{hint}</li>
                    ))}
                  </ul>
                </div>
              </CyberCard>

              {/* Action Console & Verdict */}
              <CyberCard>
                <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                  <div className="flex items-center gap-3">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={defenseActive}
                        onChange={(e) => {
                          setDefenseActive(e.target.checked);
                          setChallengeResult(null);
                        }}
                        className="rounded border-cyber-border text-neon-cyan focus:ring-neon-cyan bg-cyber-black w-4 h-4"
                      />
                      Enable Gateway Defense Patch
                    </label>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                        defenseActive
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                          : 'bg-rose-950 text-rose-400 border border-rose-700'
                      }`}
                    >
                      {defenseActive ? 'Defense Active' : 'Vulnerable Mode'}
                    </span>
                  </div>

                  <AnimatedButton onClick={handleRunChallenge} className="flex items-center gap-2 text-xs">
                    <Play className="w-3.5 h-3.5" />
                    Test Request Against Target
                  </AnimatedButton>
                </div>

                {/* Token or Hash payload sent */}
                <div className="mb-4">
                  <label className="block text-xs font-semibold text-slate-400 mb-1">
                    Outbound Authorization Header / Payload Sent:
                  </label>
                  <div className="p-2.5 rounded bg-cyber-black border border-cyber-border font-mono text-xs text-slate-200 break-all">
                    {selectedScenarioId === 'crypto_unsalted_hashes'
                      ? currentScenario.initialHash
                      : tokenInput || '(No token provided)'}
                  </div>
                </div>

                {/* Live Execution Output & Security Analysis */}
                {challengeResult && (
                  <div className="space-y-4 pt-4 border-t border-cyber-border">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                        <Terminal className="w-4 h-4 text-neon-cyan" />
                        Simulated API Gateway Execution Trace
                      </span>
                      <span
                        className={`text-xs px-2.5 py-1 rounded font-mono font-bold ${
                          challengeResult.statusCode === 200
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                            : 'bg-rose-950 text-rose-400 border border-rose-700'
                        }`}
                      >
                        HTTP {challengeResult.statusCode}
                      </span>
                    </div>

                    <pre className="p-3 rounded-lg bg-cyber-black font-mono text-xs text-slate-300 overflow-x-auto border border-cyber-border">
                      {JSON.stringify(challengeResult.responseBody, null, 2)}
                    </pre>

                    <div
                      className={`p-3.5 rounded-lg border text-xs leading-relaxed ${
                        challengeResult.passed
                          ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-200'
                          : 'bg-rose-950/40 border-rose-700/60 text-rose-200'
                      }`}
                    >
                      <div className="font-semibold flex items-center gap-1.5 mb-1">
                        {challengeResult.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400" />
                        )}
                        Security Analysis Verdict
                      </div>
                      <p>{challengeResult.explanation}</p>
                      {challengeResult.attackVector && (
                        <div className="mt-2 text-[11px] font-mono text-slate-400">
                          Classified Vector: <span className="text-slate-200">{challengeResult.attackVector}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </CyberCard>
            </div>
          </div>
        )}

        {/* TAB 3: Offline Key Cracker & Hash Analysis */}
        {activeTab === 'cracker' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Offline Dictionary Cracker */}
            <CyberCard>
              <h3 className="text-white font-semibold flex items-center gap-2 mb-2">
                <Zap className="w-5 h-5 text-neon-cyan" />
                HMAC Secret Dictionary Cracker
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Demonstrates how attackers exploit symmetric HMAC-SHA256 tokens offline. By computing hashes locally
                without sending requests to the API, weak passwords are recovered in milliseconds.
              </p>

              <div className="space-y-3 mb-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Target JWT Token:</label>
                  <textarea
                    value={crackerToken}
                    onChange={(e) => setCrackerToken(e.target.value)}
                    rows={3}
                    className="w-full bg-cyber-black p-2.5 rounded font-mono text-xs text-slate-300 border border-cyber-border focus:outline-none focus:border-neon-cyan"
                  />
                </div>

                <div className="text-xs text-slate-400">
                  <span>Testing Wordlist: </span>
                  <span className="font-mono text-slate-300">{COMMON_WEAK_SECRETS.join(', ')}</span>
                </div>

                <AnimatedButton onClick={handleRunCracker} className="w-full text-xs py-2 flex items-center justify-center gap-2">
                  <Play className="w-3.5 h-3.5" />
                  Run Offline Dictionary Attack
                </AnimatedButton>
              </div>

              {crackResult && (
                <div
                  className={`p-3 rounded border text-xs space-y-1 ${
                    crackResult.cracked
                      ? 'bg-emerald-950/40 border-emerald-700 text-emerald-200'
                      : 'bg-rose-950/40 border-rose-700 text-rose-200'
                  }`}
                >
                  <div className="font-semibold flex items-center gap-1.5">
                    {crackResult.cracked ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    )}
                    {crackResult.cracked ? 'Secret Key Recovered!' : 'Cracking Attempt Failed'}
                  </div>
                  {crackResult.cracked && (
                    <div className="font-mono text-sm font-bold text-emerald-400 mt-1">
                      Signing Secret: "{crackResult.secret}"
                    </div>
                  )}
                  <div className="text-[11px] font-mono text-slate-400">
                    Tested {crackResult.attempts} candidates in {crackResult.timeMs}ms.
                  </div>
                </div>
              )}
            </CyberCard>

            {/* Standalone Key Entropy Calculator & Rainbow Table Lookup */}
            <div className="space-y-6">
              {/* Entropy Calculator */}
              <CyberCard>
                <h3 className="text-white font-semibold flex items-center gap-2 mb-2">
                  <KeyRound className="w-5 h-5 text-purple-400" />
                  Key Shannon Entropy Meter
                </h3>
                <p className="text-xs text-slate-400 mb-3">
                  Symmetric signing keys require at least 128 (ideally 256) bits of entropy to resist modern GPU clusters.
                </p>

                <div className="space-y-3">
                  <input
                    type="text"
                    value={entropyInputKey}
                    onChange={(e) => setEntropyInputKey(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-cyber-black border border-cyber-border text-slate-200 font-mono text-xs focus:outline-none focus:border-purple-400"
                    placeholder="Enter key to measure entropy..."
                  />

                  <div className="p-3 rounded bg-cyber-black/70 border border-cyber-border space-y-1 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Calculated Entropy:</span>
                      <span className="font-mono font-bold text-slate-200">{standaloneEntropy.entropy} bits/char</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Estimated Total Strength:</span>
                      <span className="font-mono font-bold text-slate-200">{standaloneEntropy.bits} bits</span>
                    </div>
                    <div className="flex items-center justify-between pt-1 border-t border-cyber-border/40">
                      <span className="text-slate-400">Security Grade:</span>
                      <span className={`font-mono font-bold ${standaloneEntropy.labelColor}`}>
                        {standaloneEntropy.rating}
                      </span>
                    </div>
                  </div>
                </div>
              </CyberCard>

              {/* Rainbow Table Lookup */}
              <CyberCard>
                <h3 className="text-white font-semibold flex items-center gap-2 mb-2">
                  <Database className="w-5 h-5 text-emerald-400" />
                  Unsalted Hash Rainbow Table Lookup
                </h3>
                <p className="text-xs text-slate-400 mb-3">
                  Unsalted MD5/SHA-1 password hashes are vulnerable to instant precomputed lookup.
                </p>

                <div className="space-y-3">
                  <input
                    type="text"
                    value={rainbowHashInput}
                    onChange={(e) => setRainbowHashInput(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-cyber-black border border-cyber-border text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-400"
                    placeholder="Enter 32-character MD5 hash..."
                  />

                  <button
                    onClick={handleRainbowLookup}
                    className="w-full text-xs py-2 rounded bg-emerald-950/70 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800 transition"
                  >
                    Query Rainbow Table
                  </button>

                  {rainbowResult && (
                    <div
                      className={`p-2.5 rounded border text-xs ${
                        rainbowResult.cracked
                          ? 'bg-emerald-950/50 border-emerald-700 text-emerald-200'
                          : 'bg-slate-900 border-slate-700 text-slate-300'
                      }`}
                    >
                      {rainbowResult.cracked ? (
                        <div>
                          <span className="font-bold text-emerald-400">REVERSED: </span>
                          Plaintext password is <span className="font-mono font-bold text-white">"{rainbowResult.plaintext}"</span>
                        </div>
                      ) : (
                        <span>Hash not found in standard demonstration table.</span>
                      )}
                    </div>
                  )}
                </div>
              </CyberCard>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ApiSecurityLab;
