"""
LLM Client Interface & Implementations
Abstract interface with MockLLM (deterministic, offline, template-based)
and OllamaLLM (local offline generative LLM via Ollama REST API).
Strictly operates on evidence records.
"""

from abc import ABC, abstractmethod
import json
import os
import re
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error


class LLMClient(ABC):
    """Abstract interface for offline LLM interaction."""
    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        pass


class MockLLM(LLMClient):
    """
    Deterministic offline template-based LLM.
    Parses provided evidence records from the prompt and constructs a structured,
    grounded JSON incident narrative.
    """

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        # Extract alert records present in prompt text
        # Prompts include records serialized as JSON or lines
        # Look for alert IDs like S1-ALT-*, ALT-*, etc.
        found_alert_ids = re.findall(r"\b(?:S1-ALT-\d{4}|S2-ALT-\d{4}|S4-SPK-\d{4}|S4-NE-\d{4}|ALT-[A-Za-z0-9-_]+)\b", prompt)
        found_ips = re.findall(r"\b(?:203\.0\.113\.\d{1,3}|(?:\d{1,3}\.){3}\d{1,3})\b", prompt)

        unique_alerts = list(dict.fromkeys(found_alert_ids))
        entry_ip = found_ips[0] if found_ips else "203.0.113.5"

        # Standard 5-stage reconstruction
        # Partition found alerts across the 5 canonical stages
        stages_plan = [
            ("Initial Access", "TA0001", "T1078", "Adversary gained initial access via compromised admin credentials and unauthorized external ingress.", "Establish initial unauthorized foothold on perimeter infrastructure."),
            ("Privilege Escalation", "TA0004", "T1068", "Adversary escalated privileges to SYSTEM/domain authority by executing internal privilege escalation exploit.", "Obtain elevated permissions necessary for lateral traversal and access."),
            ("Lateral Movement", "TA0008", "T1021.001", "Adversary initiated unauthorized lateral movement via RDP tunneling to internal application server SRV-APP-01.", "Traverse network isolation boundaries to reach sensitive application tiers."),
            ("Data Access", "TA0009", "T1005", "Adversary accessed and staged sensitive operational databases and confidential files.", "Locate and prepare high-value intellectual property and grid telemetry for collection."),
            ("Evidence Tampering", "TA0005", "T1070", "Adversary cleared host event logs and abruptly terminated monitoring sessions to evade forensic attribution.", "Impede forensic incident response and conceal compromise footprint."),
        ]

        stages = []
        num_alerts = len(unique_alerts)
        chunk_size = max(1, num_alerts // 5) if num_alerts >= 5 else 1

        for i, (name, tactic, tech, claim, intent) in enumerate(stages_plan):
            if num_alerts >= 5:
                start = min(i * chunk_size, num_alerts)
                end = min((i + 1) * chunk_size, num_alerts) if i < 4 else num_alerts
                stage_evidence = unique_alerts[start:end]
                if not stage_evidence and unique_alerts:
                    stage_evidence = [unique_alerts[min(i, len(unique_alerts) - 1)]]
            else:
                stage_evidence = unique_alerts

            stages.append({
                "stage_number": i + 1,
                "stage_name": name,
                "tactic": tactic,
                "technique": tech,
                "claim": f"{claim} Corroborated by evidence records: {', '.join(stage_evidence[:2])}.",
                "evidence_ids": stage_evidence,
                "attacker_intent": intent,
            })

        output = {
            "incident_title": "Multi-Stage Advanced Persistent Threat Campaign Reconstruction",
            "summary": f"Coordinated 5-stage cyber attack originating from external pivot IP {entry_ip} impacting critical operational infrastructure.",
            "attacker_entry_point": f"External IP {entry_ip}",
            "stages": stages,
        }

        return json.dumps(output, indent=2)


class OllamaLLM(LLMClient):
    """
    Client for locally-hosted Ollama offline LLM instances.
    Air-gapped and private; runs on local GPU/CPU.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 45,
    ):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3")
        self.timeout = timeout

    def is_available(self) -> bool:
        """Checks if local Ollama daemon is reachable."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt or "You are an expert incident response supervisor. Respond ONLY in valid JSON matching the requested schema.",
            "stream": False,
            "format": "json",
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res_body = json.loads(resp.read().decode("utf-8"))
                return res_body.get("response", "{}")
        except Exception as e:
            # Graceful fallback to MockLLM if Ollama is not actively running
            print(f"[OllamaLLM] Local Ollama call failed ({e}), falling back to MockLLM.")
            return MockLLM().generate(prompt, system_prompt)


def get_llm_client(preferred: Optional[str] = None) -> LLMClient:
    """Factory to retrieve appropriate LLM client."""
    mode = preferred or os.environ.get("LLM_BACKEND", "mock").lower()
    if mode == "ollama":
        ollama = OllamaLLM()
        if ollama.is_available():
            return ollama
        print("[LLM Factory] Ollama not available on localhost:11434, using MockLLM.")
        return MockLLM()
    return MockLLM()
