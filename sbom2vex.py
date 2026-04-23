"""
SBOM to VEX Generator using Microsoft Azure AI Foundry Agent
-----------------------------------------------------------
This script:
1. Loads a CycloneDX or SPDX SBOM (JSON format)
2. Sends it to a deployed Azure AI Foundry agent
3. Parses the agent's response into a valid VEX (CycloneDX VEX) document
4. Saves the VEX document to disk

Requirements:
    pip install azure-ai-projects azure-identity python-dotenv

Environment variables (.env):
    AZURE_PROJECT_ENDPOINT   – e.g. https://<hub>.services.ai.azure.com/...
    AZURE_AGENT_ID           – the deployed agent / assistant ID
    AZURE_SUBSCRIPTION_ID    – your Azure subscription ID
    AZURE_RESOURCE_GROUP     – resource group name
    AZURE_PROJECT_NAME       – AI Foundry project name
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

AZURE_PROJECT_ENDPOINT = os.getenv("AZURE_PROJECT_ENDPOINT")
AZURE_AGENT_ID = os.getenv("AZURE_AGENT_ID")

# Default sample SBOM (CycloneDX minimal) used when no file path is supplied
SAMPLE_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": {
            "type": "application",
            "name": "my-application",
            "version": "1.0.0",
        },
    },
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        {
            "type": "library",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        },
        {
            "type": "library",
            "name": "openssl",
            "version": "1.1.1k",
            "purl": "pkg:generic/openssl@1.1.1k",
        },
    ],
}

# System prompt that instructs the agent how to produce a VEX document
VEX_SYSTEM_PROMPT = """
You are a cybersecurity expert specialising in software supply chain security.
When the user provides an SBOM (Software Bill of Materials) in CycloneDX or
SPDX format, you must:

1. Identify every component listed in the SBOM.
2. For each component, assess known vulnerabilities (CVEs) based on your
   training knowledge and mark the VEX status as one of:
   - not_affected      – component is not affected by the CVE
   - affected          – component is affected and a fix/workaround exists
   - fixed             – vulnerability has been fixed in this version
   - under_investigation – status is currently unknown

3. Return ONLY a valid CycloneDX VEX JSON document (specVersion 1.5).
   Do NOT include markdown fences or any explanation outside the JSON.

The VEX JSON must follow this skeleton:
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "<new urn:uuid>",
  "version": 1,
  "metadata": { "timestamp": "<ISO-8601>", "component": { ... } },
  "vulnerabilities": [
    {
      "id": "<CVE-ID>",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/<CVE-ID>" },
      "ratings": [{ "source": { "name": "NVD" }, "score": <CVSS>, "severity": "<severity>", "method": "CVSSv3" }],
      "description": "<short description>",
      "affects": [
        {
          "ref": "<purl of affected component>",
          "versions": [{ "version": "<version>", "status": "<vex-status>" }]
        }
      ]
    }
  ]
}
"""


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def load_sbom(sbom_path: str | None) -> dict:
    """Load an SBOM from a JSON file, or return the built-in sample."""
    if sbom_path and Path(sbom_path).exists():
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom = json.load(f)
        print(f"[+] Loaded SBOM from {sbom_path}")
    else:
        sbom = SAMPLE_SBOM
        print("[!] No SBOM file provided – using built-in sample SBOM.")
    return sbom


def build_client() -> AIProjectClient:
    """Instantiate the Azure AI Project client using DefaultAzureCredential."""
    if not AZURE_PROJECT_ENDPOINT:
        raise EnvironmentError(
            "AZURE_PROJECT_ENDPOINT is not set. "
            "Please add it to your .env file or environment."
        )
    credential = DefaultAzureCredential()
    client = AIProjectClient(
        endpoint=AZURE_PROJECT_ENDPOINT,
        credential=credential,
    )
    print(f"[+] Connected to Azure AI Foundry project: {AZURE_PROJECT_ENDPOINT}")
    return client


def call_agent(client: AIProjectClient, sbom: dict) -> str:
    """
    Create a thread, post the SBOM, run the agent, and return the text reply.
    """
    if not AZURE_AGENT_ID:
        raise EnvironmentError(
            "AZURE_AGENT_ID is not set. "
            "Please add it to your .env file or environment."
        )

    agents = client.agents

    # 1. Create a new conversation thread
    thread = agents.create_thread()
    thread_id = thread.id
    print(f"[+] Created thread: {thread_id}")

    # 2. Post the SBOM as the user message
    user_content = (
        "Please analyse the following SBOM and generate a CycloneDX VEX document "
        "in JSON format only (no markdown, no explanation):\n\n"
        + json.dumps(sbom, indent=2)
    )

    agents.create_message(
        thread_id=thread_id,
        role="user",
        content=user_content,
    )
    print("[+] SBOM posted to thread.")

    # 3. Run the agent
    run = agents.create_run(
        thread_id=thread_id,
        assistant_id=AZURE_AGENT_ID,
        additional_instructions=VEX_SYSTEM_PROMPT,
    )
    run_id = run.id
    print(f"[+] Run started: {run_id}")

    # 4. Poll until the run is complete
    poll_interval = 3  # seconds
    max_wait = 300     # 5 minutes

    elapsed = 0
    while elapsed < max_wait:
        run_status = agents.get_run(thread_id=thread_id, run_id=run_id)
        status = run_status.status
        print(f"    Status: {status} ({elapsed}s elapsed)")

        if status == "completed":
            break
        elif status in ("failed", "cancelled", "expired"):
            raise RuntimeError(
                f"Agent run ended with status '{status}'. "
                f"Last error: {getattr(run_status, 'last_error', 'unknown')}"
            )

        time.sleep(poll_interval)
        elapsed += poll_interval
    else:
        raise TimeoutError("Agent run did not complete within the timeout period.")

    # 5. Retrieve the assistant's reply
    messages = agents.list_messages(thread_id=thread_id)
    for msg in reversed(messages.data):          # oldest → newest
        if msg.role == "assistant":
            for block in msg.content:
                if block.type == "text":
                    return block.text.value

    raise ValueError("No assistant message found in the thread.")


def extract_json(raw: str) -> dict:
    """
    Strip optional markdown fences and parse JSON from the agent response.
    """
    text = raw.strip()
    # Remove ```json ... ``` or ``` ... ``` fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(text)


def enrich_vex(vex: dict, sbom: dict) -> dict:
    """
    Ensure the VEX document has correct metadata sourced from the SBOM.
    """
    if "metadata" not in vex:
        vex["metadata"] = {}

    vex["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    vex["metadata"]["tools"] = [
        {"vendor": "Microsoft", "name": "Azure AI Foundry", "version": "latest"}
    ]

    # Carry over the target component from the SBOM if available
    sbom_component = sbom.get("metadata", {}).get("component")
    if sbom_component and "component" not in vex.get("metadata", {}):
        vex["metadata"]["component"] = sbom_component

    # Guarantee a new serial number so VEX and SBOM serials differ
    vex["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    return vex


def save_vex(vex: dict, output_path: str = "vex_document.json") -> None:
    """Write the VEX document to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(vex, f, indent=2, ensure_ascii=False)
    print(f"[+] VEX document saved to: {output_path}")


def print_summary(vex: dict) -> None:
    """Print a human-readable summary of the VEX findings."""
    vulns = vex.get("vulnerabilities", [])
    print("\n" + "=" * 60)
    print("VEX SUMMARY")
    print("=" * 60)
    print(f"Total vulnerabilities assessed: {len(vulns)}")
    for v in vulns:
        vid = v.get("id", "unknown")
        affects = v.get("affects", [])
        for affect in affects:
            ref = affect.get("ref", "unknown")
            for ver in affect.get("versions", []):
                status = ver.get("status", "unknown")
                version = ver.get("version", "")
                severity_list = v.get("ratings", [{}])
                severity = severity_list[0].get("severity", "unknown") if severity_list else "unknown"
                print(f"  [{severity.upper():8s}] {vid}  →  {ref}@{version}  [{status}]")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(sbom_path: str | None = None, output_path: str = "vex_document.json") -> None:
    """
    Orchestrate the full SBOM → VEX workflow.

    Args:
        sbom_path:   Path to a CycloneDX/SPDX SBOM JSON file. If None, the
                     built-in sample SBOM is used.
        output_path: Where to write the generated VEX JSON document.
    """
    print("\n=== SBOM → VEX Generator (Azure AI Foundry) ===\n")

    # Step 1 – Load SBOM
    sbom = load_sbom(sbom_path)

    # Step 2 – Connect to Azure AI Foundry
    client = build_client()

    # Step 3 – Call the agent
    raw_response = call_agent(client, sbom)
    print("\n[+] Received agent response.")

    # Step 4 – Parse and enrich the VEX document
    vex = extract_json(raw_response)
    vex = enrich_vex(vex, sbom)

    # Step 5 – Save and summarise
    save_vex(vex, output_path)
    print_summary(vex)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a CycloneDX VEX document from an SBOM using "
                    "an Azure AI Foundry agent."
    )
    parser.add_argument(
        "--sbom",
        type=str,
        default=None,
        help="Path to a CycloneDX or SPDX SBOM JSON file. "
             "Omit to use the built-in sample SBOM.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="vex_document.json",
        help="Output path for the generated VEX document (default: vex_document.json).",
    )

    args = parser.parse_args()
    main(sbom_path=args.sbom, output_path=args.output)
