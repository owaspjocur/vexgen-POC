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
