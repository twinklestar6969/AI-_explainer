#!/usr/bin/env python3
"""
Check Bedrock model access and agreement status.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
import boto3
import json

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

bedrock_model_id = os.getenv("BEDROCK_MODEL_ID")
aws_region = os.getenv("AWS_REGION", "us-east-1")

print(f"Checking model access for: {bedrock_model_id}")
print(f"Region: {aws_region}")
print("=" * 80)

bedrock_client = boto3.client("bedrock", region_name=aws_region)

# Get model information
try:
    model_info = bedrock_client.get_foundation_model(modelIdentifier=bedrock_model_id)
    print("\nFOUNDATION MODEL DETAILS:")
    print(json.dumps(model_info, indent=2, default=str))
except Exception as e:
    print(f"ERROR getting model info: {e}")

# List model access grants
try:
    print("\n\nMODEL ACCESS:")
    grants = bedrock_client.list_model_access_grants()
    print(f"Total model access grants: {len(grants.get('grants', []))}")
    for grant in grants.get('grants', []):
        print(json.dumps(grant, indent=2, default=str))
except Exception as e:
    print(f"Note: {e}")

# Check if we can list custom models
try:
    print("\n\nCUSTOM MODELS:")
    custom_models = bedrock_client.list_custom_models()
    print(f"Total custom models: {len(custom_models.get('modelSummaries', []))}")
except Exception as e:
    print(f"Note: {e}")

print("\n" + "=" * 80)
print("\nTROUBLESHOOTING:")
print("-" * 80)
print("If you see 'Operation not allowed' or 'ValidationException' errors, this typically means:")
print("  1. The OpenAI model access has NOT been enabled in Bedrock console")
print("  2. Required agreements or model access not granted")
print("")
print("STEPS TO FIX:")
print("  1. Go to: https://console.aws.amazon.com/bedrock/home")
print("  2. In left sidebar, click: Model Access")
print("  3. Search for: 'GPT-5.6 Luna'")
print("  4. Look for the model status - check 'Access Status'")
print("  5. If status is 'Access Denied' or requires agreement:")
print("     - Click the model name")
print("     - Review and accept any required OpenAI agreements")
print("     - Click 'Request Model Access' or 'Accept Agreement'")
print("  6. Wait for access to be granted (usually instant)")
print("  7. Re-run: python scanner/main.py")
