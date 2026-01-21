#!/usr/bin/env python3
"""
Test Ollama connectivity from Docker container
"""
import requests
import json

print("=" * 60)
print("Testing Ollama Connectivity")
print("=" * 60)

# Test endpoints
endpoints = [
    "http://host.docker.internal:11434/v1/models",
    "http://localhost:11434/v1/models",  # For host mode
]

for endpoint in endpoints:
    print(f"\nTesting: {endpoint}")
    try:
        response = requests.get(endpoint, timeout=5)
        if response.status_code == 200:
            print(f"  ✓ Connection successful!")
            data = response.json()
            if 'data' in data:
                print(f"  Available models: {len(data['data'])}")
                for model in data['data'][:3]:
                    print(f"    - {model.get('id', 'unknown')}")
            break
        else:
            print(f"  ✗ HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  ✗ Connection refused")
    except requests.exceptions.Timeout:
        print(f"  ✗ Timeout")
    except Exception as e:
        print(f"  ✗ Error: {e}")

# Test chat completion
print("\n" + "=" * 60)
print("Testing Chat Completion API")
print("=" * 60)

chat_endpoint = "http://host.docker.internal:11434/v1/chat/completions"
payload = {
    "model": "alibayram/Qwen3-30B-A3B-Instruct-2507:latest",
    "messages": [{"role": "user", "content": "你好"}],
    "max_tokens": 50
}

print(f"\nEndpoint: {chat_endpoint}")
print(f"Model: {payload['model']}")

try:
    response = requests.post(chat_endpoint, json=payload, timeout=30)
    if response.status_code == 200:
        print("  ✓ Chat completion successful!")
        data = response.json()
        if 'choices' in data and len(data['choices']) > 0:
            message = data['choices'][0].get('message', {})
            content = message.get('content', '')
            print(f"  Response: {content[:100]}")
    else:
        print(f"  ✗ HTTP {response.status_code}")
        print(f"  Response: {response.text[:200]}")
except Exception as e:
    print(f"  ✗ Error: {e}")

print("\n" + "=" * 60)
print("Connectivity Test Complete")
print("=" * 60)
