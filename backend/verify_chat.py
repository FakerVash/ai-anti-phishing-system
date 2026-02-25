import requests
import json

BASE_URL = "http://localhost:5000/chat"

def test_chat(description, payload):
    print(f"\n--- Testing: {description} ---")
    try:
        response = requests.post(BASE_URL, json=payload)
        if response.status_code == 200:
            print("Status: Success")
            print("Response:", response.json().get("answer"))
        else:
            print(f"Status: Error {response.status_code}")
            print("Response:", response.text)
    except Exception as e:
        print(f"Connection Error: {e}")

# Test 1: General Greeting (No URL)
payload_greeting = {
    "question": "Hola, ¿quién eres?",
    "url": ""
}

# Test 2: General Security Question (No URL)
payload_general = {
    "question": "Dime para qué sirves",
    "url": ""
}

# Test 3: Specific URL Context (Simulated)
payload_context = {
    "question": "¿Es seguro este sitio?",
    "url": "http://suspicious-bank.com",
    "analysis_context": {
        "ai_risk_level": "Alto",
        "ai_analysis": "Sitio sospechoso de phishing bancario.",
        "heuristic": {"score": 85},
        "virustotal": {"stats": {"malicious": 2}}
    }
}

# Test 4: Project Knowledge
payload_project = {
    "question": "¿Qué hace este proyecto y cómo funciona?",
    "url": ""
}

if __name__ == "__main__":
    test_chat("General Greeting", payload_greeting)
    test_chat("General Purpose Question", payload_general)
    test_chat("Contextual Question", payload_context)
    test_chat("Project Knowledge Question", payload_project)
