import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
import time

load_dotenv()

def get_guardian_brain():
    """Initializes a resilient Gemini engine with auto-retries."""
    api_key = os.getenv("GOOGLE_API_KEY")
    
    # We'll use 1.5 Flash as a fallback if 2.0 is hitting limits
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash", 
        google_api_key=api_key,
        temperature=0,
        max_retries=6 # Helps with the 429 RESOURCE_EXHAUSTED errors
    )

if __name__ == "__main__":
    brain = get_guardian_brain()
    try:
        # A simple test to see if Hugin and Munin are awake
        response = brain.invoke("Eye of Odin system check. Status?")
        print(f"Guardian Response: {response.content}")
        print("\n[SUCCESS] Phase 3: Brain is online.")
    except Exception as e:
        print(f"[FAIL] Check your .env or API Quota: {e}")