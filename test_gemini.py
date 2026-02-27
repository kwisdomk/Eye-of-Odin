from langchain_google_genai import ChatGoogleGenerativeAI
import os
from dotenv import load_dotenv

load_dotenv()

# Use 1.5-flash for maximum uptime during the hackathon
llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash", 
    google_api_key=os.getenv("GOOGLE_API_KEY"),
    temperature=0,
    max_retries=6 # This is your shield; it forces a retry after that 20s delay
)

try:
    response = llm.invoke("You are a cybersecurity AI. Say: CyberSentinel is ready.")
    print(f"Success: {response.content}")
except Exception as e:
    print(f"Error: {e}")