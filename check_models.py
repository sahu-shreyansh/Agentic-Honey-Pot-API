import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("Skipping model check: No GEMINI_API_KEY found in .env")
else:
    print(f"Checking models with key ending in ...{api_key[-4:]}")
    try:
        genai.configure(api_key=api_key)
        found = False
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(f"AVAILABLE: {m.name}")
                found = True
        if not found:
            print("No models found with generateContent support.")
    except Exception as e:
        print(f"Error listing models: {e}")
