import os
import requests

def diagnose_with_ollama(sanitized_text, model='llama3.2'):
    """Send only caller-provided sanitized text to a local Ollama server."""
    base=os.getenv('OLLAMA_URL','http://localhost:11434').rstrip('/')
    try:
        response=requests.post(base+'/api/generate',json={'model':model,'prompt':'Diagnose this sanitized application log. State likely root cause, evidence, and next safe debugging step. Do not infer redacted values.\n\n'+sanitized_text,'stream':False},timeout=45)
        response.raise_for_status()
        return response.json().get('response','No response returned.'), None
    except requests.RequestException as exc:
        return None, f"Could not reach local Ollama ({type(exc).__name__}). Check that Ollama is running and the model is available."
    except (ValueError, KeyError):
        return None, 'Ollama returned an unexpected response format.'
