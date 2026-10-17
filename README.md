# Ai-Based-Phishing-and-scam-awareness-tool

ScamSense checks pasted messages and URLs for common scam warning signs using explainable, rule-based heuristics. It does not use an AI/ML model, fetch URLs, or guarantee that content is safe.

## Run locally

Requires Python 3.9 or later.

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Run tests

```powershell
python -m unittest -v
```

## Privacy and limitations

Text submitted in the browser is sent to the Flask server running this app for analysis and is not persisted by the application. Avoid entering sensitive information. URL checks parse the supplied text only and never make network requests. Heuristic checks may miss scams or flag legitimate content; results are informational, not a safety guarantee.
