# Phishing Detection Tool

A comprehensive, real-time security solution designed to detect and block phishing attempts. This project combines a robust Python backend (utilizing rule-based analysis, a custom machine learning model, and Google Gemini LLM deep validation) with a **Chrome Extension (Plugin)** and an **Expo React Native Mobile App** to protect users across devices.

## 🏗️ System Architecture

The security validation operates on a **3-Layer Hybrid Detection System**:

```
                       [ Incoming URL Request ]
                                  │
                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│ Layer 1,2,3:  Heuristic, Blacklist, Domain and SSL analysis  
└─────────────────────────────────┬─────────────────────────────────┘
                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│ Layer 4: Machine Learning Model (XGBoost) │
└─────────────────────────────────┬─────────────────────────────────┘
                                  ▼
                      [ Calculate Fast Path Score ]
                                  │
             ┌────────────────────┴────────────────────┐
             │ Fast Score ≤ 18                         │ 18 < Fast Score ≤ 51.90
             ▼ (Clearly Safe / Unsafe)                 ▼ (Grey Zone / Suspicious)
    ┌─────────────────┐             ┌───────────────────────────────────────────┐
    │  Safe / Unsafe  │             │ Layer 5: Deep LLM Analysis (Gemini Vision)│
    │  Fast Decision  │             └─────────────────────┬─────────────────────┘
    └─────────────────┘                                   ▼
                                            ┌───────────────────────────┐
                                            │ Logo & Branding Cross-    │
                                            │ Match (Domain Alignment)  │
                                            └─────────────┬─────────────┘
                                                          ▼
                                            ┌───────────────────────────┐
                                            │   Final Hybrid Verdict    │
                                            └───────────────────────────┘
```

1. **Layer 1,2,3: Heuristic, Blacklist, Domain and SSL analysis** – Runs instant checks on URL length, subdomains, suspicious keywords, SSL availability, and WHOIS domain age.
2. **Layer 4: Machine Learning** – A trained classification model extracts numerical features from the URL structure and predicts a phishing probability.
3. **Layer 5: Deep LLM Analysis (Google Gemini)** – If the URL falls in an uncertain "grey zone" (Fast Path Score between 18.0 and 51.9), the system triggers Gemini to fetch the page content, inspect metadata, examine logos, and cross-reference domain ownership to detect homoglyphs and impersonations.

## 📂 Project Directory Structure

```filepath
Phising-Detection-Web-Tool/
├── backend/                  # Flask Python Backend API
│   ├── app.py                # Main server and endpoints (/analyze, /analyze-deep)
│   ├── ml_model.py           # Feature extraction and ML prediction loader
│   ├── llm_analyzer.py       # Gemini API integration & logo/content crawlers
│   ├── scoring.py            # Weighting engine & configuration manager
│   ├── requirements.txt      # Python dependencies
│   └── models/               # model_training_ml.pkl
│   ├── evaluation/           # Evaluate fast path system, full path system
├── plugin/                   # Chrome Extension (Manifest V3)
│   ├── manifest.json         # Extension permissions and configurations
│   ├── background.js         # Service worker intercepting web requests
│   ├── checks.js             # API connection client & offline fallback heuristics
│   └── warning.html/js/css   # Redirection warning screen
├── mobileAppDetection/       # React Native Expo Mobile App
│   ├── App.js                # Main application UI and scanner views
│   ├── package.json          # Node dependencies & Expo scripts
│   └── assets/               # Icons and splash images
└── colab_notebooks/          # Training scripts & datasets
    ├── machine_learning_integration.ipynb # Notebook used to train model in Google colab
    └── model_feature_config.json          # Configuration list of ML features
```
## 🛠️ Prerequisites & Development Environment

To run the full suite locally, you will need the following tools installed on your development machine:

* **Node.js**: Version 18.0.0 or higher ([Download Node.js](https://nodejs.org/))
* **Python**: Version 3.9 to 3.12 ([Download Python](https://www.python.org/))
* **Google Chrome**: Needed to test the browser extension unpacked.
* **Expo Go / Emulator**: To run the mobile app, install **Expo Go** on your physical phone (Android/iOS) or configure **Android Studio Emulator** / **Xcode Simulator**.

## 🚀 Step-by-Step Setup Guide

### 1. Set Up and Run the Backend Server

The backend runs on Python Flask. It is preconfigured with a trained ML model and a default pool of Gemini API keys for development.

#### Step 1: Initialize the Virtual Environment
Navigate to the root directory of the project and activate the virtual environment (`venv` is already included in the repository structure).

* **On Windows (PowerShell):**
  ```powershell
  # If venv is not initialized, run: python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
* **On Windows (Command Prompt):**
  ```cmd
  .\venv\Scripts\activate.bat
  ```
* **On macOS/Linux:**
  ```bash
  source venv/bin/activate
  ```

#### Step 2: Install Python Dependencies
```bash
cd backend
pip install -r requirements.txt
```

#### Step 3: Configure API Keys (Optional)
Open [backend/llm_analyzer.py](file:/backend/llm_analyzer.py) to inspect or modify the Gemini API keys. The system uses a fallback rotation mechanism. 

Open the Google api key website: https://aistudio.google.com/app/apikey
Choose tab 'API Keys'
Click button 'Create API key'
Name the key, Choose an imported project - create new project
Click create key
Click copy key and paste your own Gemini API keys directly into the `API_KEYS` list:
```python
API_KEYS = [
    "YOUR_GEMINI_API_KEY_1",
    "YOUR_GEMINI_API_KEY_2",
    # ...
]
```

#### Step 4: Start the Server
Run the Flask application at backend direction:
```bash
python app.py or py app.py
```
The server will boot up locally at: **`http://127.0.0.1:5000`**

To verify it is active, open `http://127.0.0.1:5000/` in your browser. You should see a JSON payload listing the status as `"running"` and confirming the ML model is loaded.

### 2. Load the Chrome Extension (Plugin)
The Chrome extension monitors your active browser tabs and blocks unsafe websites by communicating with the backend.

1. Open Google Chrome.
2. Navigate to the extensions page by typing **`chrome://extensions/`** in the URL bar.
3. Enable **Developer mode** using the toggle switch in the upper-right corner.
4. Click the **Load unpacked** button in the top-left corner.
5. In the file explorer popup, select the **`plugin`** directory from this repository.
6. The extension is now active! 

#### How to Test:
* Ensure the Python Backend is running.
* Try opening a domain in Chrome. If the backend classifies it as malicious (e.g. `http://fake-login-bank.net`), you will be immediately redirected to the built-in warning page (`warning.html`) showing the safety breakdown score.

### 3. Run the Mobile Application (Expo)

The mobile app provides a search-bar scanner, deep-link intercept simulation, and local fallback heuristics.

#### Step 1: Install Node Dependencies
Navigate into the mobile project folder and run `npm install`:
```bash
cd mobileAppDetection
npm install
```

#### Step 2: Configure the Backend API Connection (CRITICAL DEV STEP)
By default, the mobile app points to `http://127.0.0.1:5000/analyze` in [mobileAppDetection/App.js]

#### Step 3: Start the Expo Metro Bundler
Start the development server:
```bash
npm start or npx expo start
```
› Press a │ open Android
› Press w │ open web
› Press r │ reload app

##  Simulation and Testing

Once all components are running, you can test the phishing detection engine:

### 1. Chrome Extension Test
Open a browser tab and navigate to:
* `http://phish-update-secure.com` 
* At the UI: blocked instantly
* At the backend: Show fast path score, LLM score, final score, status, warning reason.
*Click 'Open' to access the link. Click 'Go back' to navigate back to the default state

* `http://www.youtube.com` 
* At the UI: allow to access immediately
* At the backend: Show fast path score, final score, status.
* Click 'Open' to access the link. Click 'Go back' to navigate back to the default state

### 2. Mobile App Test
1. Open the app simulation or the web version (press a or w)
2. Type any URL in the top search box and tap **Check** to see the popup result
3. Click 'Open' to access the link. Click 'Go back' to navigate back to the default state

---

## 🔍 Troubleshooting

* **Backend `ModuleNotFoundError`**: Ensure you activated `venv` before running `pip install -r requirements.txt`. If issues persist, check that your default python version is compatible (v3.9 - v3.12).
* **Mobile app fails to scan (Offline fallback triggers immediately)**:
  1. Confirm your computer and phone are on the same Wi-Fi network.
  2. Confirm you updated the IP address in `App.js` to your host computer's wireless IP (not Ethernet or VPN adapter IP).
  3. Ensure your computer's firewall is not blocking incoming requests on port `5000`.
* **Gemini rate limits**: If you see quota errors in the backend terminal logs, the backend will auto-rotate to another key in `llm_analyzer.py`. If all keys are exhausted, you can create a free key on [Google AI Studio](https://aistudio.google.com/) and replace the keys in `llm_analyzer.py`.
