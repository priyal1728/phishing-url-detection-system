# Phishing URL Detection System

## Project Overview
This project is a web-based phishing URL detection system created using Python and Flask. It analyzes URLs for common phishing indicators like missing HTTPS, IP-based hostnames, suspicious keywords, URL shorteners, unusual domain names, and long/misleading URL patterns. Based on these indicators, the system assigns a risk score and displays a risk category such as Low, Medium, or High.

The application also stores scan history in SQLite, allowing users to review previous URLs and their results. This project is intended for educational use and helps students understand phishing detection techniques in a practical way.

## TYBSc IT Project Plan

### 1. Introduction
Phishing is a cybercrime in which attackers trick users into visiting fake websites or clicking malicious links to steal personal or financial information. This project develops a simple yet effective web application for scanning URLs and identifying likely phishing patterns.

### 2. Problem Statement
People often click on deceptive links without verifying their authenticity. There is a need for educational tools that help users analyze suspicious links before entering sensitive information.

### 3. Objectives
- Understand phishing attacks and common URL-based warning signs.
- Build a web application using Python and Flask.
- Analyze URLs using predefined security rules.
- Calculate a risk score and classify the result.
- Store scan history in a SQLite database.
- Display practical safety recommendations.
- Test the application and maintain code in GitHub.

### 4. Scope of the Project
The system will accept a URL entered by the user, check for phishing indicators, calculate a risk score, and show safety guidance. The project will store previous scan records in SQLite and display them in a history page.

### 5. Main Modules
1. URL Input Module
   - Accepts the URL entered by the user.
   - Validates whether the format is correct.

2. URL Analysis Module
   - Checks for HTTPS usage.
   - Detects IP-based websites.
   - Identifies suspicious keywords like login, password, verify, bank, update.
   - Detects URL shorteners and unusual hostname structures.
   - Flags long or deceptive URL patterns.

3. Risk Assessment Module
   - Assigns points for each malicious indicator.
   - Calculates total risk score.
   - Classifies the results as Low, Medium, or High.

4. SQLite History Module
   - Saves each scan result with timestamp.
   - Displays previous scans and risk information.

5. Awareness and Safety Module
   - Provides practical recommendations for protecting users from phishing attacks.

### 6. Tools and Technologies
- Python 3.x
- Flask
- SQLite
- HTML, CSS
- VS Code
- GitHub

### 7. System Workflow
1. User enters a URL on the homepage.
2. The application validates the format.
3. Security rules are applied.
4. Risk score and category are calculated.
5. Results and recommendations are displayed.
6. The scan result is stored in SQLite.
7. User can view previous scan records on the history page.

## Step-by-Step Implementation

### Step 1: Set up the environment in VS Code
- Open VS Code.
- Create a new folder named `phishing_url_project`.
- Open the terminal in that folder.
- Create a virtual environment: `python -m venv .venv`
- Activate the virtual environment.
- Install Flask: `pip install flask`

### Step 2: Create the project structure
Project structure:
- `app.py` – main Flask application
- `templates/index.html` – home page
- `templates/result.html` – scan result page
- `templates/history.html` – scan history page
- `static/style.css` – styling
- `phishing_history.db` – SQLite database generated at runtime

### Step 3: Create the database schema
The SQLite database holds the following fields:
- `id` – unique record identifier
- `url` – scanned URL
- `score` – risk score from 0 to 100
- `risk_level` – Low, Medium, or High
- `indicators` – detected suspicious signs
- `scanned_at` – date and time of the scan

### Step 4: Implement URL validation and analysis
The application checks:
- whether the URL has a valid http/https scheme
- if the hostname is an IP address
- whether the URL uses a shortening service
- if suspicious keywords are present
- whether the URL contains unusual symbol patterns or long hostname

### Step 5: Assign risk score and classification
Example scoring logic:
- Missing HTTPS: +20
- IP address host: +30
- URL shortener: +25
- Suspicious keywords: +10 each
- Long URL: +10
- Hyphenated hostname: +10
- ‘@’ symbol in URL: +15

The system then applies:
- 0-34: Low risk
- 35-69: Medium risk
- 70-100: High risk

### Step 6: Build Flask routes
Routes to be defined:
- `/` – homepage and URL submission form
- `/history` – previous scans page
- `/` (POST) – analyze URL and save result

### Step 7: Save history in SQLite
Each valid URL scan is inserted into the database. The history page reads the database and displays earlier results in descending order.

### Step 8: Add user recommendations
The application should explain the detected problem and provide safe browsing advice. Example messages:
- Do not submit personal details
- Verify the link using the official website
- Check the website domain carefully
- Review browser warnings and security settings

### Step 9: Test the application
Test sample URLs such as:
- `https://www.google.com`
- `http://192.168.1.10/login.php`
- `https://bit.ly/456xyz`
- `https://secure-bank-login.com/update-account`

Confirm that the results match the expected categories.

### Step 10: Deploy and document
- Keep the code in GitHub
- Add README documentation
- Share screenshots and output examples
- Explain the purpose and limitations of the system

## How to Run the Project
1. Open a terminal in the project folder.
2. Activate the virtual environment:
   - Windows: `.venv\Scripts\activate`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Run the app:
   - `python app.py`
5. Open the browser at:
   - `http://127.0.0.1:5000`

## Important Note
This project is an educational tool intended to help users understand phishing indicators. It should not be treated as a definitive or production-grade malware detector.

## Project Summary
The Phishing URL Detection System is a practical TYBSc IT project that combines web development, cybersecurity awareness, and database management. It helps users detect suspicious URLs using rule-based analysis while also teaching safe online practices.
