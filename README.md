# CyberShield

Educational Web Vulnerability Assessment & Attack/Defense Simulator.

## Run on Windows

1. Open this folder in VS Code.
2. Open Terminal.
3. Install Flask:

   pip install -r requirements.txt

4. Start:

   python app.py

5. Open:

   http://127.0.0.1:5000

The sign-in page is a visual recreation inspired by the referenced CyberShield AI sign-in experience. It is not connected to the original site's backend and the email login is a local demo.

All security functions are intended for authorized local lab/testing environments.

## SQL Injection Simulator

The project now includes a separate `/sql-injection` educational simulator. It uses an isolated in-memory SQLite database and compares an intentionally unsafe string-concatenated query with a secure parameterized query. The existing users table, signup/login flow, scanner, reconnaissance, vulnerability checks, attack simulator, defense simulator, and report are not replaced.
