# KI WebSecure

Simple Flask app for encrypting uploads and measuring performance.

Setup (local):

1. Copy `.env.example` to `.env` and fill values (do NOT commit `.env`).
2. Create virtualenv and install dependencies (example):

   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt

3. Initialize DB and run:

   python app.py

Notes:
- Keep `.env` out of version control. Use `.env.example` for the variable names.
- Use GitHub Secrets or your hosting provider's environment settings for production credentials.
