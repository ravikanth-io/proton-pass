# api/index.py
from smartpass.spweb.api import app

# Expose app as "handler" for Vercel
handler = app
