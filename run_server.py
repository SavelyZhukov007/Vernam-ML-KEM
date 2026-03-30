#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
import shutil
src = os.path.join(os.path.dirname(__file__), "web", "templates")
dst = os.path.join(os.path.dirname(__file__), "server", "templates")
os.makedirs(dst, exist_ok=True)
for f in os.listdir(src):
    shutil.copy(os.path.join(src, f), os.path.join(dst, f))
os.chdir(os.path.join(os.path.dirname(__file__), "server"))
from server.app import app
app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)