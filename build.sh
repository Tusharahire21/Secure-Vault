#!/usr/bin/env bash
# build.sh — Render build script
# Runs once per deploy before the web service starts.

set -o errexit   # exit on any error

pip install --upgrade pip
pip install -r requirements.txt

# Collect static assets into /staticfiles (served by WhiteNoise)
python manage.py collectstatic --no-input

# Apply database migrations
python manage.py migrate
