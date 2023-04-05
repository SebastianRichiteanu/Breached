#!/bin/bash
source "breached_venv/bin/activate"

FLASK_APP=breached
FLASK_DEBUG=1
flask run