#!/bin/bash
source "breached_venv/bin/activate"

export FLASK_APP=breached
export FLASK_DEBUG=1
flask run --host=0.0.0.0