powershell -ep Bypass "breached_venv\bin\Activate.ps1";$env:FLASK_APP = "breached";$env:FLASK_DEBUG = 1;flask run --host=0.0.0.0