@echo off
rem Saves a fresh snapshot of the live phishing feeds (OpenPhish, Phishunt).
rem Scheduled daily by Windows Task Scheduler; see README for how to set up or remove it.
cd /d "%~dp0.."
python -m src.collect >> "data\raw\live\collect_log.txt" 2>&1
