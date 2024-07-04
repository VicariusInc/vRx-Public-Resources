from django.shortcuts import render
from django.http import HttpResponse
import subprocess

def index(request):
    return render(request, 'myapp/index.html')

def update_all_tables(request):
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['--allreports']),

    ]
    log_file = "/var/log/Web-alltables.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")

def update_metabase_template(request):
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['--metabaseTempalateReplace']),
    ]
    log_file = "/var/log/Web-metabase_tempalte.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")

def create_mb_user(request):
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['--createMBUser']),
    ]
    log_file = "/var/log/Web-metabase_tempalte.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")

def update_refresh_tables(request):
    '''
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['-a']),
        ('scripts/VickyTopiaReportCLI.py',['-p']),
        ('scripts/VickyTopiaReportCLI.py',['-hp']),
        ('scripts/VickyTopiaReportCLI.py',['-v']),
    ]
    log_file = "/var/log/Web-refreshTables.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")
    '''
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['-a']),
        ('scripts/VickyTopiaReportCLI.py',['-p']),
        ('scripts/VickyTopiaReportCLI.py',['-hp']),
        ('scripts/VickyTopiaReportCLI.py',['-v']),
    ]
    log_file = "/var/log/Web-refreshTables.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")

def update_sync_tables(request):
    scripts = [
        ('scripts/VickyTopiaReportCLI.py',['-t']),
        ('scripts/VickyTopiaReportCLI.py',['-i']),
    ]
    log_file = "/var/log/Web-syncTables.log"
    output = ""
    for script, flags in scripts:
        try:
            with open(log_file, 'a') as f:
                result = subprocess.run(['python3', script] + flags, capture_output=True, text=True)
            output += f"Output of {script} with flags {flags}:\n{result.stdout}\n"
        except Exception as e:
            output += f"Error running {script} with flags {flags}: {str(e)}\n"
    
    return HttpResponse(f"<pre>{output}</pre>")
