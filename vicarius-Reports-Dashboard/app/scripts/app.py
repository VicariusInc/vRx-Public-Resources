from flask import Flask, request, render_template
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_script', methods=['POST'])
def run_script():
    script_name = request.form['script_name']
    try:
        script_path = f'scripts/{script_name}.py'
        result = subprocess.run(['python', script_path], capture_output=True, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        output = f"An error occurred:\n{e.stderr}"
    except FileNotFoundError:
        output = f"Script {script_name} not found."
    return render_template('index.html', output=output)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
