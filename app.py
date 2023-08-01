from flask import Flask, request, jsonify, render_template
from test import ipscan, detscan
import json

app = Flask(__name__)

results = {}
results1 = {}

@app.route('/')
def home():
    return render_template('index.html', results=results, results1=results1)

@app.route('/scan', methods=['POST'])
def pscan():
    ipr = str(request.form['a'])
    global results
    results = ipscan(ipr)
    return render_template('index.html', results=results, results1=results1)

@app.route('/dscan', methods=['POST'])
def dscan():
    ip = request.form.get("ip")
    port = '-'  # Assuming port is always '-' in this case
    global results1
    results1 = detscan(ip, port)
    response = {'results' : results1}    
    # return render_template('index.html', results=results, results1=results1)
    return json.dumps(response)


if __name__ == "__main__":
    app.run(debug=True)
