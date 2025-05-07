from flask import Flask, render_template, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/demo')
def demo():
    """Show a demo visualization of a sample Kubernetes cluster"""
    return render_template('demo.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)