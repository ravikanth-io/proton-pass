from flask import Flask, jsonify, request
from smartpass.generator import generate
from smartpass.evaluator import evaluate_password

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "message": "SmartPass API is running successfully on Vercel 🚀"
    })

@app.route('/generate', methods=['POST'])
def generate_route():
    data = request.get_json() or {}
    length = data.get('length', 12)
    options = {
        'upper': data.get('upper', True),
        'lower': data.get('lower', True),
        'digits': data.get('digits', True),
        'symbols': data.get('symbols', True)
    }
    password = generate(length, **options)
    return jsonify({'password': password})

@app.route('/score', methods=['POST'])
def score_route():
    data = request.get_json() or {}
    password = data.get('password', '')
    result = evaluate_password(password)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
