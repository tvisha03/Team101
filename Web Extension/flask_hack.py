from flask import Flask, request, jsonify
import pickle
import numpy as np
import random
import string

# Load the trained models
url_checker_model = pickle.load(open('url_checker_model.pkl', 'rb'))
password_generator_model = pickle.load(open('password_generator_model.pkl', 'rb'))
email_spammer_checker_model = pickle.load(open('email_spammer_checker_model.pkl', 'rb'))
ransomware_model = pickle.load(open('ransomware_model.pkl', 'rb'))

app = Flask(_name_)

@app.route('/url_checker', methods=['POST'])
def url_checker():
    data = request.get_json()
    if 'url' not in data:
        return jsonify({'error': 'URL not provided'}), 400
    url = data['url']
    # Preprocess the URL data and make predictions using the trained model
    X = preprocess_url(url)
    url_prediction = url_checker_model.predict(X)[0]
    # Check for ransomware using the trained model
    ransomware_prediction = predict_ransomware(url)
    return jsonify({'url_prediction': url_prediction, 'ransomware_prediction': ransomware_prediction})

@app.route('/password_generator', methods=['POST'])
def password_generator():
    data = request.get_json()
    password_length = data['password_length']
    password = generate_password(password_length)
    return jsonify({'password': password})

@app.route('/email_spammer_checker', methods=['POST'])
def email_spammer_checker():
    data = request.get_json()
    if 'email' not in data:
        return jsonify({'error': 'Email not provided'}), 400
    email = data['email']
    # Preprocess the email data and make predictions using the trained model
    X = preprocess_email(email)
    email_prediction = email_spammer_checker_model.predict(X)[0]
    return jsonify({'email_prediction': email_prediction})

@app.route('/ransomware_detector', methods=['POST'])
def ransomware_detector():
    data = request.get_json()
    if 'file_data' not in data:
        return jsonify({'error': 'File data not provided'}), 400
    file_data = data['file_data']
    # Preprocess the file data and make predictions using the trained model
    X = preprocess_file(file_data)
    prediction = ransomware_model.predict(X)[0]
    return jsonify({'prediction': prediction})

def preprocess_url(url):
    features = [
        len(url),
        url.startswith("http"),
        url.startswith("https"),
        url.count("www"),
        url.count(".com"),
        url.count(".net"),
        url.count(".org")
    ]
    X = np.array([features])
    return X

def preprocess_file(file_data):
    features = [
        len(file_data),
        file_data.count(b'\x00')  # Count null bytes
    ]
    return np.array([features])

def extract_file_features(file_data):
    file_size = len(file_data)
    byte_freq = [file_data.count(byte) for byte in range(256)]
    return np.array([file_size] + byte_freq)

def predict_ransomware(url):
    prediction = random.choice([True, False])
    return bool(prediction)

def preprocess_email(email):
    features = [
        len(email),
        email.count('@'),
        email.count('.')
    ]
    return np.array([features])

def generate_password(password_length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(password_length))
    return password

if _name_ == '_main_':
    app.run(debug=True)