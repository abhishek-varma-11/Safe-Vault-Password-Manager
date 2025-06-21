from flask import Flask, render_template, request, redirect, url_for, session
import os
import base64
import random
import hashlib
import string
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = os.urandom(24)

bcrypt = Bcrypt(app)

# Connect to MongoDB Atlas
MONGO_URI = "mongodb+srv://<username>:<passowrd>@cluster0.sz0dx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['password_manager']
users_collection = db['users']

# Key Derivation Function
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Encryption Function
def encrypt_password(password, master_password, salt):
    key = derive_key(master_password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted).decode()

# Decryption Function
def decrypt_password(encrypted_password, master_password, salt):
    key = derive_key(master_password, salt)
    encrypted_data = base64.b64decode(encrypted_password)
    iv, encrypted = encrypted_data[:16], encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']
        confirm_password = request.form['confirm_password']
        secret_question = request.form['secret_question']
        secret_answer = request.form['secret_answer'].strip().lower()

        if users_collection.find_one({"username": username}):
            message = "User already exists"
        elif confirm_password != master_password:
            message = "Passwords you entered doesn't match"
        else:
            hashed_password = bcrypt.generate_password_hash(master_password).decode()
            salt = os.urandom(16)
            hashed_answer = bcrypt.generate_password_hash(secret_answer).decode()

            users_collection.insert_one({
                "username": username,
                "password": hashed_password,
                "salt": base64.b64encode(salt).decode(),
                "secret_question": secret_question,
                "secret_answer": hashed_answer,
                "passwords": {}
            })
            return redirect(url_for('login'))

    return render_template('signup.html', message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']
        user = users_collection.find_one({"username": username})

        if user and bcrypt.check_password_hash(user['password'], master_password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            message = "Invalid credentials"
    return render_template('login.html', message=message)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    message = None
    show_question = False
    question = ""
    username = ""

    if request.method == 'POST':
        if 'fetch_question' in request.form:
            username = request.form['username']
            user = users_collection.find_one({"username": username})
            if user:
                question = user.get("secret_question", "")
                show_question = True
            else:
                message = "User not found"

        elif 'reset_password' in request.form:
            username = request.form['username']
            answer = request.form['secret_answer'].strip().lower()
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            user = users_collection.find_one({"username": username})
            if not user:
                message = "User not found"
            elif not bcrypt.check_password_hash(user['secret_answer'], answer):
                message = "Incorrect answer to the secret question"
            elif new_password != confirm_password:
                message = "Passwords do not match"
            else:
                hashed = bcrypt.generate_password_hash(new_password).decode()
                users_collection.update_one({"username": username}, {"$set": {"password": hashed}})
                return redirect(url_for('login'))

    return render_template('forgot_password.html', message=message, show_question=show_question, question=question, username=username)


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    message = None

    if request.method == 'POST':
        website = request.form['website'].strip().lower()
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        master_password = request.form['master_password']

        user = users_collection.find_one({"username": session['username']})
        if not user:
            message = 'User not found'
        elif not bcrypt.check_password_hash(user['password'], master_password):
            message = 'Incorrect Master Password'
        else:
            salt = base64.b64decode(user['salt'])
            encrypted_password = encrypt_password(password, master_password, salt)
            users_collection.update_one(
                {"username": session['username']},
                {"$set": {f"passwords.{website}": {
                    "email": email,
                    "username": username,
                    "password": encrypted_password
                }}}
            )
            message = 'Password stored successfully'

    return render_template('add_password.html', message=message)

@app.route('/retrieve_password', methods=['GET', 'POST'])
def retrieve_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    message = None
    password_entries = {}

    if request.method == 'POST':
        website = request.form['website'].strip().lower()
        master_password = request.form['master_password']

        user = users_collection.find_one({"username": session['username']})
        if not user or 'passwords' not in user:
            message = "No passwords saved for this user"
        else:
            salt = base64.b64decode(user['salt'])
            entry = user['passwords'].get(website)
            if entry:
                try:
                    decrypted_password = decrypt_password(entry['password'], master_password, salt)
                    password_entries[website] = {
                        "username": entry['username'],
                        "email": entry['email'],
                        "password": decrypted_password
                    }
                except Exception:
                    message = "Incorrect master password"
            else:
                message = f"No password found for '{website}'"

    return render_template('retrieve_password.html', password_entries=password_entries, message=message)

@app.route('/delete_password', methods=['POST'])
def delete_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    website = request.form.get('website', '').strip().lower()
    user = users_collection.find_one({"username": session['username']})

    if not user or 'passwords' not in user or website not in user['passwords']:
        message = f'No password stored for "{website}"'
    else:
        users_collection.update_one(
            {"username": session['username']},
            {"$unset": {f"passwords.{website}": ""}}
        )
        message = f'Password for "{website}" deleted successfully'

    return redirect(url_for('retrieve_password', message=message))

@app.route('/password_generator', methods=['GET', 'POST'])
def password_generator():
    if request.method == 'POST':
        base_string = request.form['base_string']
        required_specials = request.form['required_specials']
        required_numbers = request.form['required_numbers']
        length = int(request.form['length'])

        if length < 10:
            return render_template('password_generator.html', error="Password must be at least 10 characters long.")

        if length < 12 and 'proceed' not in request.form:
            return render_template('password_generator.html', recommend=True, base_string=base_string, 
                                   required_specials=required_specials, required_numbers=required_numbers, length=length)

        password = secure_password(base_string, required_specials, required_numbers, length)
        return render_template('password_generator.html', password=password)

    return render_template('password_generator.html')

def secure_password(base_string, special_chars, numbers, length):
    if not special_chars:
        special_chars = '!@#$%'
    if not numbers:
        numbers = '1234567890'

    base_length = len(base_string)

    if base_length >= length:
        password = list(base_string[:length])
        if not any(c in special_chars for c in password):
            password[0] = random.choice(special_chars)
        if not any(c in numbers for c in password):
            password[1] = random.choice(numbers)
        letters = [c for c in password if c.isalpha()]
        if letters:
            selected = random.choice(letters).lower()
            password = [c.upper() if c.lower() == selected else c for c in password]
        return ''.join(password)

    remaining_length = length - base_length
    required = [random.choice(special_chars), random.choice(numbers)]
    remaining_length -= len(required)
    filler_pool = list(base_string + special_chars + numbers)
    filler = ''.join(random.choices(filler_pool, k=remaining_length))
    combined = list(''.join(required) + filler)
    random.shuffle(combined)
    password = base_string + ''.join(combined)
    letters = [c for c in base_string if c.isalpha()]
    if letters:
        selected = random.choice(letters).lower()
        password = ''.join([c.upper() if c.lower() == selected else c for c in password])
    return password

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({"username": session['username']})

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not bcrypt.check_password_hash(user['password'], old_password):
            return render_template('settings.html', message="Incorrect current password", category="error")

        if new_password != confirm_password:
            return render_template('settings.html', message="New passwords do not match", category="error")

        new_hashed_password = bcrypt.generate_password_hash(new_password).decode()
        users_collection.update_one(
            {"username": session['username']},
            {"$set": {"password": new_hashed_password}}
        )
        return render_template('settings.html', message="Password updated successfully", category="success")

    return render_template('settings.html')

@app.route('/password_strength', methods=['GET', 'POST'])
def password_strength():
    strength_result = None
    if request.method == 'POST':
        password = request.form['password_input']
        strength_result = evaluate_strength(password)
    return render_template('password_strength.html', strength_result=strength_result)

def evaluate_strength(password):
    score = 0
    length = len(password)

    if length >= 8: score += 1
    if length >= 12: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/~`" for c in password): score += 1

    if score >= 5:
        return "✅ Strong password: Secure and reliable."
    elif score >= 3:
        return "⚠️ Medium strength: Consider improving length or complexity."
    else:
        return "❌ Weak password: Too short or predictable."

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
