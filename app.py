from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from datetime import timedelta
import os
import io
import random

import re
from flask import flash

def is_strong_password(password):
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'\d', password) or
        not re.search(r'[!@#$%^&*]', password)):
        return False
    return True


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'

# Session timeout after inactivity
app.permanent_session_lifetime = timedelta(minutes=10)

# Flask-Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'alokdixit193@gmail.com'
app.config['MAIL_PASSWORD'] = 'lzjuakkeqsabwthv'
app.config['MAIL_DEFAULT_SENDER'] = 'alokdixit193@gmail.com'
mail = Mail(app)

db = SQLAlchemy(app)
ENCRYPTION_KEY = b'63upI2waVG8dZwDX9y1TgeNp9Wm--b9IuGF_chzf6io='
fernet = Fernet(ENCRYPTION_KEY)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200))


# Routes
@app.route('/')
def index():
    return render_template('index.html')

# ----------- User Routes -----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('register'))

        
        

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or Email already exists!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and check_password_hash(user.password, password):
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['temp_user_id'] = user.id

            msg = Message('Your OTP Code', recipients=[user.email])
            msg.body = f'Your OTP code is: {otp}'
            mail.send(msg)

            flash('OTP sent to your email.', 'success')
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'temp_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            session['user_id'] = session.pop('temp_user_id')
            session.pop('otp')
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect OTP.', 'error')

    return render_template('verify_otp.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    files = File.query.filter_by(uploader_id=session['user_id']).all()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)

            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)

            new_file = File(filename=filename, uploader_id=session['user_id'])
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded & encrypted successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(id=file_id, uploader_id=session['user_id']).first()
    if not file_record:
        flash('File not found or access denied.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('download_otp'):
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.filename + '.enc')
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = fernet.decrypt(encrypted_data)
            session.pop('download_otp')
            flash('File downloaded successfully.', 'success')
            return send_file(io.BytesIO(decrypted_data), download_name=file_record.filename, as_attachment=True)
        else:
            flash('Incorrect OTP.', 'error')

    otp = str(random.randint(100000, 999999))
    session['download_otp'] = otp

    user = User.query.get(session['user_id'])
    msg = Message('Your File Download OTP', recipients=[user.email])
    msg.body = f'Your OTP for file download is: {otp}'
    mail.send(msg)

    return render_template('download_otp.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

# ----------- Admin Routes -----------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            otp = str(random.randint(100000, 999999))
            session['admin_temp_id'] = admin.id
            session['admin_otp'] = otp

            msg = Message('Admin Login OTP', recipients=['YOUR_ADMIN_EMAIL@gmail.com'])
            msg.body = f'Your admin OTP is: {otp}'
            mail.send(msg)

            flash('OTP sent to admin email.', 'success')
            return redirect(url_for('admin_verify_otp'))
        else:
            flash('Invalid admin credentials.', 'error')

    return render_template('admin_login.html')

@app.route('/admin/verify_otp', methods=['GET', 'POST'])
def admin_verify_otp():
    if 'admin_otp' not in session or 'admin_temp_id' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['admin_otp']:
            session.pop('admin_otp')
            session['admin_id'] = session.pop('admin_temp_id')
            session.permanent = True  # Enables session timeout for admin
            flash('Admin login successful.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Incorrect OTP.', 'error')

    return render_template('admin_verify_otp.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    users = User.query.all()
    files = File.query.all()
    total_users = len(users)
    total_files = len(files)
    return render_template('admin_dashboard.html', users=users, files=files, total_users=total_users, total_files=total_files)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if user:
        files = File.query.filter_by(uploader_id=user.id).all()
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename + '.enc')
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(file)

        db.session.delete(user)
        db.session.commit()
        flash('User and associated files deleted.', 'success')
    else:
        flash('User not found.', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_file/<int:file_id>')
def delete_file(file_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    file = File.query.get(file_id)
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename + '.enc')
        if os.path.exists(file_path):
            os.remove(file_path)

        db.session.delete(file)
        db.session.commit()
        flash('File deleted successfully.', 'success')
    else:
        flash('File not found.', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_otp'] = otp
            session['reset_user_id'] = user.id

            msg = Message('Your Password Reset OTP', recipients=[user.email])
            msg.body = f'Your OTP to reset password is: {otp}'
            mail.send(msg)

            flash('OTP sent to your email.', 'success')
            return redirect(url_for('verify_reset_otp'))
        else:
            flash('Email not found.', 'error')
    
    return render_template('forgot_password.html')


@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_otp' not in session or 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['reset_otp']:
            session['allow_password_reset'] = True
            flash('OTP verified. Please set a new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Incorrect OTP.', 'error')

    return render_template('verify_reset_otp.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('allow_password_reset'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)

        user = User.query.get(session['reset_user_id'])
        user.password = hashed_password
        db.session.commit()

        session.pop('reset_otp', None)
        session.pop('reset_user_id', None)
        session.pop('allow_password_reset', None)

        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    with app.app_context():
        db.create_all()
    app.run(debug=True)
