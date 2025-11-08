import os
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import numpy as np
import base64
import json
from PIL import Image
import io
import uuid
import re
import time
from fpdf import FPDF

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import google.generativeai as genai
from deepface import DeepFace
from scipy.spatial.distance import cosine


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-for-sessions'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['DATABASE'] = 'database.db'
app.config['TEMP_FOLDER'] = 'static/uploads/temp'

# ✅ Add this line to fix 413 Request Entity Too Large
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit (you can increase if needed)

# Email and API keys
GEMINI_API_KEY = "AIzaSyDwi2skn6WWEkAwZuNBTMuY2b_bTIwmGOw"
GMAIL_USER = "chinhodisha@gmail.com"
GMAIL_PASSWORD = "bqou fkyy wfwu fkjo"



genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, user_type TEXT NOT NULL, is_email_verified INTEGER DEFAULT 0,
        otp TEXT, otp_expiry DATETIME
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS user_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, is_verified INTEGER DEFAULT 0,
        recent_photo TEXT, dental_xray TEXT, aadhaar_card TEXT, blood_group_report TEXT,
        aadhaar_name TEXT, aadhaar_relation TEXT, aadhaar_dob TEXT, aadhaar_address TEXT,
        aadhaar_gender TEXT, aadhaar_contact TEXT, aadhaar_no TEXT,
        blood_group TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS face_encodings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        encoding TEXT NOT NULL,
        FOREIGN KEY (profile_id) REFERENCES user_profiles (id)
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, status TEXT NOT NULL,
        photo_path TEXT, name TEXT, age INTEGER, hair_color TEXT, eye_color TEXT, skin_color TEXT,
        identity_marks TEXT, height TEXT, weight TEXT, aadhaar TEXT, contact_no TEXT, clothing_description TEXT,
        other_details TEXT, last_seen_date TEXT, last_seen_time TEXT, last_seen_location TEXT,
        report_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (reporter_id) REFERENCES users (id)
    )
    ''')
    try:
        c.execute("SELECT blood_group FROM user_profiles LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE user_profiles ADD COLUMN blood_group TEXT")

    try:
        c.execute("SELECT aadhaar_no FROM user_profiles LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE user_profiles ADD COLUMN aadhaar_no TEXT")

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def clean_aadhaar_number(num_str):
    if not num_str:
        return ""
    return re.sub(r'\D', '', num_str)


def send_otp_email(email, otp):
    try:
        msg = MIMEText(f"Your OTP for Lost and Found Odisha is: {otp}")
        msg['Subject'] = 'Email Verification OTP'
        msg['From'] = GMAIL_USER
        msg['To'] = email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def create_fir_report(report_data, reporter_data):
    """Generates a styled, single-page PDF report resembling a modern FIR."""
    COLOR_DARK_GREY = (45, 45, 45)
    COLOR_MEDIUM_GREY = (90, 95, 115)
    COLOR_LIGHT_GREY = (170, 170, 170)
    COLOR_PURPLE = (92, 53, 168)
    class PDF(FPDF):
        def header(self):
            logo_path = os.path.join('static', 'logo.png')
            if os.path.exists(logo_path):
                self.image(logo_path, 10, 12, 18)
            self.set_font('Arial', 'B', 22)
            self.set_text_color(*COLOR_DARK_GREY)
            self.cell(0, 10, 'FIRST INFORMATION REPORT', 0, 1, 'C')
            self.set_font('Arial', '', 10)
            self.set_text_color(*COLOR_MEDIUM_GREY)
            self.cell(0, 6, 'CHINH - Lost & Found Initiative, Government of Odisha', 0, 1, 'C')
            self.set_draw_color(*COLOR_LIGHT_GREY)
            self.set_line_width(0.5)
            self.line(10, 32, 200, 32)
            self.ln(15)
        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.set_text_color(*COLOR_LIGHT_GREY)
            self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')

    pdf = PDF('P', 'mm', 'A4')
    pdf.add_page()
    pdf.set_auto_page_break(False)

    def draw_section_header(title):
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(*COLOR_PURPLE)
        pdf.cell(0, 8, title, 0, 1, 'L')
        pdf.set_draw_color(*COLOR_DARK_GREY)
        pdf.set_line_width(0.2)
        pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)
    def add_single_row(label, value):
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(*COLOR_MEDIUM_GREY)
        pdf.cell(50, 7, label, align='L')
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(*COLOR_DARK_GREY)
        pdf.multi_cell(0, 7, str(value) if value else "N/A", align='L')
    def add_double_row(label1, value1, label2, value2):
        y_start = pdf.get_y()
        pdf.set_x(10)
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(*COLOR_MEDIUM_GREY)
        pdf.cell(30, 7, label1, align='L')
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(*COLOR_DARK_GREY)
        pdf.cell(65, 7, str(value1) if value1 else "N/A", align='L')
        pdf.set_x(110)
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(*COLOR_MEDIUM_GREY)
        pdf.cell(30, 7, label2, align='L')
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(*COLOR_DARK_GREY)
        pdf.cell(0, 7, str(value2) if value1 else "N/A", align='L')
        pdf.set_y(y_start + 7)

    ts_obj = datetime.strptime(report_data['report_timestamp'], '%Y-%m-%d %H:%M:%S')
    add_double_row('Report ID:', f"CHINH-{report_data['id']:06d}", 'Date & Time:', ts_obj.strftime('%d-%b-%Y, %I:%M %p'))
    add_double_row('Report Type:', str(report_data['status']).upper(), 'Reported By:', reporter_data['name'])
    pdf.ln(2)

    date_label = "Date Last Seen:" if report_data['status'] == 'lost' else "Date Found:"
    location_label = "Location:"
    draw_section_header('1. Incident Particulars')
    add_double_row(date_label, report_data['last_seen_date'], 'Approx. Time:', report_data['last_seen_time'])
    add_single_row(location_label, report_data['last_seen_location'])
    draw_section_header(f'2. Details of {report_data["status"].capitalize()} Person')

    photo_path_to_draw = None
    if report_data['photo_path']:
        photo_full_path = os.path.join(app.config['UPLOAD_FOLDER'], report_data['photo_path'])
        if os.path.exists(photo_full_path):
            photo_path_to_draw = photo_full_path

    if photo_path_to_draw:
        y_start_details = pdf.get_y()
        photo_height = 60
        pdf.image(photo_path_to_draw, x=140, y=y_start_details, w=50)
        photo_end_y = y_start_details + photo_height
        def add_detail_in_column(label, value, x_pos, label_w, value_w):
            pdf.set_x(x_pos)
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(*COLOR_MEDIUM_GREY)
            pdf.cell(label_w, 7, label, align='L')
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(*COLOR_DARK_GREY)
            pdf.multi_cell(value_w, 7, str(value) if value else "N/A", align='L')
        current_y = y_start_details
        add_detail_in_column('Full Name:', report_data['name'], 10, 25, 45)
        add_detail_in_column('Approx. Age:', report_data['age'], 75, 25, 35)
        pdf.set_y(current_y + 8)
        current_y = pdf.get_y()
        add_detail_in_column('Height:', report_data['height'], 10, 25, 45)
        add_detail_in_column('Hair Color:', report_data['hair_color'], 75, 25, 35)
        pdf.set_y(current_y + 8)
        current_y = pdf.get_y()
        add_detail_in_column('Eye Color:', report_data['eye_color'], 10, 25, 45)
        add_detail_in_column('Skin Tone:', report_data['skin_color'], 75, 25, 35)
        pdf.set_y(current_y + 8)
        current_y = pdf.get_y()
        add_detail_in_column('Aadhaar:', report_data['aadhaar'], 10, 25, 45)
        pdf.set_y(current_y + 8)
        add_single_row('Distinctive Marks:', report_data['identity_marks'])
        add_single_row('Clothing Worn:', report_data['clothing_description'])
        final_y = max(pdf.get_y(), photo_end_y)
        pdf.set_y(final_y)
    else:
        add_double_row('Full Name:', report_data['name'], 'Approx. Age:', report_data['age'])
        add_double_row('Height:', report_data['height'], 'Hair Color:', report_data['hair_color'])
        add_double_row('Eye Color:', report_data['eye_color'], 'Skin Tone:', report_data['skin_color'])
        add_single_row('Aadhaar (if any):', report_data['aadhaar'])
        add_single_row('Distinctive Marks:', report_data['identity_marks'])
        add_single_row('Clothing Worn:', report_data['clothing_description'])

    draw_section_header('3. Additional Details')
    add_single_row('Reporter Contact:', reporter_data['email'])
    add_single_row('Provided Phone No:', report_data['contact_no'])
    add_single_row('Other Information:', report_data['other_details'])
    pdf.set_y(260)
    pdf.set_font('Arial', 'I', 9)
    pdf.set_text_color(*COLOR_MEDIUM_GREY)
    pdf.cell(95, 10, "Signature of Complainant/Informer", 'T', 0, 'C')
    pdf.cell(10, 10, "")
    pdf.cell(95, 10, "Signature of Receiving Official", 'T', 0, 'C')
    safe_name = re.sub(r'[^a-zA-Z0-9]', '', report_data['name'] or '')
    filename = f"CHINH_Report_{report_data['id']}_{safe_name}.pdf"
    output_path = os.path.join(app.config['TEMP_FOLDER'], filename)
    pdf.output(output_path)
    return output_path

def extract_face_encoding_deepface(image_path):
    try:
        embedding_objs = DeepFace.represent(img_path=image_path, model_name='SFace', enforce_detection=True)
        embedding = embedding_objs[0]['embedding']
        return json.dumps(embedding)
    except Exception as e:
        print(f"DeepFace encoding error for {image_path}: {e}")
        return None
    
def compare_deepface_encodings(unknown_encoding, known_encoding_str, threshold=0.55):
    try:
        known_encoding = np.array(json.loads(known_encoding_str))
        distance = cosine(unknown_encoding, known_encoding)
        return distance <= threshold
    except Exception as e:
        print(f"Error comparing encodings: {e}")
        return False

def analyze_aadhaar_with_gemini(image_path):
    try:
        img = Image.open(image_path)
        prompt = """
        Your task is to act as a highly precise OCR and JSON data extraction tool.
        Analyze the provided Aadhaar card image meticulously.
        Extract the following information and return it as a single, valid JSON object.

        **CRITICAL INSTRUCTIONS:**
        1. Your entire response must be ONLY the JSON object.
        2. DO NOT include the word "json" or backticks ``` in your response.
        3. ABSOLUTELY NO text, explanations, or summaries before or after the JSON object.

        Use these exact keys: 'name', 'relation', 'dob' (as DD/MM/YYYY), 'address', 'gender', 'contact', and 'aadhaar_no'.
        If a specific field is not visible, use the string "N/A" as its value.

        Example of a perfect response:
        {"name": "Vishma Pasayat", "relation": "S/O Prahlad Chandra Pasayat", "dob": "29/03/2005", "address": "Chhend Colony, Rourkela, Odisha - 769015", "gender": "Male", "contact": "6371545241", "aadhaar_no": "3852 1422 5554"}
        """
        response = model.generate_content([prompt, img])
        text_response = response.text.strip()
        try:
            data = json.loads(text_response)
            return data
        except json.JSONDecodeError:
            json_match = re.search(r'\{.*\}', text_response, re.DOTALL)
            if not json_match:
                print(f"Aadhaar analysis error: No JSON found in response: {text_response}")
                return None
            json_string = json_match.group(0)
            data = json.loads(json_string)
            return data
    except Exception as e:
        print(f"Aadhaar analysis error: {e}")
        return None

def analyze_blood_report_with_gemini(image_path):
    try:
        img = Image.open(image_path)
        prompt = """
        Your task is to act as a highly precise OCR and JSON data extraction tool.
        Analyze the provided blood report and identify the blood group.
        
        **CRITICAL INSTRUCTIONS:**
        1. Your entire response must be ONLY the JSON object.
        2. The JSON object should have a single key: "blood_group".
        3. DO NOT include the word "json" or backticks ``` in your response.
        4. ABSOLUTELY NO text, explanations, or summaries before or after the JSON object.
        
        Example of a perfect response:
        {"blood_group": "O+"}
        """
        response = model.generate_content([prompt, img])
        text_response = response.text.strip()
        try:
            data = json.loads(text_response)
            return data
        except json.JSONDecodeError:
            json_match = re.search(r'\{.*\}', text_response, re.DOTALL)
            if not json_match:
                print(f"Blood report analysis error: No JSON found in response: {text_response}")
                return None
            json_string = json_match.group(0)
            data = json.loads(json_string)
            return data
    except Exception as e:
        print(f"Blood report analysis error: {e}")
        return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            if not user['is_email_verified']:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('verify_otp', email=email))
            session['user_id'] = user['id']
            session['user_type'] = user['user_type']
            session['name'] = user['name']
            if user['user_type'] == 'user':
                return redirect(url_for('user_dashboard'))
            elif user['user_type'] == 'official':
                return redirect(url_for('official_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_type = request.form['user_type']
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email address already exists.', 'danger')
            conn.close()
            return redirect(url_for('signup'))
        
        password_hash = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (name, email, password_hash, user_type, is_email_verified) VALUES (?, ?, ?, ?, ?)',
            (name, email, password_hash, user_type, 1)
        )
        conn.commit()
        conn.close()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
       
    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if request.method == 'POST':
        user_otp = request.form['otp']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and user['otp'] == user_otp:
            otp_expiry_time = datetime.strptime(user['otp_expiry'].split('.')[0], '%Y-%m-%d %H:%M:%S')
            if datetime.now() <= otp_expiry_time:
                conn.execute('UPDATE users SET is_email_verified = 1, otp = NULL WHERE email = ?', (email,))
                conn.commit()
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('OTP has expired.', 'danger')
        else:
            flash('Invalid OTP.', 'danger')
        conn.close()
    return render_template('otp_verify.html', email=email)

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'user':
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    profile_query = 'SELECT p.*, u.name as user_name FROM user_profiles p JOIN users u ON p.user_id = u.id WHERE p.user_id = ?'
    profile = conn.execute(profile_query, (user_id,)).fetchone()
    if not profile:
        conn.execute('INSERT INTO user_profiles (user_id) VALUES (?)', (user_id,))
        conn.commit()
        profile = conn.execute(profile_query, (user_id,)).fetchone()
    conn.close()
    report_success = request.args.get('report_success')
    report_id = request.args.get('report_id')
    return render_template('user_dashboard.html', profile=profile, report_success=report_success, report_id=report_id)

@app.route('/verify_profile', methods=['GET', 'POST'])
def verify_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = session['user_id']
        saved_filenames, full_paths = {}, {}
        doc_keys = ['recent_photo', 'dental_xray', 'aadhaar_card', 'blood_group_report']
        try:
            for key in doc_keys:
                base64_data = request.form.get(key)
                if not base64_data or not base64_data.startswith('data:image'):
                    file_obj = request.files.get(key)
                    if file_obj and file_obj.filename != '':
                        filename = secure_filename(f"{user_id}_{key}_{uuid.uuid4().hex}_{file_obj.filename}")
                        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file_obj.save(path)
                        saved_filenames[key], full_paths[key] = filename, path
                        continue
                    else:
                         return jsonify({'success': False, 'message': f'Missing document: {key.replace("_", " ").title()}'}), 400
                header, encoded = base64_data.split(",", 1)
                file_extension = header.split(';')[0].split('/')[1]
                data = base64.b64decode(encoded)
                filename = secure_filename(f"{user_id}_{key}_{uuid.uuid4().hex}.{file_extension}")
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(path, "wb") as f: f.write(data)
                saved_filenames[key], full_paths[key] = filename, path

            aadhaar_data = analyze_aadhaar_with_gemini(full_paths['aadhaar_card'])
            if not aadhaar_data or not aadhaar_data.get('name'):
                 return jsonify({'success': False, 'message': 'Could not analyze Aadhaar card. Please upload a clear image.'}), 400
            blood_data = analyze_blood_report_with_gemini(full_paths['blood_group_report'])
            if not blood_data: blood_data = {'blood_group': 'N/A'}
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(''' UPDATE user_profiles SET is_verified = 1, recent_photo = ?, dental_xray = ?, aadhaar_card = ?, blood_group_report = ?, aadhaar_name = ?, aadhaar_relation = ?, aadhaar_dob = ?, aadhaar_address = ?, aadhaar_gender = ?, aadhaar_contact = ?, aadhaar_no = ?, blood_group = ? WHERE user_id = ? ''', (saved_filenames['recent_photo'], saved_filenames['dental_xray'], saved_filenames['aadhaar_card'], saved_filenames['blood_group_report'], aadhaar_data.get('name', 'N/A'), aadhaar_data.get('relation', 'N/A'), aadhaar_data.get('dob', 'N/A'), aadhaar_data.get('address', 'N/A'), aadhaar_data.get('gender', 'N/A'), aadhaar_data.get('contact', 'N/A'), aadhaar_data.get('aadhaar_no', 'N/A'), blood_data.get('blood_group', 'N/A'), user_id))
            profile = cursor.execute('SELECT id FROM user_profiles WHERE user_id = ?', (user_id,)).fetchone()
            profile_id = profile['id']
            cursor.execute('DELETE FROM face_encodings WHERE profile_id = ?', (profile_id,))
            face_encoding_1 = extract_face_encoding_deepface(full_paths['recent_photo'])
            if face_encoding_1:
                cursor.execute('INSERT INTO face_encodings (profile_id, encoding) VALUES (?, ?)',(profile_id, face_encoding_1))
            face_encoding_2 = extract_face_encoding_deepface(full_paths['aadhaar_card'])
            if face_encoding_2:
                 cursor.execute('INSERT INTO face_encodings (profile_id, encoding) VALUES (?, ?)',(profile_id, face_encoding_2))
            if not face_encoding_1 and not face_encoding_2:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'message': 'Could not detect a clear face in your photo or Aadhaar. Please use front-facing pictures.'}), 400
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'redirect_url': url_for('user_dashboard')})
        except Exception as e:
            print(f"Error during verification for user {user_id}: {e}")
            return jsonify({'success': False, 'message': 'An unexpected error occurred during analysis. Please try again.'}), 500
    return render_template('verify_profile.html')

@app.route('/report', methods=['POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    photo_filename = None
    uploaded_photo = request.files.get('photo')
    captured_photo_data = request.form.get('captured_photo')
    if uploaded_photo and uploaded_photo.filename != '':
        photo_filename = secure_filename(f"report_{uuid.uuid4().hex}_{uploaded_photo.filename}")
        uploaded_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
    elif captured_photo_data:
        try:
            header, encoded = captured_photo_data.split(",", 1)
            photo_data = base64.b64decode(encoded)
            photo_filename = f"report_capture_{uuid.uuid4().hex}.jpg"
            with open(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename), "wb") as f:
                f.write(photo_data)
        except Exception as e:
            flash(f"Error processing captured photo: {e}", "danger")
            return redirect(url_for('user_dashboard'))
    report_data = {
        'reporter_id': session['user_id'], 'status': request.form.get('status'), 'photo_path': photo_filename,
        'name': request.form.get('name'), 'age': request.form.get('age'), 'hair_color': request.form.get('hair_color'),
        'eye_color': request.form.get('eye_color'), 'skin_color': request.form.get('skin_color'), 'identity_marks': request.form.get('identity_marks'),
        'height': request.form.get('height'), 'weight': request.form.get('weight'), 'aadhaar': request.form.get('aadhaar'),
        'contact_no': request.form.get('contact_no'), 'clothing_description': request.form.get('clothing_description'),
        'other_details': request.form.get('other_details'), 'last_seen_date': request.form.get('last_seen_date'),
        'last_seen_time': request.form.get('last_seen_time'), 'last_seen_location': request.form.get('last_seen_location')
    }
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(''' INSERT INTO reports (reporter_id, status, photo_path, name, age, hair_color, eye_color, skin_color, identity_marks, height, weight, aadhaar, contact_no, clothing_description, other_details, last_seen_date, last_seen_time, last_seen_location) VALUES (:reporter_id, :status, :photo_path, :name, :age, :hair_color, :eye_color, :skin_color, :identity_marks, :height, :weight, :aadhaar, :contact_no, :clothing_description, :other_details, :last_seen_date, :last_seen_time, :last_seen_location) ''', report_data)
    new_report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return redirect(url_for('user_dashboard', report_success='true', report_id=new_report_id))

@app.route('/download_report/<int:report_id>')
def download_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    report_data = conn.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
    if not report_data:
        flash("Report not found.", "danger")
        return redirect(url_for('list_page'))
    reporter_data = conn.execute('SELECT * FROM users WHERE id = ?', (report_data['reporter_id'],)).fetchone()
    conn.close()
    if not (reporter_data and session['user_id'] == reporter_data['id'] or session.get('user_type') == 'official'):
        flash("You are not authorized to download this report.", "warning")
        return redirect(url_for('list_page'))
    try:
        pdf_path = create_fir_report(dict(report_data), dict(reporter_data))
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        print(f"Error creating or sending PDF for report {report_id}: {e}")
        flash("An error occurred while generating your report PDF. Please try again.", "danger")
        return redirect(url_for('list_page'))

@app.route('/official_dashboard', methods=['GET', 'POST'])
def official_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'official':
        return redirect(url_for('login'))
    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if request.method == 'GET':
        return render_template('official_dashboard.html', current_user=current_user)
    if request.method == 'POST':
        aadhaar_image = request.files.get('aadhaar_image')
        person_image = request.files.get('person_image')
        xray_image = request.files.get('xray_image')
        name_input = request.form.get('name', '').strip()
        aadhaar_no_input = request.form.get('aadhaar_no', '').strip()

        if not any([aadhaar_image, person_image, xray_image, name_input, aadhaar_no_input]):
            flash('Please provide at least one piece of information to analyze.', 'warning')
            return redirect(url_for('official_dashboard'))

        temp_files_to_clean = []
        uploaded_xray_filename = None
        try:
            input_face_encoding_str = None
            search_aadhaar_numbers = set()
            if aadhaar_no_input: search_aadhaar_numbers.add(clean_aadhaar_number(aadhaar_no_input))

            if person_image and person_image.filename != '':
                p_filename = secure_filename(f"temp_person_{uuid.uuid4().hex}.jpg")
                p_path = os.path.join(app.config['TEMP_FOLDER'], p_filename)
                person_image.save(p_path)
                temp_files_to_clean.append(p_path)
                input_face_encoding_str = extract_face_encoding_deepface(p_path)
                if not input_face_encoding_str: flash('Could not detect a face in the provided Person/Dead Body image.', 'warning')
            
            a_path = None
            if aadhaar_image and aadhaar_image.filename != '':
                a_filename = secure_filename(f"temp_aadhaar_{uuid.uuid4().hex}.jpg")
                a_path = os.path.join(app.config['TEMP_FOLDER'], a_filename)
                aadhaar_image.save(a_path)
                temp_files_to_clean.append(a_path)
                if not input_face_encoding_str:
                    input_face_encoding_str = extract_face_encoding_deepface(a_path)
                    if not input_face_encoding_str: flash('Could not detect a face in the provided Aadhaar image.', 'warning')
            if a_path and os.path.exists(a_path):
                aadhaar_data = analyze_aadhaar_with_gemini(a_path)
                if aadhaar_data and aadhaar_data.get('aadhaar_no') not in [None, "N/A", ""]:
                    cleaned_num = clean_aadhaar_number(aadhaar_data['aadhaar_no'])
                    if cleaned_num:
                        search_aadhaar_numbers.add(cleaned_num)
                        flash(f"Extracted Aadhaar number '{cleaned_num}' for matching.", 'info')
            
            if xray_image and xray_image.filename != '':
                x_filename = secure_filename(f"display_xray_{uuid.uuid4().hex}.jpg")
                x_path = os.path.join(app.config['TEMP_FOLDER'], x_filename)
                xray_image.save(x_path)
                uploaded_xray_filename = x_filename

            match_result, match_type = None, None
            conn = get_db_connection()
            all_profiles = conn.execute("SELECT u.name, u.email, up.* FROM user_profiles up JOIN users u ON up.user_id = u.id WHERE up.is_verified = 1").fetchall()
            flash(f"Searching {len(all_profiles)} verified profiles...", "info")
            if input_face_encoding_str:
                unknown_encoding = np.array(json.loads(input_face_encoding_str))

            for profile in all_profiles:
                is_match = False
                if name_input and profile['aadhaar_name'] and name_input.lower() in profile['aadhaar_name'].lower(): is_match = True
                if not is_match and search_aadhaar_numbers and profile['aadhaar_no']:
                    if clean_aadhaar_number(profile['aadhaar_no']) in search_aadhaar_numbers: is_match = True
                if not is_match and input_face_encoding_str:
                    profile_encodings_rows = conn.execute("SELECT encoding FROM face_encodings WHERE profile_id = ?", (profile['id'],)).fetchall()
                    for row in profile_encodings_rows:
                        if compare_deepface_encodings(unknown_encoding, row['encoding']):
                            is_match = True
                            break
                if is_match:
                    match_result, match_type = dict(profile), 'profile'
                    break
            
            if not match_result:
                all_reports = conn.execute("SELECT * FROM reports").fetchall()
                flash(f"No profile match. Searching {len(all_reports)} reports...", "info")
                for report in all_reports:
                    is_match = False
                    if name_input and report['name'] and name_input.lower() in report['name'].lower(): is_match = True
                    if not is_match and search_aadhaar_numbers and report['aadhaar']:
                        if clean_aadhaar_number(report['aadhaar']) in search_aadhaar_numbers: is_match = True
                    if not is_match and input_face_encoding_str and report['photo_path']:
                        report_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], report['photo_path'])
                        if os.path.exists(report_photo_path):
                            report_encoding_str = extract_face_encoding_deepface(report_photo_path)
                            if report_encoding_str:
                                if compare_deepface_encodings(unknown_encoding, report_encoding_str): is_match = True
                    if is_match:
                        match_result, match_type = dict(report), 'report'
                        break

            conn.close()
            return render_template('official_dashboard.html', match_result=match_result, match_type=match_type, no_match_found=not match_result, uploaded_xray_filename=uploaded_xray_filename, current_user=current_user)
        finally:
            for f_path in temp_files_to_clean:
                if os.path.exists(f_path):
                    try: os.remove(f_path)
                    except Exception as e: print(f"Error removing temp file {f_path}: {e}")

@app.route('/list')
def list_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    conn = get_db_connection()
    reports = conn.execute('SELECT * FROM reports ORDER BY report_timestamp DESC').fetchall()
    profile = conn.execute('SELECT * FROM user_profiles WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    dashboard_url = url_for('user_dashboard') if session.get('user_type') == 'user' else url_for('official_dashboard')
    return render_template('list.html', reports=reports, profile=profile, dashboard_url=dashboard_url)

@app.route('/list_official')
def list_official():
    if 'user_id' not in session or session.get('user_type') != 'official':
        return redirect(url_for('login'))
    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    reports = conn.execute('SELECT * FROM reports ORDER BY report_timestamp DESC').fetchall()
    conn.close()
    return render_template('list_official.html', reports=reports, current_user=current_user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists(app.config['TEMP_FOLDER']):
        os.makedirs(app.config['TEMP_FOLDER'])
    app.run(debug=True)
