# app.py
from Crypto.Random import get_random_bytes
import os
from dotenv import load_dotenv # 1. IMPORT LIBRARY
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import time
import uuid
# app.py
from flask import send_file # Tambahkan ini
import crypto_utils
import io

load_dotenv() # 2. PERINTAHKAN UNTUK MEMUAT FILE .env

# --- KONFIGURASI APLIKASI ---
app = Flask(__name__)

# 3. AMBIL NILAI DARI ENVIRONMENT VARIABLE, BUKAN DITULIS LANGSUNG
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ambil konfigurasi database dari .env
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{db_user}:{db_password}@localhost/{db_name}'


db = SQLAlchemy(app)



# --- MODEL DATABASE (STRUKTUR TABEL) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_timestamp = db.Column(db.DateTime, server_default=db.func.now())
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PerformanceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    algorithm = db.Column(db.String(10), nullable=False)
    key_hex = db.Column(db.Text, nullable=False) # Kunci disimpan di sini, BUKAN di kode
    file_path = db.Column(db.String(255), nullable=False)
    encryption_time_ms = db.Column(db.Float, nullable=False)
    decryption_time_ms = db.Column(db.Float, nullable=True) # Diisi saat dekripsi
    ciphertext_size_bytes = db.Column(db.Integer, nullable=False)

# --- HALAMAN-HALAMAN WEB (ROUTES) ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username sudah ada, silakan gunakan yang lain.', 'error')
            return redirect(url_for('register'))
            
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        new_user = User(username=username, password_hash=hashed_password.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah.', 'error')
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Ambil semua file yang diupload oleh user yang sedang login
    user_files = File.query.filter_by(owner_id=session['user_id']).order_by(File.upload_timestamp.desc()).all()

    return render_template('dashboard.html', files=user_files)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files or request.files['file'].filename == '':
        flash('File tidak ditemukan.', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    file_bytes = file.read() # Baca file sebagai data biner

    # Simpan record file utama ke database
    new_file = File(original_filename=file.filename, owner_id=session['user_id'])
    db.session.add(new_file)
    db.session.commit()

    # Daftar algoritma, fungsi, dan ukuran kuncinya
    algorithms = {
        'AES': (crypto_utils.encrypt_aes, 32), # AES-256
        'DES': (crypto_utils.encrypt_des, 8),
        'RC4': (crypto_utils.encrypt_rc4, 16)
    }

    # Loop untuk setiap algoritma
    for algo_name, (encrypt_func, key_size) in algorithms.items():
        # 1. Buat kunci baru yang acak (TIDAK HARD-CODED)
        key = get_random_bytes(key_size)
        
        # 2. Ukur waktu enkripsi
        start_time = time.time()
        encrypted_data = encrypt_func(file_bytes, key)
        end_time = time.time()
        encryption_time = (end_time - start_time) * 1000 # dalam milidetik

        # 3. Simpan file terenkripsi ke folder /uploads
        unique_filename = f"{uuid.uuid4()}.enc"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # 4. Simpan log performa ke database
        log = PerformanceLog(
            file_id=new_file.id,
            algorithm=algo_name,
            key_hex=key.hex(),
            file_path=file_path,
            encryption_time_ms=encryption_time,
            ciphertext_size_bytes=len(encrypted_data)
        )
        db.session.add(log)
    
    db.session.commit()
    flash(f'File "{file.filename}" berhasil dienkripsi dengan 3 algoritma!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/report/<int:file_id>')
def report(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Ambil data file dan pastikan itu milik user
    file = File.query.filter_by(id=file_id, owner_id=session['user_id']).first_or_404()
    logs = PerformanceLog.query.filter_by(file_id=file.id).all()

    return render_template('report.html', file=file, logs=logs)

@app.route('/download/<int:log_id>')
def download(log_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Ambil log dan verifikasi kepemilikan melalui file
    log = PerformanceLog.query.get_or_404(log_id)
    file_owner = File.query.get_or_404(log.file_id)
    if file_owner.owner_id != session['user_id']:
        return "Akses ditolak", 403

    # Baca file terenkripsi
    with open(log.file_path, 'rb') as f:
        encrypted_data = f.read()

    # Ambil kunci dari database dan konversi dari hex ke bytes
    key = bytes.fromhex(log.key_hex)

    # Pilih fungsi dekripsi yang tepat
    decrypt_func = getattr(crypto_utils, f'decrypt_{log.algorithm.lower()}')

    # Ukur waktu dekripsi
    start_time = time.time()
    decrypted_data = decrypt_func(encrypted_data, key)
    end_time = time.time()
    decryption_time = (end_time - start_time) * 1000

    # Update log di database dengan waktu dekripsi
    log.decryption_time_ms = decryption_time
    db.session.commit()

    # Kirim file yang sudah didekripsi sebagai download
    return send_file(
        io.BytesIO(decrypted_data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=file_owner.original_filename
    )

# --- Perintah untuk menjalankan aplikasi ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)