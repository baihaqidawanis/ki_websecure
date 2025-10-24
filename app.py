import os
import time
import uuid
import io
import bcrypt
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from Crypto.Random import get_random_bytes
import crypto_utils
from collections import OrderedDict

# Memuat variabel dari file .env
load_dotenv()

# --- Konfigurasi Aplikasi ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{db_user}:{db_password}@localhost/{db_name}'

db = SQLAlchemy(app)

# --- Model Database (Struktur DINAMIS) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_timestamp = db.Column(db.DateTime, server_default=db.func.now())
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_key_hex = db.Column(db.Text, nullable=False)

# TABEL BARU: Menggantikan FinancialReport yang statis
class ReportData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    row_index = db.Column(db.Integer, nullable=False)
    column_name_encrypted = db.Column(db.Text, nullable=False)
    cell_value_encrypted = db.Column(db.Text, nullable=False)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PerformanceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    algorithm = db.Column(db.String(10), nullable=False)
    key_hex = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    encryption_time_ms = db.Column(db.Float, nullable=False)
    decryption_time_ms = db.Column(db.Float, nullable=True)
    ciphertext_size_bytes = db.Column(db.Integer, nullable=False)

# --- Routes ---
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
    if 'user_id' not in session: return redirect(url_for('login'))
    user_files = File.query.filter_by(owner_id=session['user_id']).order_by(File.upload_timestamp.desc()).all()
    shared_files_query = db.session.query(File).join(Share, File.id == Share.file_id).filter(Share.shared_to_user_id == session['user_id']).all()
    return render_template('dashboard.html', files=user_files, shared_files=shared_files_query)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect(url_for('login'))
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('File tidak ditemukan.', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if not file.filename.endswith(('.xlsx', '.xls')):
        flash('Hanya file Excel (.xlsx, .xls) yang diizinkan.', 'error')
        return redirect(url_for('dashboard'))

    try:
        data_key = get_random_bytes(32)
        new_file = File(original_filename=file.filename, owner_id=session['user_id'], data_key_hex=data_key.hex())
        db.session.add(new_file)
        db.session.commit()
        
        df = pd.read_excel(file, engine='openpyxl')
        for index, row in df.iterrows():
            for column_name in df.columns:
                cell_value = str(row[column_name])
                col_name_enc = crypto_utils.encrypt_aes(column_name.encode('utf-8'), data_key)
                cell_val_enc = crypto_utils.encrypt_aes(cell_value.encode('utf-8'), data_key)
                report_entry = ReportData(
                    file_id=new_file.id,
                    row_index=index,
                    column_name_encrypted=col_name_enc.hex(),
                    cell_value_encrypted=cell_val_enc.hex()
                )
                db.session.add(report_entry)
    except Exception as e:
        flash(f'Gagal memproses file Excel. Pastikan format file valid. Error: {e}', 'error')
        db.session.rollback()
        return redirect(url_for('dashboard'))

    file.seek(0)
    file_bytes = file.read()
    algorithms = {'AES': (crypto_utils.encrypt_aes, 32), 'DES': (crypto_utils.encrypt_des, 8), 'RC4': (crypto_utils.encrypt_rc4, 16)}
    for algo_name, (encrypt_func, key_size) in algorithms.items():
        key = get_random_bytes(key_size)
        start_time = time.time()
        encrypted_data = encrypt_func(file_bytes, key)
        end_time = time.time()
        encryption_time = (end_time - start_time) * 1000
        unique_filename = f"{uuid.uuid4()}.enc"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(file_path, 'wb') as f: f.write(encrypted_data)
        log = PerformanceLog(file_id=new_file.id, algorithm=algo_name, key_hex=key.hex(), file_path=file_path, encryption_time_ms=encryption_time, ciphertext_size_bytes=len(encrypted_data))
        db.session.add(log)
    
    db.session.commit()
    flash(f'File "{file.filename}" berhasil diproses dan dienkripsi!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/share/<int:file_id>', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    file = File.query.filter_by(id=file_id, owner_id=session['user_id']).first_or_404()
    recipient_username = request.form.get('username')
    if not recipient_username:
        flash('Username penerima harus diisi.', 'error')
        return redirect(url_for('report', file_id=file_id))
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        flash(f'User dengan username "{recipient_username}" tidak ditemukan.', 'error')
        return redirect(url_for('report', file_id=file_id))
    if recipient.id == session['user_id']:
        flash('Anda tidak bisa berbagi file dengan diri sendiri.', 'error')
        return redirect(url_for('report', file_id=file_id))
    existing_share = Share.query.filter_by(file_id=file_id, shared_to_user_id=recipient.id).first()
    if existing_share:
        flash(f'File ini sudah dibagikan kepada {recipient_username}.', 'error')
        return redirect(url_for('report', file_id=file_id))
    new_share = Share(file_id=file.id, owner_id=session['user_id'], shared_to_user_id=recipient.id)
    db.session.add(new_share)
    db.session.commit()
    flash(f'File berhasil dibagikan kepada {recipient_username}.', 'success')
    return redirect(url_for('report', file_id=file_id))

@app.route('/report/<int:file_id>')
def report(file_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    file = File.query.get_or_404(file_id)
    share_access = Share.query.filter_by(file_id=file_id, shared_to_user_id=session['user_id']).first()
    if file.owner_id != session['user_id'] and not share_access: return "Akses Ditolak", 403
    
    data_key = bytes.fromhex(file.data_key_hex)
    encrypted_rows = ReportData.query.filter_by(file_id=file_id).all()
    
    # Rekonstruksi tabel dinamis
    headers = OrderedDict()
    reconstructed_table = {}
    for row_data in encrypted_rows:
        row_idx = row_data.row_index
        col_name = crypto_utils.decrypt_aes(bytes.fromhex(row_data.column_name_encrypted), data_key).decode('utf-8')
        cell_val = crypto_utils.decrypt_aes(bytes.fromhex(row_data.cell_value_encrypted), data_key).decode('utf-8')
        
        headers[col_name] = None # Gunakan dict untuk mendapatkan header unik secara berurutan
        if row_idx not in reconstructed_table:
            reconstructed_table[row_idx] = {}
        reconstructed_table[row_idx][col_name] = cell_val

    # Ubah data ke format yang mudah di-render di template
    final_headers = list(headers.keys())
    final_rows = []
    for i in sorted(reconstructed_table.keys()):
        row = reconstructed_table[i]
        final_rows.append([row.get(h, '') for h in final_headers])

    performance_logs = PerformanceLog.query.filter_by(file_id=file.id).all()
    return render_template('report.html', file=file, logs=performance_logs, headers=final_headers, rows=final_rows)

@app.route('/download/<int:log_id>')
def download(log_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    log = PerformanceLog.query.get_or_404(log_id)
    file_owner = File.query.get_or_404(log.file_id)
    share_access = Share.query.filter_by(file_id=log.file_id, shared_to_user_id=session['user_id']).first()
    if file_owner.owner_id != session['user_id'] and not share_access: return "Akses ditolak", 403
    
    with open(log.file_path, 'rb') as f: encrypted_data = f.read()
    key = bytes.fromhex(log.key_hex)
    decrypt_func = getattr(crypto_utils, f'decrypt_{log.algorithm.lower()}')
    
    start_time = time.time()
    decrypted_data = decrypt_func(encrypted_data, key)
    end_time = time.time()
    decryption_time = (end_time - start_time) * 1000
    
    log.decryption_time_ms = decryption_time
    db.session.commit()
    
    return send_file(io.BytesIO(decrypted_data), mimetype='application/octet-stream', as_attachment=True, download_name=file_owner.original_filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    app.run(debug=True)