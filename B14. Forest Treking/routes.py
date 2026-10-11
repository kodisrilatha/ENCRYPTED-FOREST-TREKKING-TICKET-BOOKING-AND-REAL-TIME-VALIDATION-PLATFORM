import os
from flask import render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime

from app import app
from database import (
    create_user, get_user_by_username, get_user_by_email, get_all_users,
    get_users_by_role, update_user, delete_user,
    create_route, get_all_routes, get_active_routes, get_route_by_id,
    update_route, delete_route,
    create_booking, get_all_bookings, get_bookings_by_user, get_booking_by_id,
    update_booking, cancel_booking,
    create_file_record, get_files_by_uploader, get_file_by_id, get_all_files,
    share_file_with_role, get_files_shared_with_role,
    create_shared_secret, get_secrets_for_role, get_secrets_sent_by_user,
    get_secret_by_id, mark_secret_read,
    create_schedule, get_all_schedules, get_schedules_by_route, get_schedule_by_id,
    update_schedule, book_schedule_slots, get_active_schedules, get_stats,
    get_user_by_id
)
from crypto_utils import (
    encrypt_file, decrypt_file, encrypt_text, decrypt_text,
    get_ripemd_hash, verify_file_integrity
)

class User:
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        self.full_name = user_data.get('full_name')
        self.phone = user_data.get('phone')
        self.is_active = True
        self.is_authenticated = True
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_anonymous(self):
        return False

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'encrypted')
DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'decrypted')

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        address = request.form.get('address', '')
        
        if not all([username, email, password, confirm_password, role, full_name, phone]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if get_user_by_username(username):
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if get_user_by_email(email):
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        create_user(username, email, password_hash, role, full_name, phone, address)
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = get_user_by_username(username)
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data)
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'trekking_management':
        return redirect(url_for('trekking_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    stats = get_stats()
    recent_bookings = get_all_bookings()[-5:]
    recent_users = get_all_users()[-5:]
    return render_template('admin/dashboard.html', stats=stats, 
                         recent_bookings=recent_bookings, recent_users=recent_users)

@app.route('/admin/routes', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_routes():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty')
        duration = request.form.get('duration')
        max_capacity = int(request.form.get('max_capacity', 20))
        price = float(request.form.get('price', 0))
        
        create_route(name, description, difficulty, duration, max_capacity, price)
        flash('Trekking route created successfully!', 'success')
        return redirect(url_for('admin_routes'))
    
    routes = get_all_routes()
    return render_template('admin/routes.html', routes=routes)

@app.route('/admin/routes/edit/<int:route_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_edit_route(route_id):
    data = {
        'name': request.form.get('name'),
        'description': request.form.get('description'),
        'difficulty': request.form.get('difficulty'),
        'duration': request.form.get('duration'),
        'max_capacity': int(request.form.get('max_capacity', 20)),
        'price': float(request.form.get('price', 0)),
        'is_active': request.form.get('is_active') == 'on'
    }
    update_route(route_id, data)
    flash('Route updated successfully!', 'success')
    return redirect(url_for('admin_routes'))

@app.route('/admin/routes/delete/<int:route_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_route(route_id):
    delete_route(route_id)
    flash('Route deleted successfully!', 'success')
    return redirect(url_for('admin_routes'))

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = get_all_users()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_edit_user(user_id):
    data = {
        'full_name': request.form.get('full_name'),
        'email': request.form.get('email'),
        'phone': request.form.get('phone'),
        'role': request.form.get('role')
    }
    update_user(user_id, data)
    flash('User updated successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))
    delete_user(user_id)
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/bookings')
@login_required
@role_required('admin')
def admin_bookings():
    bookings = get_all_bookings()
    enriched_bookings = []
    for booking in bookings:
        user = get_user_by_id(booking['user_id'])
        route = get_route_by_id(booking['route_id'])
        enriched_bookings.append({
            **booking,
            'user': user,
            'route': route
        })
    return render_template('admin/bookings.html', bookings=enriched_bookings)

@app.route('/admin/bookings/update/<int:booking_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_update_booking(booking_id):
    status = request.form.get('status')
    update_booking(booking_id, {'status': status})
    flash('Booking status updated!', 'success')
    return redirect(url_for('admin_bookings'))

@app.route('/admin/reports')
@login_required
@role_required('admin')
def admin_reports():
    stats = get_stats()
    bookings = get_all_bookings()
    
    total_revenue = sum(b.get('total_price', 0) for b in bookings if b.get('status') == 'confirmed')
    
    confirmed = len([b for b in bookings if b.get('status') == 'confirmed'])
    cancelled = len([b for b in bookings if b.get('status') == 'cancelled'])
    pending = len([b for b in bookings if b.get('status') == 'pending'])
    
    routes = get_all_routes()
    route_stats = []
    for route in routes:
        route_bookings = [b for b in bookings if b.get('route_id') == route['id']]
        route_stats.append({
            'name': route['name'],
            'total_bookings': len(route_bookings),
            'revenue': sum(b.get('total_price', 0) for b in route_bookings if b.get('status') == 'confirmed')
        })
    
    return render_template('admin/reports.html', stats=stats, total_revenue=total_revenue,
                         confirmed=confirmed, cancelled=cancelled, pending=pending,
                         route_stats=route_stats)

@app.route('/trekking/dashboard')
@login_required
@role_required('trekking_management')
def trekking_dashboard():
    schedules = get_all_schedules()
    bookings = get_all_bookings()
    files = get_files_shared_with_role('trekking_management')
    secrets = get_secrets_for_role('trekking_management')
    unread_secrets = len([s for s in secrets if not s.get('is_read')])
    
    return render_template('trekking/dashboard.html', 
                         schedules=schedules, bookings=bookings,
                         files=files, unread_secrets=unread_secrets)

@app.route('/trekking/schedules', methods=['GET', 'POST'])
@login_required
@role_required('trekking_management')
def trekking_schedules():
    if request.method == 'POST':
        route_id = int(request.form.get('route_id'))
        date = request.form.get('date')
        time = request.form.get('time')
        available_slots = int(request.form.get('available_slots', 20))
        
        create_schedule(route_id, date, time, available_slots, current_user.id)
        flash('Schedule created successfully!', 'success')
        return redirect(url_for('trekking_schedules'))
    
    schedules = get_all_schedules()
    enriched_schedules = []
    for schedule in schedules:
        route = get_route_by_id(schedule['route_id'])
        enriched_schedules.append({
            **schedule,
            'route': route
        })
    
    routes = get_active_routes()
    return render_template('trekking/schedules.html', schedules=enriched_schedules, routes=routes)

@app.route('/trekking/schedules/edit/<int:schedule_id>', methods=['POST'])
@login_required
@role_required('trekking_management')
def trekking_edit_schedule(schedule_id):
    data = {
        'date': request.form.get('date'),
        'time': request.form.get('time'),
        'available_slots': int(request.form.get('available_slots', 20)),
        'is_active': request.form.get('is_active') == 'on'
    }
    update_schedule(schedule_id, data)
    flash('Schedule updated successfully!', 'success')
    return redirect(url_for('trekking_schedules'))

@app.route('/trekking/bookings')
@login_required
@role_required('trekking_management')
def trekking_bookings():
    bookings = get_all_bookings()
    enriched_bookings = []
    for booking in bookings:
        user = get_user_by_id(booking['user_id'])
        route = get_route_by_id(booking['route_id'])
        schedule = get_schedule_by_id(booking.get('schedule_id'))
        enriched_bookings.append({
            **booking,
            'user': user,
            'route': route,
            'schedule': schedule
        })
    return render_template('trekking/bookings.html', bookings=enriched_bookings)

@app.route('/trekking/files', methods=['GET', 'POST'])
@login_required
@role_required('trekking_management')
def trekking_files():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('trekking_files'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('trekking_files'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            
            temp_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            file.save(temp_path)
            
            encrypted_filename = f"encrypted_{unique_filename}"
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
            encryption_hash = encrypt_file(temp_path, encrypted_path)
            
            create_file_record(
                filename=unique_filename,
                original_filename=filename,
                uploader_id=current_user.id,
                uploader_role='trekking_management',
                encrypted_path=encrypted_path,
                decrypted_path=temp_path,
                encryption_hash=encryption_hash
            )
            
            share_with = request.form.getlist('share_with')
            file_record = get_files_by_uploader(current_user.id)[-1]
            for role in share_with:
                share_file_with_role(file_record['id'], role)
            
            flash('File uploaded and encrypted successfully!', 'success')
            return redirect(url_for('trekking_files'))
    
    my_files = get_files_by_uploader(current_user.id)
    shared_files = get_files_shared_with_role('trekking_management')
    shared_files = [f for f in shared_files if f['uploader_id'] != current_user.id]
    
    return render_template('trekking/files.html', my_files=my_files, shared_files=shared_files)

@app.route('/trekking/share', methods=['GET', 'POST'])
@login_required
@role_required('trekking_management')
def trekking_share():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        recipient_role = request.form.get('recipient_role')
        
        encrypted_content, encryption_hash = encrypt_text(content)
        
        create_shared_secret(
            sender_id=current_user.id,
            sender_role='trekking_management',
            recipient_role=recipient_role,
            title=title,
            encrypted_content=encrypted_content,
            encryption_hash=encryption_hash
        )
        
        flash('Secret data shared successfully!', 'success')
        return redirect(url_for('trekking_share'))
    
    sent_secrets = get_secrets_sent_by_user(current_user.id)
    received_secrets = get_secrets_for_role('trekking_management')
    
    for secret in received_secrets:
        sender = get_user_by_id(secret['sender_id'])
        secret['sender_name'] = sender['full_name'] if sender else 'Unknown'
    
    return render_template('trekking/share.html', sent_secrets=sent_secrets, 
                         received_secrets=received_secrets)

@app.route('/user/dashboard')
@login_required
@role_required('user')
def user_dashboard():
    my_bookings = get_bookings_by_user(current_user.id)
    my_files = get_files_by_uploader(current_user.id)
    shared_files = get_files_shared_with_role('user')
    secrets = get_secrets_for_role('user')
    unread_secrets = len([s for s in secrets if not s.get('is_read')])
    
    enriched_bookings = []
    for booking in my_bookings:
        route = get_route_by_id(booking['route_id'])
        enriched_bookings.append({**booking, 'route': route})
    
    return render_template('user/dashboard.html', 
                         bookings=enriched_bookings, my_files=my_files,
                         shared_files=shared_files, unread_secrets=unread_secrets)

@app.route('/user/browse')
@login_required
@role_required('user')
def user_browse():
    routes = get_active_routes()
    enriched_routes = []
    for route in routes:
        schedules = get_schedules_by_route(route['id'])
        active_schedules = [s for s in schedules if s.get('is_active')]
        enriched_routes.append({
            **route,
            'schedules': active_schedules
        })
    return render_template('user/browse.html', routes=enriched_routes)

@app.route('/user/book/<int:route_id>', methods=['GET', 'POST'])
@login_required
@role_required('user')
def user_book(route_id):
    route = get_route_by_id(route_id)
    if not route:
        flash('Route not found.', 'error')
        return redirect(url_for('user_browse'))
    
    schedules = get_schedules_by_route(route_id)
    active_schedules = [s for s in schedules if s.get('is_active') and 
                       s.get('available_slots', 0) > s.get('booked_slots', 0)]
    
    if request.method == 'POST':
        schedule_id = int(request.form.get('schedule_id'))
        num_participants = int(request.form.get('num_participants', 1))
        
        schedule = get_schedule_by_id(schedule_id)
        if not schedule:
            flash('Schedule not found.', 'error')
            return redirect(url_for('user_book', route_id=route_id))
        
        available = schedule.get('available_slots', 0) - schedule.get('booked_slots', 0)
        if num_participants > available:
            flash(f'Only {available} slots available.', 'error')
            return redirect(url_for('user_book', route_id=route_id))
        
        total_price = route['price'] * num_participants
        booking_date = schedule['date']
        
        create_booking(current_user.id, route_id, schedule_id, num_participants, 
                      total_price, booking_date)
        book_schedule_slots(schedule_id, num_participants)
        
        flash('Booking confirmed successfully!', 'success')
        return redirect(url_for('user_bookings'))
    
    return render_template('user/book.html', route=route, schedules=active_schedules)

@app.route('/user/bookings')
@login_required
@role_required('user')
def user_bookings():
    bookings = get_bookings_by_user(current_user.id)
    enriched_bookings = []
    for booking in bookings:
        route = get_route_by_id(booking['route_id'])
        schedule = get_schedule_by_id(booking.get('schedule_id'))
        enriched_bookings.append({
            **booking,
            'route': route,
            'schedule': schedule
        })
    return render_template('user/bookings.html', bookings=enriched_bookings)

@app.route('/user/bookings/cancel/<int:booking_id>', methods=['POST'])
@login_required
@role_required('user')
def user_cancel_booking(booking_id):
    booking = get_booking_by_id(booking_id)
    if booking and booking['user_id'] == current_user.id:
        cancel_booking(booking_id)
        flash('Booking cancelled successfully.', 'success')
    else:
        flash('Booking not found or unauthorized.', 'error')
    return redirect(url_for('user_bookings'))

@app.route('/user/files', methods=['GET', 'POST'])
@login_required
@role_required('user')
def user_files():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('user_files'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('user_files'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            
            temp_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            file.save(temp_path)
            
            encrypted_filename = f"encrypted_{unique_filename}"
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
            encryption_hash = encrypt_file(temp_path, encrypted_path)
            
            create_file_record(
                filename=unique_filename,
                original_filename=filename,
                uploader_id=current_user.id,
                uploader_role='user',
                encrypted_path=encrypted_path,
                decrypted_path=temp_path,
                encryption_hash=encryption_hash
            )
            
            share_with = request.form.getlist('share_with')
            file_record = get_files_by_uploader(current_user.id)[-1]
            for role in share_with:
                share_file_with_role(file_record['id'], role)
            
            flash('File uploaded and encrypted successfully!', 'success')
            return redirect(url_for('user_files'))
    
    my_files = get_files_by_uploader(current_user.id)
    shared_files = get_files_shared_with_role('user')
    shared_files = [f for f in shared_files if f['uploader_id'] != current_user.id]
    
    return render_template('user/files.html', my_files=my_files, shared_files=shared_files)

@app.route('/user/shared')
@login_required
@role_required('user')
def user_shared():
    received_secrets = get_secrets_for_role('user')
    sent_secrets = get_secrets_sent_by_user(current_user.id)
    
    for secret in received_secrets:
        sender = get_user_by_id(secret['sender_id'])
        secret['sender_name'] = sender['full_name'] if sender else 'Unknown'
    
    return render_template('user/shared.html', received_secrets=received_secrets,
                         sent_secrets=sent_secrets)

@app.route('/user/share', methods=['POST'])
@login_required
@role_required('user')
def user_share_secret():
    title = request.form.get('title')
    content = request.form.get('content')
    recipient_role = request.form.get('recipient_role')
    
    encrypted_content, encryption_hash = encrypt_text(content)
    
    create_shared_secret(
        sender_id=current_user.id,
        sender_role='user',
        recipient_role=recipient_role,
        title=title,
        encrypted_content=encrypted_content,
        encryption_hash=encryption_hash
    )
    
    flash('Secret data shared successfully!', 'success')
    return redirect(url_for('user_shared'))

@app.route('/download/encrypted/<int:file_id>')
@login_required
def download_encrypted(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    can_access = (
        file_record['uploader_id'] == current_user.id or
        current_user.role in file_record.get('shared_with', []) or
        current_user.role == 'admin'
    )
    
    if not can_access:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    encrypted_path = file_record['encrypted_path']
    if os.path.exists(encrypted_path):
        return send_file(
            encrypted_path,
            as_attachment=True,
            download_name=f"encrypted_{file_record['original_filename']}"
        )
    
    flash('Encrypted file not found.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/download/decrypted/<int:file_id>')
@login_required
def download_decrypted(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    can_access = (
        file_record['uploader_id'] == current_user.id or
        current_user.role in file_record.get('shared_with', []) or
        current_user.role == 'admin'
    )
    
    if not can_access:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    encrypted_path = file_record['encrypted_path']
    encryption_hash = file_record['encryption_hash']
    
    decrypted_filename = f"decrypted_{file_record['filename']}"
    decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)
    
    try:
        decrypt_file(encrypted_path, decrypted_path, encryption_hash)
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=file_record['original_filename']
        )
    except Exception as e:
        flash(f'Error decrypting file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/secret/view/<int:secret_id>')
@login_required
def view_secret(secret_id):
    secret = get_secret_by_id(secret_id)
    if not secret:
        flash('Secret not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if secret['recipient_role'] != current_user.role and secret['sender_id'] != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        decrypted_content = decrypt_text(secret['encrypted_content'], secret['encryption_hash'])
        mark_secret_read(secret_id)
        
        sender = get_user_by_id(secret['sender_id'])
        
        return render_template('view_secret.html', 
                             secret=secret, 
                             decrypted_content=decrypted_content,
                             sender=sender)
    except Exception as e:
        flash(f'Error decrypting secret: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/file/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record or file_record['uploader_id'] != current_user.id:
        flash('File not found or unauthorized.', 'error')
        return redirect(url_for('dashboard'))
    
    role = request.form.get('role')
    if role in ['admin', 'trekking_management', 'user']:
        share_file_with_role(file_id, role)
        flash(f'File shared with {role}!', 'success')
    
    return redirect(request.referrer or url_for('dashboard'))
