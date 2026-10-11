from tinydb import TinyDB, Query
from datetime import datetime
import os

db_folder = 'data'
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

db = TinyDB(os.path.join(db_folder, 'forest_trekking.json'))

users_table = db.table('users')
routes_table = db.table('trekking_routes')
bookings_table = db.table('bookings')
files_table = db.table('files')
shared_secrets_table = db.table('shared_secrets')
schedules_table = db.table('schedules')

User = Query()
Route = Query()
Booking = Query()
File = Query()
Secret = Query()
Schedule = Query()

def get_next_id(table):
    all_records = table.all()
    if not all_records:
        return 1
    return max(record.get('id', 0) for record in all_records) + 1

def create_user(username, email, password_hash, role, full_name, phone, address=''):
    user_id = get_next_id(users_table)
    user_data = {
        'id': user_id,
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'role': role,
        'full_name': full_name,
        'phone': phone,
        'address': address,
        'created_at': datetime.now().isoformat()
    }
    users_table.insert(user_data)
    return user_data

def get_user_by_username(username):
    result = users_table.search(User.username == username)
    return result[0] if result else None

def get_user_by_email(email):
    result = users_table.search(User.email == email)
    return result[0] if result else None

def get_user_by_id(user_id):
    result = users_table.search(User.id == user_id)
    return result[0] if result else None

def get_all_users():
    return users_table.all()

def get_users_by_role(role):
    return users_table.search(User.role == role)

def update_user(user_id, data):
    users_table.update(data, User.id == user_id)

def delete_user(user_id):
    users_table.remove(User.id == user_id)

def create_route(name, description, difficulty, duration, max_capacity, price, image_url=''):
    route_id = get_next_id(routes_table)
    route_data = {
        'id': route_id,
        'name': name,
        'description': description,
        'difficulty': difficulty,
        'duration': duration,
        'max_capacity': max_capacity,
        'price': price,
        'image_url': image_url,
        'is_active': True,
        'created_at': datetime.now().isoformat()
    }
    routes_table.insert(route_data)
    return route_data

def get_all_routes():
    return routes_table.all()

def get_active_routes():
    return routes_table.search(Route.is_active == True)

def get_route_by_id(route_id):
    result = routes_table.search(Route.id == route_id)
    return result[0] if result else None

def update_route(route_id, data):
    routes_table.update(data, Route.id == route_id)

def delete_route(route_id):
    routes_table.remove(Route.id == route_id)

def create_booking(user_id, route_id, schedule_id, num_participants, total_price, booking_date):
    booking_id = get_next_id(bookings_table)
    booking_data = {
        'id': booking_id,
        'user_id': user_id,
        'route_id': route_id,
        'schedule_id': schedule_id,
        'num_participants': num_participants,
        'total_price': total_price,
        'booking_date': booking_date,
        'status': 'confirmed',
        'created_at': datetime.now().isoformat()
    }
    bookings_table.insert(booking_data)
    return booking_data

def get_all_bookings():
    return bookings_table.all()

def get_bookings_by_user(user_id):
    return bookings_table.search(Booking.user_id == user_id)

def get_booking_by_id(booking_id):
    result = bookings_table.search(Booking.id == booking_id)
    return result[0] if result else None

def update_booking(booking_id, data):
    bookings_table.update(data, Booking.id == booking_id)

def cancel_booking(booking_id):
    bookings_table.update({'status': 'cancelled'}, Booking.id == booking_id)

def create_file_record(filename, original_filename, uploader_id, uploader_role, encrypted_path, decrypted_path, encryption_hash):
    file_id = get_next_id(files_table)
    file_data = {
        'id': file_id,
        'filename': filename,
        'original_filename': original_filename,
        'uploader_id': uploader_id,
        'uploader_role': uploader_role,
        'encrypted_path': encrypted_path,
        'decrypted_path': decrypted_path,
        'encryption_hash': encryption_hash,
        'shared_with': [],
        'created_at': datetime.now().isoformat()
    }
    files_table.insert(file_data)
    return file_data

def get_files_by_uploader(uploader_id):
    return files_table.search(File.uploader_id == uploader_id)

def get_file_by_id(file_id):
    result = files_table.search(File.id == file_id)
    return result[0] if result else None

def get_all_files():
    return files_table.all()

def share_file_with_role(file_id, role):
    file_record = get_file_by_id(file_id)
    if file_record:
        shared_with = file_record.get('shared_with', [])
        if role not in shared_with:
            shared_with.append(role)
            files_table.update({'shared_with': shared_with}, File.id == file_id)

def get_files_shared_with_role(role):
    all_files = files_table.all()
    return [f for f in all_files if role in f.get('shared_with', [])]

def create_shared_secret(sender_id, sender_role, recipient_role, title, encrypted_content, encryption_hash):
    secret_id = get_next_id(shared_secrets_table)
    secret_data = {
        'id': secret_id,
        'sender_id': sender_id,
        'sender_role': sender_role,
        'recipient_role': recipient_role,
        'title': title,
        'encrypted_content': encrypted_content,
        'encryption_hash': encryption_hash,
        'is_read': False,
        'created_at': datetime.now().isoformat()
    }
    shared_secrets_table.insert(secret_data)
    return secret_data

def get_secrets_for_role(role):
    return shared_secrets_table.search(Secret.recipient_role == role)

def get_secrets_sent_by_user(user_id):
    return shared_secrets_table.search(Secret.sender_id == user_id)

def get_secret_by_id(secret_id):
    result = shared_secrets_table.search(Secret.id == secret_id)
    return result[0] if result else None

def mark_secret_read(secret_id):
    shared_secrets_table.update({'is_read': True}, Secret.id == secret_id)

def create_schedule(route_id, date, time, available_slots, manager_id):
    schedule_id = get_next_id(schedules_table)
    schedule_data = {
        'id': schedule_id,
        'route_id': route_id,
        'date': date,
        'time': time,
        'available_slots': available_slots,
        'booked_slots': 0,
        'manager_id': manager_id,
        'is_active': True,
        'created_at': datetime.now().isoformat()
    }
    schedules_table.insert(schedule_data)
    return schedule_data

def get_all_schedules():
    return schedules_table.all()

def get_schedules_by_route(route_id):
    return schedules_table.search(Schedule.route_id == route_id)

def get_schedule_by_id(schedule_id):
    result = schedules_table.search(Schedule.id == schedule_id)
    return result[0] if result else None

def update_schedule(schedule_id, data):
    schedules_table.update(data, Schedule.id == schedule_id)

def book_schedule_slots(schedule_id, num_slots):
    schedule = get_schedule_by_id(schedule_id)
    if schedule:
        new_booked = schedule.get('booked_slots', 0) + num_slots
        schedules_table.update({'booked_slots': new_booked}, Schedule.id == schedule_id)

def get_active_schedules():
    return schedules_table.search(Schedule.is_active == True)

def get_stats():
    return {
        'total_users': len(users_table.all()),
        'total_routes': len(routes_table.all()),
        'total_bookings': len(bookings_table.all()),
        'total_files': len(files_table.all()),
        'admin_count': len(get_users_by_role('admin')),
        'manager_count': len(get_users_by_role('trekking_management')),
        'user_count': len(get_users_by_role('user'))
    }
