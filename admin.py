from app import db, Admin
from werkzeug.security import generate_password_hash

admin_username = ''
admin_email = ''
admin_password = ''

hashed_password = generate_password_hash(admin_password)

new_admin = Admin(username=admin_username, email=admin_email, password=hashed_password)
with app.app_context():
    db.session.add(new_admin)
    db.session.commit()

print("Admin created successfully!")
