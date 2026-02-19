from app import db, Admin
from werkzeug.security import generate_password_hash

admin_username = 'umang509'
admin_email = 'alokdixit193@gmail.com'
admin_password = 'Umang&5098'

hashed_password = generate_password_hash(admin_password)

new_admin = Admin(username=admin_username, email=admin_email, password=hashed_password)
with app.app_context():
    db.session.add(new_admin)
    db.session.commit()

print("Admin created successfully!")
