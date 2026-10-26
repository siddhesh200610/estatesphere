"""Run once:  python create_admin.py   -> creates admin@estatesphere.com / Admin@123 (change the password!)"""
from app import app, db
from sqlalchemy import text
from werkzeug.security import generate_password_hash

with app.app_context():
    exists = db.session.execute(text("SELECT id FROM users WHERE email='admin@estatesphere.com'")).fetchone()
    if exists:
        print("Admin already exists.")
    else:
        db.session.execute(
            text("INSERT INTO users (name, email, password, role) VALUES ('Admin', 'admin@estatesphere.com', :p, 'admin')"),
            {"p": generate_password_hash("Admin@123")})
        db.session.commit()
        print("Admin created: admin@estatesphere.com / Admin@123")