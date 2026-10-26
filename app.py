from dotenv import load_dotenv
import os
import uuid
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Flask Session Secret Key
app.secret_key = os.getenv("SECRET_KEY", "estatesphere-secret-key")

# Database Configuration (Secure: No hardcoded password)
db_url = os.getenv("DATABASE_URL")

if db_url and db_url.startswith("mysql://"):
    db_url = db_url.replace("mysql://", "mysql+mysqlconnector://", 1)

if db_url and "?" in db_url:
    base_url, query_params = db_url.split("?", 1)
    params_list = [p for p in query_params.split("&") if not p.startswith("ssl-mode") and not p.startswith("ssl_mode")]
    db_url = f"{base_url}?" + "&".join(params_list) if params_list else base_url

# Fallback URI uses localhost without hardcoded password
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "mysql+mysqlconnector://root@localhost/estatesphere"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Image upload settings
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB per request

DEFAULT_CATEGORIES = ["Apartment", "House", "Villa", "Plot", "Commercial"]


def save_images(files):
    """Save uploaded image files, return list of '/static/uploads/<name>' paths."""
    saved = []
    for f in files:
        if not f or not f.filename:
            continue
        ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        if ext not in ALLOWED_EXT:
            continue
        name = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
        f.save(os.path.join(UPLOAD_FOLDER, name))
        saved.append(f"/static/uploads/{name}")
    return saved


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("user_role") not in roles:
                return "Access denied.", 403
            return fn(*a, **kw)
        return wrapper
    return deco


def ensure_categories_table():
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    if db.session.execute(text("SELECT COUNT(*) FROM categories")).scalar() == 0:
        for c in DEFAULT_CATEGORIES:
            db.session.execute(text("INSERT INTO categories (name) VALUES (:n)"), {"n": c})
    db.session.commit()


@app.context_processor
def inject_categories():
    """Makes `categories` (list of names) available in every template."""
    try:
        ensure_categories_table()
        rows = db.session.execute(text("SELECT name FROM categories ORDER BY name")).fetchall()
        return {"categories": [r[0] for r in rows]}
    except Exception:
        db.session.rollback()
        return {"categories": DEFAULT_CATEGORIES}

# =========================
# Home Page
# =========================
@app.route("/")
def home():
    properties_list = db.session.execute(
        text("SELECT * FROM properties WHERE status IN ('approved', 'Approved', 'Available', 'available') ORDER BY created_at DESC LIMIT 6")
    ).fetchall()
    return render_template("index.html", properties=properties_list)


# =========================
# Login Page
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        user = db.session.execute(
            text("SELECT * FROM users WHERE email = :email"),
            {"email": email}
        ).fetchone()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_name"] = user.name
            session["user_role"] = user.role
            session["user_email"] = user.email

            if user.role == 'admin':
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")

# =========================
# Dashboard & Logout
# =========================
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# Registration Page
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        role = request.form.get("role", "buyer")
        if role not in ("buyer", "owner"):
            role = "buyer"

        hashed_password = generate_password_hash(password)

        try:
            db.session.execute(
                text("INSERT INTO users (name, email, password, role) VALUES (:name, :email, :password, :role)"),
                {"name": name, "email": email, "password": hashed_password, "role": role}
            )
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {e}")
            return render_template("register.html", error="Email already registered or invalid data!")

    return render_template("register.html")


# =========================
# Add Property
# =========================
@app.route("/add-property", methods=["GET", "POST"])
@role_required("owner", "admin")
def add_property():
    if request.method == "POST":
        owner_id = session.get("user_id")
        images = save_images(request.files.getlist("images"))
        url_img = request.form.get("image", "").strip()
        if url_img:
            images.append(url_img)

        # Owner listings wait for admin approval; admin listings go live directly
        status = "approved" if session.get("user_role") == "admin" else "pending"

        db.session.execute(
            text("""
                INSERT INTO properties (owner_id, title, property_type, listing_type, price, area, location, description, image, status)
                VALUES (:owner_id, :title, :property_type, :listing_type, :price, :area, :location, :description, :image, :status)
            """),
            {
                "owner_id": owner_id,
                "title": request.form.get("title", "").strip(),
                "property_type": request.form.get("property_type", ""),
                "listing_type": request.form.get("listing_type", ""),
                "price": request.form.get("price", 0) or 0,
                "area": request.form.get("area", 0) or 0,
                "location": request.form.get("location", "").strip(),
                "description": request.form.get("description", ""),
                "image": ",".join(images),
                "status": status,
            }
        )
        db.session.commit()
        flash("Property submitted. It will be visible after admin approval." if status == "pending" else "Property added.", "success")
        return redirect(url_for("my_properties") if status == "pending" else url_for("properties"))

    return render_template("add_property.html")


@app.route("/my-properties")
@role_required("owner")
def my_properties():
    rows = db.session.execute(
        text("SELECT * FROM properties WHERE owner_id = :o ORDER BY created_at DESC"),
        {"o": session["user_id"]}
    ).fetchall()
    return render_template("my_properties.html", properties=rows)


# =========================
# Edit Property
# =========================
@app.route("/edit-property/<int:property_id>", methods=["GET", "POST"])
def edit_property(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    owner_id = session.get("user_id")
    property = db.session.execute(
        text("SELECT * FROM properties WHERE id = :property_id AND owner_id = :owner_id"),
        {"property_id": property_id, "owner_id": owner_id}
    ).fetchone()

    if not property:
        return "Property not found or you do not have permission to edit it.", 404

    if request.method == "POST":
        new_images = save_images(request.files.getlist("images"))
        url_img = request.form.get("image", "").strip()
        if url_img:
            new_images.append(url_img)
        # keep old images unless new ones were provided
        image_value = ",".join(new_images) if new_images else (property.image or "")
        db.session.execute(
            text("""
                UPDATE properties SET title = :title, property_type = :property_type, listing_type = :listing_type, 
                price = :price, area = :area, location = :location, description = :description, image = :image 
                WHERE id = :property_id AND owner_id = :owner_id
            """),
            {
                "title": request.form.get("title", ""),
                "property_type": request.form.get("property_type", ""),
                "listing_type": request.form.get("listing_type", ""),
                "price": request.form.get("price", 0),
                "area": request.form.get("area", 0),
                "location": request.form.get("location", ""),
                "description": request.form.get("description", ""),
                "image": image_value,
                "property_id": property_id,
                "owner_id": owner_id
            }
        )
        db.session.commit()
        return redirect(url_for("property_details", property_id=property_id))

    return render_template("edit_property.html", property=property)


# =========================
# Delete Property
# =========================
@app.route("/delete-property/<int:property_id>", methods=["POST"])
def delete_property(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user_role = session.get("user_role")

    if user_role == "admin":
        property = db.session.execute(text("SELECT * FROM properties WHERE id = :property_id"), {"property_id": property_id}).fetchone()
    elif user_role == "owner":
        property = db.session.execute(text("SELECT * FROM properties WHERE id = :property_id AND owner_id = :owner_id"), {"property_id": property_id, "owner_id": user_id}).fetchone()
    else:
        return "Access denied.", 403

    if not property:
        return "Property not found or unauthorized.", 404

    db.session.execute(text("DELETE FROM wishlist WHERE property_id = :property_id"), {"property_id": property_id})
    db.session.execute(text("DELETE FROM inquiries WHERE property_id = :property_id"), {"property_id": property_id})
    db.session.execute(text("DELETE FROM property_requests WHERE property_id = :property_id"), {"property_id": property_id})
    db.session.execute(text("DELETE FROM properties WHERE id = :property_id"), {"property_id": property_id})
    db.session.commit()

    return redirect(url_for("admin_properties")) if user_role == "admin" else redirect(url_for("properties"))


# =========================
# Properties Listing & Search
# =========================
@app.route("/properties")
def properties():
    search = request.args.get("search", "").strip()
    property_type = request.args.get("property_type", "").strip()
    listing_type = request.args.get("listing_type", "").strip()
    min_price = request.args.get("min_price", "").strip()
    max_price = request.args.get("max_price", "").strip()

    query = "SELECT * FROM properties WHERE status IN ('approved', 'Approved', 'Available', 'available')"
    params = {}

    if search:
        query += " AND (title LIKE :search OR location LIKE :search OR property_type LIKE :search)"
        params["search"] = f"%{search}%"
    if property_type:
        query += " AND property_type = :property_type"
        params["property_type"] = property_type
    if listing_type:
        query += " AND listing_type = :listing_type"
        params["listing_type"] = listing_type
    if min_price:
        query += " AND price >= :min_price"
        params["min_price"] = min_price
    if max_price:
        query += " AND price <= :max_price"
        params["max_price"] = max_price

    query += " ORDER BY created_at DESC"
    properties_list = db.session.execute(text(query), params).fetchall()

    return render_template(
        "properties.html", properties=properties_list, search=search,
        property_type=property_type, listing_type=listing_type,
        min_price=min_price, max_price=max_price
    )


# =========================
# Property Details
# =========================
@app.route("/property/<int:property_id>")
def property_details(property_id):
    if not session.get("user_id"):
        flash("Please login to explore property details!", "warning")
        return redirect(url_for("login"))

    property = db.session.execute(text("SELECT * FROM properties WHERE id = :property_id"), {"property_id": property_id}).fetchone()
    if not property:
        return "Property not found", 404

    if property.status not in ("approved", "Approved", "available", "Available", "sold", "rented"):
        if session.get("user_role") != "admin" and session.get("user_id") != property.owner_id:
            return "This listing is not available.", 404

    return render_template("property_details.html", property=property)


# =========================
# Wishlist Routes
# =========================
@app.route("/add-wishlist/<int:property_id>", methods=["POST"])
def add_wishlist(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    existing = db.session.execute(
        text("SELECT id FROM wishlist WHERE user_id = :user_id AND property_id = :property_id"),
        {"user_id": session["user_id"], "property_id": property_id}
    ).fetchone()

    if not existing:
        db.session.execute(
            text("INSERT INTO wishlist (user_id, property_id) VALUES (:user_id, :property_id)"),
            {"user_id": session["user_id"], "property_id": property_id}
        )
        db.session.commit()

    return redirect(url_for("wishlist"))


@app.route("/remove-wishlist/<int:property_id>", methods=["POST"])
def remove_wishlist(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    db.session.execute(
        text("DELETE FROM wishlist WHERE user_id = :user_id AND property_id = :property_id"),
        {"user_id": session["user_id"], "property_id": property_id}
    )
    db.session.commit()
    return redirect(url_for("property_details", property_id=property_id))


@app.route("/wishlist")
def wishlist():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    wishlist_properties = db.session.execute(
        text("""
            SELECT wishlist.id AS wishlist_id, properties.id AS property_id, properties.title, 
            properties.property_type, properties.listing_type, properties.price, properties.area, 
            properties.location, properties.description, properties.image, properties.status 
            FROM wishlist JOIN properties ON wishlist.property_id = properties.id 
            WHERE wishlist.user_id = :user_id ORDER BY wishlist.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template("wishlist.html", wishlist_properties=wishlist_properties)


# =========================
# Inquiries Routes
# =========================
@app.route("/inquiry/<int:property_id>", methods=["GET", "POST"])
def inquiry(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    property = db.session.execute(text("SELECT * FROM properties WHERE id = :property_id"), {"property_id": property_id}).fetchone()
    if not property:
        return "Property not found", 404

    if request.method == "POST":
        user_id = session.get("user_id")
        if not user_id:
            return "Please login first."

        db.session.execute(
            text("INSERT INTO inquiries (property_id, user_id, message) VALUES (:property_id, :user_id, :message)"),
            {"property_id": property_id, "user_id": user_id, "message": request.form.get("message", "")}
        )
        db.session.commit()
        return "Inquiry sent successfully!"

    return render_template("inquiry.html", property=property)


@app.route("/my-inquiries")
def my_inquiries():
    if not session.get("user_id"):
        return "Please login first."

    inquiries = db.session.execute(
        text("""
            SELECT inquiries.id, inquiries.message, inquiries.status, inquiries.created_at, 
            properties.title AS property_title, properties.location, users.name AS user_name, users.email AS user_email 
            FROM inquiries JOIN properties ON inquiries.property_id = properties.id 
            JOIN users ON inquiries.user_id = users.id WHERE inquiries.user_id = :user_id ORDER BY inquiries.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template("my_inquiries.html", inquiries=inquiries)


@app.route("/owner-inquiries")
def owner_inquiries():
    if not session.get("user_id"):
        return "Please login first."
    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    inquiries = db.session.execute(
        text("""
            SELECT inquiries.id, inquiries.message, inquiries.status, inquiries.created_at, 
            properties.title AS property_title, properties.location, users.name AS user_name, users.email AS user_email 
            FROM inquiries JOIN properties ON inquiries.property_id = properties.id 
            JOIN users ON inquiries.user_id = users.id WHERE properties.owner_id = :owner_id ORDER BY inquiries.created_at DESC
        """),
        {"owner_id": session["user_id"]}
    ).fetchall()

    return render_template("owner_inquiries.html", inquiries=inquiries)


@app.route("/update-inquiry-status/<int:inquiry_id>", methods=["POST"])
def update_inquiry_status(inquiry_id):
    if not session.get("user_id") or session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    status = request.form.get("status", "")
    if status not in ["pending", "contacted", "closed"]:
        return "Invalid inquiry status.", 400

    db.session.execute(
        text("""
            UPDATE inquiries JOIN properties ON inquiries.property_id = properties.id 
            SET inquiries.status = :status WHERE inquiries.id = :inquiry_id AND properties.owner_id = :owner_id
        """),
        {"status": status, "inquiry_id": inquiry_id, "owner_id": session["user_id"]}
    )
    db.session.commit()
    return render_template("status_updated.html", status=status)


# =========================
# Property Requests Routes
# =========================
@app.route("/property-request/<int:property_id>", methods=["POST"])
def property_request(property_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    request_type = request.form.get("request_type", "buy")
    if request_type not in ["buy", "rent", "sell"]:
        return "Invalid request type", 400

    property = db.session.execute(text("SELECT id, owner_id, title, listing_type, status FROM properties WHERE id = :property_id"), {"property_id": property_id}).fetchone()
    if not property:
        return "Property not found", 404
    if property.owner_id == session["user_id"]:
        return "You cannot request your own property", 403

    existing_request = db.session.execute(
        text("SELECT id FROM property_requests WHERE property_id = :property_id AND user_id = :user_id AND request_type = :request_type AND status = 'pending'"),
        {"property_id": property_id, "user_id": session["user_id"], "request_type": request_type}
    ).fetchone()

    if existing_request:
        return render_template("request_result.html", success=False, message="You have already submitted a pending request for this property.", property=property)

    message = request.form.get("message", "").strip()
    if not message:
        action = "buy" if request_type == "sell" else request_type
        message = f"I am interested in this property and would like to {action} it."

    db.session.execute(
        text("INSERT INTO property_requests (property_id, user_id, request_type, message) VALUES (:property_id, :user_id, :request_type, :message)"),
        {"property_id": property_id, "user_id": session["user_id"], "request_type": request_type, "message": message}
    )
    db.session.commit()

    return render_template("request_result.html", success=True, message="Your request has been submitted successfully!", property=property)


@app.route("/my-requests")
def my_requests():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    requests_list = db.session.execute(
        text("""
            SELECT pr.id, pr.property_id, pr.request_type, pr.message, pr.status, pr.created_at, 
            p.title AS property_title, p.location FROM property_requests pr 
            INNER JOIN properties p ON pr.property_id = p.id WHERE pr.user_id = :user_id ORDER BY pr.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template("my_requests.html", requests=requests_list)


@app.route("/owner-requests")
def owner_requests():
    if not session.get("user_id"):
        return "Please login first."
    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    requests_list = db.session.execute(
        text("""
            SELECT pr.id, pr.property_id, pr.request_type, pr.message, pr.status, pr.created_at, 
            p.title AS property_title, p.location, u.name AS user_name, u.email AS user_email 
            FROM property_requests pr INNER JOIN properties p ON pr.property_id = p.id 
            INNER JOIN users u ON pr.user_id = u.id WHERE p.owner_id = :owner_id ORDER BY pr.created_at DESC
        """),
        {"owner_id": session["user_id"]}
    ).fetchall()

    return render_template("owner_requests.html", requests=requests_list)


@app.route("/update-property-request-status/<int:request_id>", methods=["POST"])
def update_property_request_status(request_id):
    if not session.get("user_id") or session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    status = request.form.get("status", "").strip()
    if status not in ["approved", "rejected", "completed"]:
        return "Invalid request status.", 400

    property_request = db.session.execute(
        text("""
            SELECT pr.id, pr.status, pr.request_type, p.id AS property_id, p.listing_type, p.status AS property_status 
            FROM property_requests pr INNER JOIN properties p ON pr.property_id = p.id 
            WHERE pr.id = :request_id AND p.owner_id = :owner_id
        """),
        {"request_id": request_id, "owner_id": session["user_id"]}
    ).fetchone()

    if not property_request:
        return "Property request not found or access denied.", 404

    current_status = property_request.status
    if current_status == "pending" and status not in ["approved", "rejected"]:
        return "Invalid status transition.", 400
    elif current_status == "approved" and status != "completed":
        return "Invalid status transition.", 400
    elif current_status in ["rejected", "completed"]:
        return "This request can no longer be updated.", 400

    db.session.execute(text("UPDATE property_requests SET status = :status WHERE id = :request_id"), {"status": status, "request_id": request_id})

    if status == "completed":
        new_prop_status = 'rented' if property_request.listing_type == "rent" else 'sold'
        db.session.execute(text("UPDATE properties SET status = :status WHERE id = :property_id"), {"status": new_prop_status, "property_id": property_request.property_id})

    db.session.commit()
    return redirect(url_for("owner_requests"))


# =========================
# Admin Dashboard & Management
# =========================
@app.route("/admin-dashboard")
def admin_dashboard():
    if not session.get("user_id") or session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    total_users = db.session.execute(text("SELECT COUNT(*) FROM users")).scalar()
    total_properties = db.session.execute(text("SELECT COUNT(*) FROM properties")).scalar()
    total_inquiries = db.session.execute(text("SELECT COUNT(*) FROM inquiries")).scalar()

    return render_template("admin_dashboard.html", total_users=total_users, total_properties=total_properties, total_inquiries=total_inquiries)


@app.route("/admin-users")
def admin_users():
    if not session.get("user_id") or session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    users = db.session.execute(text("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC")).fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin-properties")
def admin_properties():
    if not session.get("user_id") or session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    properties = db.session.execute(
        text("""
            SELECT properties.id, properties.title, properties.property_type, properties.listing_type, 
            properties.price, properties.area, properties.location, properties.description, properties.image, 
            properties.status, properties.created_at, users.name AS owner_name, users.email AS owner_email 
            FROM properties JOIN users ON properties.owner_id = users.id ORDER BY properties.created_at DESC
        """)
    ).fetchall()

    return render_template("admin_properties.html", properties=properties)


# =========================
# Admin Inquiries Route
# =========================
@app.route("/admin-inquiries")
def admin_inquiries():
    if not session.get("user_id") or session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    inquiries = db.session.execute(
        text("""
            SELECT inquiries.id, inquiries.message, inquiries.status, inquiries.created_at, 
            properties.title AS property_title, properties.location, 
            users.name AS user_name, users.email AS user_email 
            FROM inquiries 
            JOIN properties ON inquiries.property_id = properties.id 
            JOIN users ON inquiries.user_id = users.id 
            ORDER BY inquiries.created_at DESC
        """)
    ).fetchall()

    return render_template("admin_inquiries.html", inquiries=inquiries)


@app.route("/admin/property/<int:id>/approve", methods=["POST"])
def approve_property(id):
    if not session.get("user_id") or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    db.session.execute(text("UPDATE properties SET status = 'approved' WHERE id = :id"), {"id": id})
    db.session.commit()
    return redirect(url_for("admin_properties"))


@app.route("/admin/property/<int:id>/reject", methods=["POST"])
def reject_property(id):
    if not session.get("user_id") or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    db.session.execute(text("UPDATE properties SET status = 'rejected' WHERE id = :id"), {"id": id})
    db.session.commit()
    return redirect(url_for("admin_properties"))


# =========================
# Admin: Users, Categories, Reports
# =========================
@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return "You cannot delete your own admin account.", 400
    db.session.execute(text("DELETE FROM users WHERE id = :id AND role != 'admin'"), {"id": user_id})
    db.session.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin-categories", methods=["GET", "POST"])
@role_required("admin")
def admin_categories():
    ensure_categories_table()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            try:
                db.session.execute(text("INSERT INTO categories (name) VALUES (:n)"), {"n": name})
                db.session.commit()
                flash("Category added.", "success")
            except Exception:
                db.session.rollback()
                flash("Category already exists.", "warning")
        return redirect(url_for("admin_categories"))
    rows = db.session.execute(text("SELECT id, name, created_at FROM categories ORDER BY name")).fetchall()
    return render_template("admin_categories.html", rows=rows)


@app.route("/admin/category/<int:cat_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_category(cat_id):
    db.session.execute(text("DELETE FROM categories WHERE id = :id"), {"id": cat_id})
    db.session.commit()
    return redirect(url_for("admin_categories"))


@app.route("/admin-reports")
@role_required("admin")
def admin_reports():
    q = lambda sql: db.session.execute(text(sql)).fetchall()
    data = {
        "users_by_role": q("SELECT role, COUNT(*) FROM users GROUP BY role"),
        "props_by_status": q("SELECT status, COUNT(*) FROM properties GROUP BY status"),
        "props_by_listing": q("SELECT listing_type, COUNT(*) FROM properties GROUP BY listing_type"),
        "props_by_type": q("SELECT property_type, COUNT(*) FROM properties GROUP BY property_type"),
        "reqs_by_status": q("SELECT status, COUNT(*) FROM property_requests GROUP BY status"),
        "inq_by_status": q("SELECT status, COUNT(*) FROM inquiries GROUP BY status"),
        "top_wishlisted": q("""SELECT p.title, COUNT(*) c FROM wishlist w JOIN properties p ON p.id = w.property_id
                               GROUP BY p.id, p.title ORDER BY c DESC LIMIT 5"""),
    }
    return render_template("admin_reports.html", **data)


if __name__ == "__main__":
    app.run(debug=False)