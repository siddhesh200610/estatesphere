from dotenv import load_dotenv
import os
import uuid
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "estatesphere-secret-key")

# Database configuration
db_url = os.getenv("DATABASE_URL")

if db_url and db_url.startswith("mysql://"):
    db_url = db_url.replace("mysql://", "mysql+mysqlconnector://", 1)

if db_url and "?" in db_url:
    base_url, query_params = db_url.split("?", 1)
    params_list = [
        p for p in query_params.split("&")
        if not p.startswith("ssl-mode") and not p.startswith("ssl_mode")
    ]
    db_url = f"{base_url}?" + "&".join(params_list) if params_list else base_url

app.config["SQLALCHEMY_DATABASE_URI"] = (
    db_url or "mysql+mysqlconnector://root@localhost/estatesphere"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Image upload settings
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

DEFAULT_CATEGORIES = ["Apartment", "House", "Villa", "Plot", "Commercial"]

# Only approved/available properties are shown to buyers.
LIVE_STATUSES = ("approved", "Approved", "available", "Available")
LIVE_SQL = "status IN ('approved', 'Approved', 'Available', 'available')"


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def normalize_listing_type(value):
    """Treat sell/sale as buy; preserve rent."""
    return "rent" if (value or "").strip().lower() == "rent" else "buy"


def to_positive_number(value):
    """Return a positive number or None."""
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None

    return number if number > 0 else None


def role_home():
    if session.get("user_role") == "admin":
        return url_for("admin_dashboard")
    return url_for("dashboard")


def save_images(files):
    """Save uploaded images and return their static paths."""
    saved = []

    for file in files:
        if not file or not file.filename:
            continue

        ext = (
            file.filename.rsplit(".", 1)[-1].lower()
            if "." in file.filename else ""
        )

        if ext not in ALLOWED_EXT:
            continue

        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        saved.append(f"/static/uploads/{filename}")

    return saved


def role_required(*roles):
    """Restrict routes to the specified user roles."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))

            if session.get("user_role") not in roles:
                return (
                    f"Access denied. This page is only for: {', '.join(roles)}.",
                    403
                )

            return function(*args, **kwargs)

        return wrapper

    return decorator


def ensure_categories_table():
    """Create the categories table if it does not exist."""
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))

    count = db.session.execute(
        text("SELECT COUNT(*) FROM categories")
    ).scalar()

    if count == 0:
        for category in DEFAULT_CATEGORIES:
            db.session.execute(
                text("INSERT INTO categories (name) VALUES (:name)"),
                {"name": category}
            )

    db.session.commit()


@app.context_processor
def inject_categories():
    """Make categories available to all templates."""
    try:
        ensure_categories_table()

        rows = db.session.execute(
            text("SELECT name FROM categories ORDER BY name")
        ).fetchall()

        return {"categories": [row[0] for row in rows]}

    except Exception:
        db.session.rollback()
        return {"categories": DEFAULT_CATEGORIES}


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    properties_list = db.session.execute(
        text(
            f"SELECT * FROM properties WHERE {LIVE_SQL} "
            "ORDER BY created_at DESC LIMIT 6"
        )
    ).fetchall()

    return render_template("index.html", properties=properties_list)


# =========================================================
# LOGIN, LOGOUT AND REGISTRATION
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
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

            return redirect(role_home())

        return render_template(
            "login.html",
            error="Invalid email or password"
        )

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "buyer")

        # Public registration cannot create admin accounts.
        if role not in ("buyer", "owner"):
            role = "buyer"

        if not name or not email or len(password) < 6:
            return render_template(
                "register.html",
                error=(
                    "Name, email and a password of at least "
                    "6 characters are required."
                )
            )

        try:
            db.session.execute(
                text("""
                    INSERT INTO users (name, email, password, role)
                    VALUES (:name, :email, :password, :role)
                """),
                {
                    "name": name,
                    "email": email,
                    "password": generate_password_hash(password),
                    "role": role
                }
            )

            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as error:
            db.session.rollback()
            print(f"Registration error: {error}")

            return render_template(
                "register.html",
                error="Email already registered or invalid data!"
            )

    return render_template("register.html")


# =========================================================
# 1. OWNER / SELLER - PROPERTY MANAGEMENT
# =========================================================

@app.route("/add-property", methods=["GET", "POST"])
@role_required("owner")
def add_property():
    # Only owners can upload properties. Admin cannot use this route.
    if request.method == "POST":
        price = to_positive_number(request.form.get("price"))
        area = to_positive_number(request.form.get("area"))
        title = request.form.get("title", "").strip()
        location = request.form.get("location", "").strip()
        property_type = request.form.get("property_type", "").strip()

        if not title or not location or not property_type:
            flash("Title, property type and location are required.", "danger")
            return redirect(url_for("add_property"))

        if price is None or area is None:
            flash("Enter a valid price and area.", "danger")
            return redirect(url_for("add_property"))

        images = save_images(request.files.getlist("images"))

        image_url = request.form.get("image", "").strip()
        if image_url:
            images.append(image_url)

        # Owner properties remain pending until admin approval.
        db.session.execute(
            text("""
                INSERT INTO properties (
                    owner_id, title, property_type, listing_type,
                    price, area, location, description, image, status
                )
                VALUES (
                    :owner_id, :title, :property_type, :listing_type,
                    :price, :area, :location, :description, :image, 'pending'
                )
            """),
            {
                "owner_id": session["user_id"],
                "title": title,
                "property_type": property_type,
                "listing_type": normalize_listing_type(
                    request.form.get("listing_type")
                ),
                "price": price,
                "area": area,
                "location": location,
                "description": request.form.get("description", ""),
                "image": ",".join(images)
            }
        )

        db.session.commit()
        flash(
            "Property submitted. It will be visible to buyers after admin approval.",
            "success"
        )
        return redirect(url_for("my_properties"))

    return render_template("add_property.html")


@app.route("/my-properties")
@role_required("owner")
def my_properties():
    properties_list = db.session.execute(
        text("""
            SELECT *
            FROM properties
            WHERE owner_id = :owner_id
            ORDER BY created_at DESC
        """),
        {"owner_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "my_properties.html",
        properties=properties_list
    )


@app.route("/edit-property/<int:property_id>", methods=["GET", "POST"])
@role_required("owner")
def edit_property(property_id):
    owner_id = session["user_id"]

    # An owner can edit only their own property.
    prop = db.session.execute(
        text("""
            SELECT *
            FROM properties
            WHERE id = :property_id AND owner_id = :owner_id
        """),
        {
            "property_id": property_id,
            "owner_id": owner_id
        }
    ).fetchone()

    if not prop:
        return "Property not found or you do not have permission to edit it.", 404

    if request.method == "POST":
        price = to_positive_number(request.form.get("price"))
        area = to_positive_number(request.form.get("area"))

        if price is None or area is None:
            flash("Please enter a valid price and area.", "danger")
            return redirect(
                url_for("edit_property", property_id=property_id)
            )

        existing_images = [
            image for image in (prop.image or "").split(",") if image
        ]

        removed_images = set(request.form.getlist("remove_images"))

        images = [
            image for image in existing_images
            if image not in removed_images
        ]

        images += save_images(request.files.getlist("images"))

        image_url = request.form.get("image", "").strip()
        if image_url:
            images.append(image_url)

        # Rejected properties go back to pending after being edited.
        new_status = (
            "pending" if prop.status == "rejected" else prop.status
        )

        db.session.execute(
            text("""
                UPDATE properties
                SET title = :title,
                    property_type = :property_type,
                    listing_type = :listing_type,
                    price = :price,
                    area = :area,
                    location = :location,
                    description = :description,
                    image = :image,
                    status = :status
                WHERE id = :property_id AND owner_id = :owner_id
            """),
            {
                "title": request.form.get("title", "").strip(),
                "property_type": request.form.get("property_type", ""),
                "listing_type": normalize_listing_type(
                    request.form.get("listing_type")
                ),
                "price": price,
                "area": area,
                "location": request.form.get("location", "").strip(),
                "description": request.form.get("description", ""),
                "image": ",".join(images),
                "status": new_status,
                "property_id": property_id,
                "owner_id": owner_id
            }
        )

        db.session.commit()

        if new_status == "pending" and prop.status == "rejected":
            flash(
                "Property updated and sent for admin approval again.",
                "success"
            )
        else:
            flash("Property updated successfully.", "success")

        return redirect(url_for("my_properties"))

    return render_template("edit_property.html", property=prop)


@app.route("/delete-property/<int:property_id>", methods=["POST"])
@role_required("owner")
def delete_property(property_id):
    # Owners can delete only their own properties.
    property_row = db.session.execute(
        text("""
            SELECT id
            FROM properties
            WHERE id = :property_id AND owner_id = :owner_id
        """),
        {
            "property_id": property_id,
            "owner_id": session["user_id"]
        }
    ).fetchone()

    if not property_row:
        return "Property not found or unauthorized.", 404

    # Remove dependent records before deleting the property.
    db.session.execute(
        text("DELETE FROM wishlist WHERE property_id = :p"),
        {"p": property_id}
    )
    db.session.execute(
        text("DELETE FROM inquiries WHERE property_id = :p"),
        {"p": property_id}
    )
    db.session.execute(
        text("DELETE FROM property_requests WHERE property_id = :p"),
        {"p": property_id}
    )
    db.session.execute(
        text("DELETE FROM properties WHERE id = :p AND owner_id = :o"),
        {
            "p": property_id,
            "o": session["user_id"]
        }
    )

    db.session.commit()
    flash("Property deleted successfully.", "success")

    return redirect(url_for("my_properties"))


# ---- Owner: view inquiries for their properties ----

@app.route("/owner-inquiries")
@role_required("owner")
def owner_inquiries():
    inquiries = db.session.execute(
        text("""
            SELECT
                inquiries.id,
                inquiries.message,
                inquiries.status,
                inquiries.created_at,
                properties.title AS property_title,
                properties.location,
                users.name AS user_name,
                users.email AS user_email
            FROM inquiries
            JOIN properties
                ON inquiries.property_id = properties.id
            JOIN users
                ON inquiries.user_id = users.id
            WHERE properties.owner_id = :owner_id
            ORDER BY inquiries.created_at DESC
        """),
        {"owner_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "owner_inquiries.html",
        inquiries=inquiries
    )


@app.route("/update-inquiry-status/<int:inquiry_id>", methods=["POST"])
@role_required("owner")
def update_inquiry_status(inquiry_id):
    status = request.form.get("status", "")

    if status not in ["pending", "contacted", "closed"]:
        return "Invalid inquiry status.", 400

    # Update only inquiries belonging to this owner's properties.
    db.session.execute(
        text("""
            UPDATE inquiries
            SET status = :status
            WHERE id = :inquiry_id
              AND property_id IN (
                  SELECT id
                  FROM properties
                  WHERE owner_id = :owner_id
              )
        """),
        {
            "status": status,
            "inquiry_id": inquiry_id,
            "owner_id": session["user_id"]
        }
    )

    db.session.commit()
    flash("Inquiry status updated.", "success")

    return redirect(url_for("owner_inquiries"))


# ---- Owner: view buyer requests ----

@app.route("/owner-requests")
@role_required("owner")
def owner_requests():
    requests_list = db.session.execute(
        text("""
            SELECT
                pr.id,
                pr.property_id,
                pr.request_type,
                pr.message,
                pr.status,
                pr.created_at,
                p.title AS property_title,
                p.location,
                u.name AS user_name,
                u.email AS user_email
            FROM property_requests pr
            INNER JOIN properties p ON pr.property_id = p.id
            INNER JOIN users u ON pr.user_id = u.id
            WHERE p.owner_id = :owner_id
            ORDER BY pr.created_at DESC
        """),
        {"owner_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "owner_requests.html",
        requests=requests_list
    )


@app.route("/update-property-request-status/<int:request_id>", methods=["POST"])
@role_required("owner")
def update_property_request_status(request_id):
    status = request.form.get("status", "").strip()

    if status not in ["approved", "rejected", "completed"]:
        return "Invalid request status.", 400

    request_row = db.session.execute(
        text("""
            SELECT
                pr.id,
                pr.status,
                pr.request_type,
                p.id AS property_id,
                p.listing_type,
                p.status AS property_status
            FROM property_requests pr
            INNER JOIN properties p ON pr.property_id = p.id
            WHERE pr.id = :request_id
              AND p.owner_id = :owner_id
        """),
        {
            "request_id": request_id,
            "owner_id": session["user_id"]
        }
    ).fetchone()

    if not request_row:
        return "Property request not found or access denied.", 404

    current_status = request_row.status

    if current_status == "pending" and status not in ["approved", "rejected"]:
        return "Invalid status transition.", 400

    if current_status == "approved" and status != "completed":
        return "Invalid status transition.", 400

    if current_status in ["rejected", "completed"]:
        return "This request can no longer be updated.", 400

    db.session.execute(
        text("""
            UPDATE property_requests
            SET status = :status
            WHERE id = :request_id
        """),
        {
            "status": status,
            "request_id": request_id
        }
    )

    if status == "completed":
        property_status = (
            "rented" if request_row.listing_type == "rent" else "sold"
        )

        db.session.execute(
            text("""
                UPDATE properties
                SET status = :status
                WHERE id = :property_id
            """),
            {
                "status": property_status,
                "property_id": request_row.property_id
            }
        )

    db.session.commit()
    flash("Request status updated.", "success")

    return redirect(url_for("owner_requests"))


# =========================================================
# 2. BUYER / TENANT - PROPERTY DISCOVERY
# =========================================================

@app.route("/properties")
def properties():
    """Search and filter approved/available properties."""
    search = request.args.get("search", "").strip()
    property_type = request.args.get("property_type", "").strip()
    listing_type = request.args.get("listing_type", "").strip()
    min_price = request.args.get("min_price", "").strip()
    max_price = request.args.get("max_price", "").strip()

    query = f"SELECT * FROM properties WHERE {LIVE_SQL}"
    params = {}

    if search:
        query += """
            AND (
                title LIKE :search
                OR location LIKE :search
                OR property_type LIKE :search
            )
        """
        params["search"] = f"%{search}%"

    if property_type:
        query += " AND property_type = :property_type"
        params["property_type"] = property_type

    if listing_type:
        if normalize_listing_type(listing_type) == "rent":
            query += " AND listing_type = 'rent'"
        else:
            query += " AND listing_type IN ('buy', 'sell', 'sale')"

    if min_price:
        query += " AND price >= :min_price"
        params["min_price"] = min_price

    if max_price:
        query += " AND price <= :max_price"
        params["max_price"] = max_price

    query += " ORDER BY created_at DESC"

    properties_list = db.session.execute(
        text(query), params
    ).fetchall()

    # FIX: pass buyer's wishlist IDs for the heart icon in properties.html.
    user_wishlist = []

    if session.get("user_role") == "buyer":
        wishlist_rows = db.session.execute(
            text("""
                SELECT property_id
                FROM wishlist
                WHERE user_id = :user_id
            """),
            {"user_id": session["user_id"]}
        ).fetchall()

        user_wishlist = [row[0] for row in wishlist_rows]

    return render_template(
        "properties.html",
        properties=properties_list,
        search=search,
        property_type=property_type,
        listing_type=listing_type,
        min_price=min_price,
        max_price=max_price,
        user_wishlist=user_wishlist
    )


@app.route("/property/<int:property_id>")
def property_details(property_id):
    if not session.get("user_id"):
        flash("Please login to explore property details!", "warning")
        return redirect(url_for("login"))

    prop = db.session.execute(
        text("SELECT * FROM properties WHERE id = :property_id"),
        {"property_id": property_id}
    ).fetchone()

    if not prop:
        return "Property not found.", 404

    is_live = prop.status in LIVE_STATUSES
    is_closed = prop.status in ("sold", "rented")

    if not (is_live or is_closed):
        # Pending/rejected listings are visible only to their owner/admin.
        if (
            session.get("user_role") != "admin"
            and session.get("user_id") != prop.owner_id
        ):
            return "This listing is not available.", 404

    in_wishlist = False

    if session.get("user_role") == "buyer":
        wishlist_row = db.session.execute(
            text("""
                SELECT id
                FROM wishlist
                WHERE user_id = :user_id AND property_id = :property_id
            """),
            {
                "user_id": session["user_id"],
                "property_id": property_id
            }
        ).fetchone()

        in_wishlist = wishlist_row is not None

    return render_template(
        "property_details.html",
        property=prop,
        is_live=is_live,
        in_wishlist=in_wishlist
    )


# ---- Wishlist: buyer only ----

@app.route("/add-wishlist/<int:property_id>", methods=["POST"])
@role_required("buyer")
def add_wishlist(property_id):
    prop = db.session.execute(
        text(
            f"SELECT id FROM properties "
            f"WHERE id = :property_id AND {LIVE_SQL}"
        ),
        {"property_id": property_id}
    ).fetchone()

    if not prop:
        return "This property is not available.", 404

    existing = db.session.execute(
        text("""
            SELECT id
            FROM wishlist
            WHERE user_id = :user_id AND property_id = :property_id
        """),
        {
            "user_id": session["user_id"],
            "property_id": property_id
        }
    ).fetchone()

    if not existing:
        db.session.execute(
            text("""
                INSERT INTO wishlist (user_id, property_id)
                VALUES (:user_id, :property_id)
            """),
            {
                "user_id": session["user_id"],
                "property_id": property_id
            }
        )
        db.session.commit()

    # FIX: return to property details when the heart button was clicked there.
    if request.form.get("next") == "property":
        return redirect(
            url_for("property_details", property_id=property_id)
        )

    return redirect(url_for("wishlist"))


@app.route("/remove-wishlist/<int:property_id>", methods=["POST"])
@role_required("buyer")
def remove_wishlist(property_id):
    db.session.execute(
        text("""
            DELETE FROM wishlist
            WHERE user_id = :user_id AND property_id = :property_id
        """),
        {
            "user_id": session["user_id"],
            "property_id": property_id
        }
    )

    db.session.commit()

    if request.form.get("next") == "property":
        return redirect(
            url_for("property_details", property_id=property_id)
        )

    return redirect(url_for("wishlist"))


@app.route("/wishlist")
@role_required("buyer")
def wishlist():
    wishlist_properties = db.session.execute(
        text("""
            SELECT
                wishlist.id AS wishlist_id,
                properties.id AS property_id,
                properties.title,
                properties.property_type,
                properties.listing_type,
                properties.price,
                properties.area,
                properties.location,
                properties.description,
                properties.image,
                properties.status
            FROM wishlist
            JOIN properties ON wishlist.property_id = properties.id
            WHERE wishlist.user_id = :user_id
            ORDER BY wishlist.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "wishlist.html",
        wishlist_properties=wishlist_properties
    )


# ---- Buyer inquiry ----

@app.route("/inquiry/<int:property_id>", methods=["GET", "POST"])
@role_required("buyer")
def inquiry(property_id):
    prop = db.session.execute(
        text(
            f"SELECT * FROM properties "
            f"WHERE id = :property_id AND {LIVE_SQL}"
        ),
        {"property_id": property_id}
    ).fetchone()

    if not prop:
        return "Property not found or no longer available.", 404

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if not message:
            return render_template(
                "inquiry.html",
                property=prop,
                error="Please write a message for the owner."
            )

        db.session.execute(
            text("""
                INSERT INTO inquiries (property_id, user_id, message)
                VALUES (:property_id, :user_id, :message)
            """),
            {
                "property_id": property_id,
                "user_id": session["user_id"],
                "message": message
            }
        )

        db.session.commit()

        return render_template(
            "request_result.html",
            success=True,
            property=prop,
            message="Your inquiry has been sent to the owner!",
            next_url=url_for("my_inquiries"),
            next_label="My Inquiries"
        )

    return render_template("inquiry.html", property=prop)


@app.route("/my-inquiries")
@role_required("buyer")
def my_inquiries():
    inquiries = db.session.execute(
        text("""
            SELECT
                inquiries.id,
                inquiries.property_id,
                inquiries.message,
                inquiries.status,
                inquiries.created_at,
                properties.title AS property_title,
                properties.location,
                users.name AS user_name,
                users.email AS user_email
            FROM inquiries
            JOIN properties ON inquiries.property_id = properties.id
            JOIN users ON inquiries.user_id = users.id
            WHERE inquiries.user_id = :user_id
            ORDER BY inquiries.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "my_inquiries.html",
        inquiries=inquiries
    )


# ---- Buyer buy/rent request ----

@app.route("/property-request/<int:property_id>", methods=["POST"])
@role_required("buyer")
def property_request(property_id):
    prop = db.session.execute(
        text("""
            SELECT id, owner_id, title, listing_type, status
            FROM properties
            WHERE id = :property_id
        """),
        {"property_id": property_id}
    ).fetchone()

    if not prop:
        return "Property not found.", 404

    if prop.status not in LIVE_STATUSES:
        return render_template(
            "request_result.html",
            success=False,
            property=prop,
            message="This property is no longer available."
        )

    request_type = "rent" if prop.listing_type == "rent" else "buy"

    existing_request = db.session.execute(
        text("""
            SELECT id
            FROM property_requests
            WHERE property_id = :property_id
              AND user_id = :user_id
              AND request_type = :request_type
              AND status = 'pending'
        """),
        {
            "property_id": property_id,
            "user_id": session["user_id"],
            "request_type": request_type
        }
    ).fetchone()

    if existing_request:
        return render_template(
            "request_result.html",
            success=False,
            property=prop,
            message=(
                "You have already submitted a pending request "
                "for this property."
            )
        )

    message = (
        request.form.get("message", "").strip()
        or f"I am interested in this property and would like to {request_type} it."
    )

    db.session.execute(
        text("""
            INSERT INTO property_requests (
                property_id, user_id, request_type, message
            )
            VALUES (
                :property_id, :user_id, :request_type, :message
            )
        """),
        {
            "property_id": property_id,
            "user_id": session["user_id"],
            "request_type": request_type,
            "message": message
        }
    )

    db.session.commit()

    return render_template(
        "request_result.html",
        success=True,
        property=prop,
        message="Your request has been submitted successfully!"
    )


@app.route("/my-requests")
@role_required("buyer")
def my_requests():
    requests_list = db.session.execute(
        text("""
            SELECT
                pr.id,
                pr.property_id,
                pr.request_type,
                pr.message,
                pr.status,
                pr.created_at,
                p.title AS property_title,
                p.location
            FROM property_requests pr
            INNER JOIN properties p ON pr.property_id = p.id
            WHERE pr.user_id = :user_id
            ORDER BY pr.created_at DESC
        """),
        {"user_id": session["user_id"]}
    ).fetchall()

    return render_template(
        "my_requests.html",
        requests=requests_list
    )


# =========================================================
# 3. ADMIN - SYSTEM ADMINISTRATION
# Admin can manage properties but cannot add properties.
# =========================================================

@app.route("/admin-dashboard")
@role_required("admin")
def admin_dashboard():
    def scalar(sql):
        return db.session.execute(text(sql)).scalar() or 0

    stats = {
        "users": scalar("SELECT COUNT(*) FROM users"),
        "owners": scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'"),
        "properties": scalar("SELECT COUNT(*) FROM properties"),
        "pending": scalar(
            "SELECT COUNT(*) FROM properties WHERE status = 'pending'"
        ),
        "inquiries": scalar("SELECT COUNT(*) FROM inquiries")
    }

    pending_list = db.session.execute(
        text("""
            SELECT
                p.id,
                p.title,
                p.location,
                p.property_type,
                p.price,
                COALESCE(u.name, 'Unknown') AS owner_name
            FROM properties p
            LEFT JOIN users u ON p.owner_id = u.id
            WHERE p.status = 'pending'
            ORDER BY p.created_at DESC
            LIMIT 10
        """)
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        pending_list=pending_list
    )


# ---- Admin: manage users ----

@app.route("/admin-users")
@role_required("admin")
def admin_users():
    users = db.session.execute(
        text("""
            SELECT id, name, email, role, created_at
            FROM users
            ORDER BY created_at DESC
        """)
    ).fetchall()

    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return "You cannot delete your own admin account.", 400

    target = db.session.execute(
        text("SELECT id, role FROM users WHERE id = :id"),
        {"id": user_id}
    ).fetchone()

    if not target or target.role == "admin":
        return "User not found or cannot be deleted.", 404

    # Remove the user's related records before deleting the user.
    owned_properties = "SELECT id FROM properties WHERE owner_id = :id"

    delete_queries = [
        f"""
            DELETE FROM wishlist
            WHERE property_id IN ({owned_properties}) OR user_id = :id
        """,
        f"""
            DELETE FROM inquiries
            WHERE property_id IN ({owned_properties}) OR user_id = :id
        """,
        f"""
            DELETE FROM property_requests
            WHERE property_id IN ({owned_properties}) OR user_id = :id
        """,
        "DELETE FROM properties WHERE owner_id = :id",
        "DELETE FROM users WHERE id = :id"
    ]

    for sql in delete_queries:
        db.session.execute(text(sql), {"id": user_id})

    db.session.commit()
    flash("User deleted successfully.", "success")

    return redirect(url_for("admin_users"))


# ---- Admin: manage all properties ----

@app.route("/admin-properties")
@role_required("admin")
def admin_properties():
    properties_rows = db.session.execute(
        text("""
            SELECT
                properties.id,
                properties.owner_id,
                properties.title,
                properties.property_type,
                properties.listing_type,
                properties.price,
                properties.area,
                properties.location,
                properties.description,
                properties.image,
                properties.status,
                properties.created_at,
                users.name AS owner_name,
                users.email AS owner_email
            FROM properties
            JOIN users ON properties.owner_id = users.id
            ORDER BY properties.created_at DESC
        """)
    ).fetchall()

    return render_template(
        "admin_properties.html",
        properties=properties_rows
    )

# ---- Admin: edit a property ----

@app.route("/admin/property/<int:property_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def admin_edit_property(property_id):
    prop = db.session.execute(
        text("SELECT * FROM properties WHERE id = :id"),
        {"id": property_id}
    ).fetchone()

    if not prop:
        flash("Property not found.", "danger")
        return redirect(url_for("admin_properties"))

    # Admin can edit only properties uploaded by their own account.
    if prop.owner_id != session["user_id"]:
        flash(
            "You can only edit properties uploaded by your account.",
            "danger"
        )
        return redirect(url_for("admin_properties"))

    if request.method == "POST":
        price = to_positive_number(request.form.get("price"))
        area = to_positive_number(request.form.get("area"))

        if price is None or area is None:
            flash("Please enter a valid price and area.", "danger")
            return redirect(
                url_for("admin_edit_property", property_id=property_id)
            )

        existing_images = [
            image for image in (prop.image or "").split(",") if image
        ]

        removed_images = set(request.form.getlist("remove_images"))

        images = [
            image for image in existing_images
            if image not in removed_images
        ]

        images += save_images(request.files.getlist("images"))

        image_url = request.form.get("image_url", "").strip()
        if image_url:
            images.append(image_url)

        db.session.execute(
            text("""
                UPDATE properties
                SET title = :title,
                    property_type = :property_type,
                    listing_type = :listing_type,
                    price = :price,
                    area = :area,
                    location = :location,
                    description = :description,
                    image = :image
                WHERE id = :id
                  AND owner_id = :owner_id
            """),
            {
                "title": request.form.get("title", "").strip(),
                "property_type": request.form.get("property_type", ""),
                "listing_type": normalize_listing_type(
                    request.form.get("listing_type")
                ),
                "price": price,
                "area": area,
                "location": request.form.get("location", "").strip(),
                "description": request.form.get("description", ""),
                "image": ",".join(images),
                "id": property_id,
                "owner_id": session["user_id"]
            }
        )

        db.session.commit()
        flash("Property updated successfully.", "success")
        return redirect(url_for("admin_properties"))

    existing_images = [
        image for image in (prop.image or "").split(",") if image
    ]

    return render_template(
        "admin_edit_property.html",
        property=prop,
        existing_images=existing_images
    )
# ---- Admin: approve a property ----

@app.route("/admin/property/<int:id>/approve", methods=["POST"])
@role_required("admin")
def approve_property(id):
    db.session.execute(
        text("""
            UPDATE properties
            SET status = 'approved'
            WHERE id = :id
              AND status IN ('pending', 'rejected')
        """),
        {"id": id}
    )

    db.session.commit()
    flash("Property approved.", "success")

    return redirect(url_for("admin_properties"))


# ---- Admin: reject a property ----

@app.route("/admin/property/<int:id>/reject", methods=["POST"])
@role_required("admin")
def reject_property(id):
    db.session.execute(
        text("""
            UPDATE properties
            SET status = 'rejected'
            WHERE id = :id
              AND status IN (
                  'pending', 'approved', 'available',
                  'Available', 'Approved'
              )
        """),
        {"id": id}
    )

    db.session.commit()
    flash("Property rejected.", "success")

    return redirect(url_for("admin_properties"))


# ---- Admin: manage inquiries ----

@app.route("/admin-inquiries")
@role_required("admin")
def admin_inquiries():
    # FIX: include the property owner's name in the result.
    inquiries = db.session.execute(
        text("""
            SELECT
                inquiries.id,
                inquiries.message,
                inquiries.status,
                inquiries.created_at,
                properties.title AS property_title,
                properties.location,
                users.name AS user_name,
                users.email AS user_email,
                owner.name AS owner_name
            FROM inquiries
            JOIN properties
                ON inquiries.property_id = properties.id
            JOIN users
                ON inquiries.user_id = users.id
            JOIN users owner
                ON properties.owner_id = owner.id
            ORDER BY inquiries.created_at DESC
        """)
    ).fetchall()

    return render_template(
        "admin_inquiries.html",
        inquiries=inquiries
    )



    status = request.form.get("status", "")

    if status not in ["pending", "contacted", "closed"]:
        return "Invalid inquiry status.", 400

    db.session.execute(
        text("""
            UPDATE inquiries
            SET status = :status
            WHERE id = :id
        """),
        {
            "status": status,
            "id": inquiry_id
        }
    )

    db.session.commit()
    flash("Inquiry status updated.", "success")

    return redirect(url_for("admin_inquiries"))


@app.route("/admin/inquiry/<int:inquiry_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_inquiry(inquiry_id):
    db.session.execute(
        text("DELETE FROM inquiries WHERE id = :id"),
        {"id": inquiry_id}
    )

    db.session.commit()
    flash("Inquiry deleted successfully.", "success")

    return redirect(url_for("admin_inquiries"))


# ---- Admin: manage categories ----

@app.route("/admin-categories", methods=["GET", "POST"])
@role_required("admin")
def admin_categories():
    ensure_categories_table()

    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if name:
            try:
                db.session.execute(
                    text("INSERT INTO categories (name) VALUES (:name)"),
                    {"name": name}
                )

                db.session.commit()
                flash("Category added successfully.", "success")

            except Exception:
                db.session.rollback()
                flash("Category already exists.", "warning")

        return redirect(url_for("admin_categories"))

    rows = db.session.execute(
        text("""
            SELECT id, name, created_at
            FROM categories
            ORDER BY name
        """)
    ).fetchall()

    return render_template("admin_categories.html", rows=rows)


@app.route("/admin/category/<int:cat_id>/rename", methods=["POST"])
@role_required("admin")
def admin_rename_category(cat_id):
    new_name = request.form.get("name", "").strip()

    old = db.session.execute(
        text("SELECT name FROM categories WHERE id = :id"),
        {"id": cat_id}
    ).fetchone()

    if not new_name or not old:
        flash("Invalid category.", "warning")
        return redirect(url_for("admin_categories"))

    try:
        db.session.execute(
            text("""
                UPDATE categories
                SET name = :new_name
                WHERE id = :id
            """),
            {
                "new_name": new_name,
                "id": cat_id
            }
        )

        # Update property types when a category is renamed.
        db.session.execute(
            text("""
                UPDATE properties
                SET property_type = :new_name
                WHERE property_type = :old_name
            """),
            {
                "new_name": new_name,
                "old_name": old.name
            }
        )

        db.session.commit()
        flash("Category renamed successfully.", "success")

    except Exception:
        db.session.rollback()
        flash("A category with that name already exists.", "warning")

    return redirect(url_for("admin_categories"))


@app.route("/admin/category/<int:cat_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_category(cat_id):
    db.session.execute(
        text("DELETE FROM categories WHERE id = :id"),
        {"id": cat_id}
    )

    db.session.commit()
    flash("Category deleted.", "success")

    return redirect(url_for("admin_categories"))


# ---- Admin: reports ----

@app.route("/admin-reports")
@role_required("admin")
def admin_reports():
    def query_rows(sql):
        return db.session.execute(text(sql)).fetchall()

    data = {
        "users_by_role": query_rows(
            "SELECT role, COUNT(*) FROM users GROUP BY role"
        ),
        "props_by_status": query_rows(
            "SELECT status, COUNT(*) FROM properties GROUP BY status"
        ),
        "props_by_listing": query_rows(
            "SELECT listing_type, COUNT(*) FROM properties GROUP BY listing_type"
        ),
        "props_by_type": query_rows(
            "SELECT property_type, COUNT(*) FROM properties GROUP BY property_type"
        ),
        "reqs_by_status": query_rows(
            "SELECT status, COUNT(*) FROM property_requests GROUP BY status"
        ),
        "inq_by_status": query_rows(
            "SELECT status, COUNT(*) FROM inquiries GROUP BY status"
        ),
        "top_wishlisted": query_rows("""
            SELECT p.title, COUNT(*) AS c
            FROM wishlist w
            JOIN properties p ON p.id = w.property_id
            GROUP BY p.id, p.title
            ORDER BY c DESC
            LIMIT 5
        """)
    }

    return render_template("admin_reports.html", **data)

@app.route("/admin/property/<int:property_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_property(property_id):
    prop = db.session.execute(
        text("SELECT id FROM properties WHERE id = :id"),
        {"id": property_id}
    ).fetchone()

    if not prop:
        flash("Property not found.", "danger")
        return redirect(url_for("admin_properties"))

    try:
        db.session.execute(
            text("DELETE FROM wishlist WHERE property_id = :id"),
            {"id": property_id}
        )
        db.session.execute(
            text("DELETE FROM inquiries WHERE property_id = :id"),
            {"id": property_id}
        )
        db.session.execute(
            text("DELETE FROM property_requests WHERE property_id = :id"),
            {"id": property_id}
        )
        db.session.execute(
            text("DELETE FROM properties WHERE id = :id"),
            {"id": property_id}
        )

        db.session.commit()
        flash("Property deleted successfully.", "success")

    except Exception as error:
        db.session.rollback()
        print(f"Property deletion error: {error}")
        flash("Unable to delete property.", "danger")

    return redirect(url_for("admin_properties"))
# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=False)