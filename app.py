from dotenv import load_dotenv
import os
import traceback
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Flask Session Secret Key
app.secret_key = os.getenv("SECRET_KEY", "estatesphere-secret-key")

# Render ya local environment se URL uthao
db_url = os.getenv("DATABASE_URL")

# Agar URL 'mysql://' se shuru hota hai (jaise Aiven/Render ka), toh usme driver add karo
if db_url and db_url.startswith("mysql://"):
    db_url = db_url.replace("mysql://", "mysql+mysqlconnector://", 1)

# Agar URL mein ssl-mode ya ssl_mode hai, toh use hata do taaki mysql-connector error na de
if db_url and "?" in db_url:
    base_url, query_params = db_url.split("?", 1)
    params_list = [p for p in query_params.split("&") if not p.startswith("ssl-mode") and not p.startswith("ssl_mode")]
    if params_list:
        db_url = f"{base_url}?" + "&".join(params_list)
    else:
        db_url = base_url

# Agar environment mein DATABASE_URL nahi hai, toh local fallback use karo
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "mysql+mysqlconnector://root:EstateSphere123@localhost/estatesphere"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =========================
# Home Page
# =========================
@app.route("/")
def home():
    return render_template("index.html")


# =========================
# Login Page
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = db.session.execute(
            text(
                "SELECT * FROM users "
                "WHERE email = :email"
            ),
            {
                "email": email
            }
        ).fetchone()

        if user and check_password_hash(user.password, password):

            session["user_id"] = user.id
            session["user_name"] = user.name
            session["user_role"] = user.role
            session["user_email"] = user.email

            if user.role == 'admin':
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        return "Invalid email or password"

    return render_template("login.html")


# =========================
# Dashboard
# =========================
@app.route("/dashboard")
def dashboard():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    return render_template("dashboard.html")


# =========================
# Logout
# =========================
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
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        hashed_password = generate_password_hash(password)

        try:
            db.session.execute(
                text(
                    "INSERT INTO users (name, email, password, role) "
                    "VALUES (:name, :email, :password, :role)"
                ),
                {
                    "name": name,
                    "email": email,
                    "password": hashed_password,
                    "role": role
                }
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
def add_property():

    if request.method == "POST":

        owner_id = session.get("user_id")

        if not owner_id:
            return "Please login first."

        title = request.form["title"]
        property_type = request.form["property_type"]
        listing_type = request.form["listing_type"]
        price = request.form["price"]
        area = request.form["area"]
        location = request.form["location"]
        description = request.form["description"]
        image = request.form["image"]

        db.session.execute(
            text(
                """
                INSERT INTO properties
                (
                    owner_id,
                    title,
                    property_type,
                    listing_type,
                    price,
                    area,
                    location,
                    description,
                    image,
                    status
                )
                VALUES
                (
                    :owner_id,
                    :title,
                    :property_type,
                    :listing_type,
                    :price,
                    :area,
                    :location,
                    :description,
                    :image,
                    'pending'
                )
                """
            ),
            {
                "owner_id": owner_id,
                "title": title,
                "property_type": property_type,
                "listing_type": listing_type,
                "price": price,
                "area": area,
                "location": location,
                "description": description,
                "image": image
            }
        )

        db.session.commit()

        return "Property added successfully! Pending admin approval."

    return render_template("add_property.html")


# =========================================================
# EDIT PROPERTY
# =========================================================
@app.route("/edit-property/<int:property_id>", methods=["GET", "POST"])
def edit_property(property_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    owner_id = session.get("user_id")

    property = db.session.execute(
        text(
            """
            SELECT *
            FROM properties
            WHERE id = :property_id
            AND owner_id = :owner_id
            """
        ),
        {
            "property_id": property_id,
            "owner_id": owner_id
        }
    ).fetchone()

    if not property:
        return "Property not found or you do not have permission to edit it.", 404

    if request.method == "POST":

        title = request.form["title"]
        property_type = request.form["property_type"]
        listing_type = request.form["listing_type"]
        price = request.form["price"]
        area = request.form["area"]
        location = request.form["location"]
        description = request.form["description"]
        image = request.form["image"]

        db.session.execute(
            text(
                """
                UPDATE properties
                SET
                    title = :title,
                    property_type = :property_type,
                    listing_type = :listing_type,
                    price = :price,
                    area = :area,
                    location = :location,
                    description = :description,
                    image = :image
                WHERE id = :property_id
                AND owner_id = :owner_id
                """
            ),
            {
                "title": title,
                "property_type": property_type,
                "listing_type": listing_type,
                "price": price,
                "area": area,
                "location": location,
                "description": description,
                "image": image,
                "property_id": property_id,
                "owner_id": owner_id
            }
        )

        db.session.commit()

        return redirect(
            url_for(
                "property_details",
                property_id=property_id
            )
        )

    return render_template(
        "edit_property.html",
        property=property
    )


# =========================
# DELETE PROPERTY
# =========================
@app.route("/delete-property/<int:property_id>", methods=["POST"])
def delete_property(property_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user_role = session.get("user_role")

    if user_role == "admin":
        property = db.session.execute(
            text("SELECT * FROM properties WHERE id = :property_id"),
            {"property_id": property_id}
        ).fetchone()
    elif user_role == "owner":
        property = db.session.execute(
            text("SELECT * FROM properties WHERE id = :property_id AND owner_id = :owner_id"),
            {"property_id": property_id, "owner_id": user_id}
        ).fetchone()
    else:
        return "Access denied.", 403

    if not property:
        return "Property not found or unauthorized.", 404

    db.session.execute(text("DELETE FROM wishlist WHERE property_id = :property_id"), {"property_id": property_id})
    db.session.execute(text("DELETE FROM inquiries WHERE property_id = :property_id"), {"property_id": property_id})
    db.session.execute(text("DELETE FROM property_requests WHERE property_id = :property_id"), {"property_id": property_id})

    db.session.execute(
        text("DELETE FROM properties WHERE id = :property_id"),
        {"property_id": property_id}
    )
    db.session.commit()

    if user_role == "admin":
        return redirect(url_for("admin_properties"))
    else:
        return redirect(url_for("properties"))


# =========================
# Properties Listing Page
# Search & Filter
# =========================
@app.route("/properties")
def properties():

    search = request.args.get("search", "").strip()
    property_type = request.args.get("property_type", "").strip()
    listing_type = request.args.get("listing_type", "").strip()
    min_price = request.args.get("min_price", "").strip()
    max_price = request.args.get("max_price", "").strip()

    query = """
        SELECT *
        FROM properties
        WHERE status IN ('approved', 'Available', 'available')
    """

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

        query += """
            AND property_type = :property_type
        """

        params["property_type"] = property_type

    if listing_type:

        query += """
            AND listing_type = :listing_type
        """

        params["listing_type"] = listing_type

    if min_price:

        query += """
            AND price >= :min_price
        """

        params["min_price"] = min_price

    if max_price:

        query += """
            AND price <= :max_price
        """

        params["max_price"] = max_price

    query += """
        ORDER BY created_at DESC
    """

    properties = db.session.execute(
        text(query),
        params
    ).fetchall()

    return render_template(
        "properties.html",
        properties=properties,
        search=search,
        property_type=property_type,
        listing_type=listing_type,
        min_price=min_price,
        max_price=max_price
    )


# =========================
# Property Details Page (Login Required)
# =========================
@app.route("/property/<int:property_id>")
def property_details(property_id):

    # Agar user login nahi hai toh login page par bhej dein
    if not session.get("user_id"):
        flash("Please login to explore property details!", "warning")
        return redirect(url_for("login"))

    property = db.session.execute(
        text(
            "SELECT * FROM properties "
            "WHERE id = :property_id"
        ),
        {
            "property_id": property_id
        }
    ).fetchone()

    if not property:
        return "Property not found", 404

    return render_template(
        "property_details.html",
        property=property
    )


# =========================
# Wishlist - Add Property
# =========================
@app.route("/add-wishlist/<int:property_id>", methods=["POST"])
def add_wishlist(property_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    property = db.session.execute(
        text(
            "SELECT id FROM properties "
            "WHERE id = :property_id"
        ),
        {
            "property_id": property_id
        }
    ).fetchone()

    if not property:
        return "Property not found", 404

    existing = db.session.execute(
        text(
            """
            SELECT id
            FROM wishlist
            WHERE user_id = :user_id
            AND property_id = :property_id
            """
        ),
        {
            "user_id": session["user_id"],
            "property_id": property_id
        }
    ).fetchone()

    if not existing:

        db.session.execute(
            text(
                """
                INSERT INTO wishlist
                (user_id, property_id)
                VALUES
                (:user_id, :property_id)
                """
            ),
            {
                "user_id": session["user_id"],
                "property_id": property_id
            }
        )

        db.session.commit()

    return redirect(url_for("wishlist"))


# =========================
# Wishlist - Remove Property
# =========================
@app.route("/remove-wishlist/<int:property_id>", methods=["POST"])
def remove_wishlist(property_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    db.session.execute(
        text(
            """
            DELETE FROM wishlist
            WHERE user_id = :user_id
            AND property_id = :property_id
            """
        ),
        {
            "user_id": session["user_id"],
            "property_id": property_id
        }
    )

    db.session.commit()

    return redirect(
        url_for(
            "property_details",
            property_id=property_id
        )
    )


# =========================
# My Wishlist
# =========================
@app.route("/wishlist")
def wishlist():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    wishlist_properties = db.session.execute(
        text(
            """
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
            JOIN properties
                ON wishlist.property_id = properties.id
            WHERE wishlist.user_id = :user_id
            ORDER BY wishlist.created_at DESC
            """
        ),
        {
            "user_id": session["user_id"]
        }
    ).fetchall()

    return render_template(
        "wishlist.html",
        wishlist_properties=wishlist_properties
    )


# =========================
# Send Inquiry
# =========================
@app.route("/inquiry/<int:property_id>", methods=["GET", "POST"])
def inquiry(property_id):

    property = db.session.execute(
        text(
            "SELECT * FROM properties "
            "WHERE id = :property_id"
        ),
        {
            "property_id": property_id
        }
    ).fetchone()

    if not property:
        return "Property not found", 404

    if request.method == "POST":

        message = request.form["message"]

        user_id = session.get("user_id")

        if not user_id:
            return "Please login first."

        db.session.execute(
            text(
                """
                INSERT INTO inquiries
                (
                    property_id,
                    user_id,
                    message
                )
                VALUES
                (
                    :property_id,
                    :user_id,
                    :message
                )
                """
            ),
            {
                "property_id": property_id,
                "user_id": user_id,
                "message": message
            }
        )

        db.session.commit()

        return "Inquiry sent successfully!"

    return render_template(
        "inquiry.html",
        property=property
    )


# =========================
# My Inquiries
# =========================
@app.route("/my-inquiries")
def my_inquiries():

    if not session.get("user_id"):
        return "Please login first."

    inquiries = db.session.execute(
        text(
            """
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
            WHERE inquiries.user_id = :user_id
            ORDER BY inquiries.created_at DESC
            """
        ),
        {
            "user_id": session["user_id"]
        }
    ).fetchall()

    return render_template(
        "my_inquiries.html",
        inquiries=inquiries
    )


# =========================
# Owner Inquiries
# =========================
@app.route("/owner-inquiries")
def owner_inquiries():

    if not session.get("user_id"):
        return "Please login first."

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    inquiries = db.session.execute(
        text(
            """
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
            """
        ),
        {
            "owner_id": session["user_id"]
        }
    ).fetchall()

    return render_template(
        "owner_inquiries.html",
        inquiries=inquiries
    )


# =========================
# Update Inquiry Status
# =========================
@app.route("/update-inquiry-status/<int:inquiry_id>", methods=["POST"])
def update_inquiry_status(inquiry_id):

    if not session.get("user_id"):
        return "Please login first."

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    status = request.form["status"]

    if status not in ["pending", "contacted", "closed"]:
        return "Invalid inquiry status.", 400

    db.session.execute(
        text(
            """
            UPDATE inquiries
            JOIN properties
                ON inquiries.property_id = properties.id
            SET inquiries.status = :status
            WHERE inquiries.id = :inquiry_id
            AND properties.owner_id = :owner_id
            """
        ),
        {
            "status": status,
            "inquiry_id": inquiry_id,
            "owner_id": session["user_id"]
        }
    )

    db.session.commit()

    return render_template(
        "status_updated.html",
        status=status
    )


# =========================
# Buy / Rent / Sell Request
# =========================
@app.route(
    "/property-request/<int:property_id>",
    methods=["POST"]
)
def property_request(property_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    request_type = request.form.get("request_type", "buy")

    if request_type not in ["buy", "rent", "sell"]:
        return "Invalid request type", 400

    property = db.session.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                title,
                listing_type,
                status
            FROM properties
            WHERE id = :property_id
            """
        ),
        {
            "property_id": property_id
        }
    ).fetchone()

    if not property:
        return "Property not found", 404

    if property.owner_id == session["user_id"]:
        return "You cannot request your own property", 403

    existing_request = db.session.execute(
        text(
            """
            SELECT id
            FROM property_requests
            WHERE property_id = :property_id
            AND user_id = :user_id
            AND request_type = :request_type
            AND status = 'pending'
            """
        ),
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
            message="You have already submitted a pending request for this property.",
            property=property
        )

    message = request.form.get("message", "").strip()

    if not message:

        if request_type == "sell":
            action = "buy"
        else:
            action = request_type

        message = (
            f"I am interested in this property "
            f"and would like to {action} it."
        )

    db.session.execute(
        text(
            """
            INSERT INTO property_requests
            (
                property_id,
                user_id,
                request_type,
                message
            )
            VALUES
            (
                :property_id,
                :user_id,
                :request_type,
                :message
            )
            """
        ),
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
        message="Your request has been submitted successfully!",
        property=property
    )


# =========================
# My Property Requests
# =========================
@app.route("/my-requests")
def my_requests():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    requests_list = db.session.execute(
        text(
            """
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
            INNER JOIN properties p
                ON pr.property_id = p.id
            WHERE pr.user_id = :user_id
            ORDER BY pr.created_at DESC
            """
        ),
        {
            "user_id": session["user_id"]
        }
    ).fetchall()

    return render_template(
        "my_requests.html",
        requests=requests_list
    )


# =========================
# Owner Property Requests
# =========================
@app.route("/owner-requests")
def owner_requests():

    if not session.get("user_id"):
        return "Please login first."

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    requests_list = db.session.execute(
        text(
            """
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
            INNER JOIN properties p
                ON pr.property_id = p.id
            INNER JOIN users u
                ON pr.user_id = u.id
            WHERE p.owner_id = :owner_id
            ORDER BY pr.created_at DESC
            """
        ),
        {
            "owner_id": session["user_id"]
        }
    ).fetchall()

    return render_template(
        "owner_requests.html",
        requests=requests_list
    )


# =========================
# Update Property Request Status
# =========================
@app.route(
    "/update-property-request-status/<int:request_id>",
    methods=["POST"]
)
def update_property_request_status(request_id):

    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "owner":
        return "Access denied. Owner account required.", 403

    status = request.form.get("status", "").strip()

    if status not in ["approved", "rejected", "completed"]:
        return "Invalid request status.", 400

    property_request = db.session.execute(
        text(
            """
            SELECT
                pr.id,
                pr.status,
                pr.request_type,
                p.id AS property_id,
                p.listing_type,
                p.status AS property_status
            FROM property_requests pr
            INNER JOIN properties p
                ON pr.property_id = p.id
            WHERE pr.id = :request_id
            AND p.owner_id = :owner_id
            """
        ),
        {
            "request_id": request_id,
            "owner_id": session["user_id"]
        }
    ).fetchone()

    if not property_request:
        return "Property request not found or access denied.", 404

    current_status = property_request.status

    if current_status == "pending":

        if status not in ["approved", "rejected"]:
            return "Invalid status transition.", 400

    elif current_status == "approved":

        if status != "completed":
            return "Invalid status transition.", 400

    elif current_status in ["rejected", "completed"]:

        return "This request can no longer be updated.", 400

    db.session.execute(
        text(
            """
            UPDATE property_requests
            SET status = :status
            WHERE id = :request_id
            """
        ),
        {
            "status": status,
            "request_id": request_id
        }
    )

    if status == "completed":

        if property_request.listing_type == "rent":

            db.session.execute(
                text(
                    """
                    UPDATE properties
                    SET status = 'rented'
                    WHERE id = :property_id
                    """
                ),
                {
                    "property_id": property_request.property_id
                }
            )

        elif property_request.listing_type in ["sell", "buy"]:

            db.session.execute(
                text(
                    """
                    UPDATE properties
                    SET status = 'sold'
                    WHERE id = :property_id
                    """
                ),
                {
                    "property_id": property_request.property_id
                }
            )

    db.session.commit()

    return redirect(url_for("owner_requests"))


# =========================
# Admin Dashboard
# =========================
@app.route("/admin-dashboard")
def admin_dashboard():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    total_users = db.session.execute(
        text(
            "SELECT COUNT(*) FROM users"
        )
    ).scalar()

    total_properties = db.session.execute(
        text(
            "SELECT COUNT(*) FROM properties"
        )
    ).scalar()

    total_inquiries = db.session.execute(
        text(
            "SELECT COUNT(*) FROM inquiries"
        )
    ).scalar()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_properties=total_properties,
        total_inquiries=total_inquiries
    )


# =========================
# Admin Users
# =========================
@app.route("/admin-users")
def admin_users():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    users = db.session.execute(
        text(
            """
            SELECT
                id,
                name,
                email,
                role,
                created_at
            FROM users
            ORDER BY created_at DESC
            """
        )
    ).fetchall()

    return render_template(
        "admin_users.html",
        users=users
    )


# =========================
# Admin Properties
# =========================
@app.route("/admin-properties")
def admin_properties():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        return "Access denied. Admin account required.", 403

    properties = db.session.execute(
        text(
            """
            SELECT
                properties.id,
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
            JOIN users
                ON properties.owner_id = users.id
            ORDER BY properties.created_at DESC
            """
        )
    ).fetchall()

    return render_template(
        "admin_properties.html",
        properties=properties
    )


# =========================
# Admin Property Approval Routes
# =========================
@app.route("/admin/property/<int:id>/approve", methods=["POST"])
def approve_property(id):
    if not session.get("user_id") or session.get("user_role") != "admin":
        return redirect(url_for("login"))
    
    property = db.session.execute(text("SELECT * FROM properties WHERE id = :id"), {"id": id}).fetchone()
    if not property:
        return "Property not found", 404

    db.session.execute(
        text("UPDATE properties SET status = 'approved' WHERE id = :id"),
        {"id": id}
    )
    db.session.commit()
    return redirect(url_for("admin_properties"))


@app.route("/admin/property/<int:id>/reject", methods=["POST"])
def reject_property(id):
    if not session.get("user_id") or session.get("user_role") != "admin":
        return redirect(url_for("login"))
    
    property = db.session.execute(text("SELECT * FROM properties WHERE id = :id"), {"id": id}).fetchone()
    if not property:
        return "Property not found", 404

    db.session.execute(
        text("UPDATE properties SET status = 'rejected' WHERE id = :id"),
        {"id": id}
    )
    db.session.commit()
    return redirect(url_for("admin_properties"))


if __name__ == "__main__":
    app.run(debug=True)