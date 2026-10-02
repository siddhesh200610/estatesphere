from app import app, db
from sqlalchemy import text

with app.app_context():
    print("Connecting to Aiven database and creating tables...")

    # 1. Users Table
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'buyer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """))

    # 2. Properties Table
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS properties (
            id INT AUTO_INCREMENT PRIMARY KEY,
            owner_id INT NOT NULL,
            title VARCHAR(200) NOT NULL,
            property_type VARCHAR(50) NOT NULL,
            listing_type VARCHAR(50) NOT NULL,
            price DECIMAL(12, 2) NOT NULL,
            area DECIMAL(10, 2) NOT NULL,
            location VARCHAR(255) NOT NULL,
            description TEXT,
            image VARCHAR(500),
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))

    # 3. Wishlist Table
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS wishlist (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            property_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE
        );
    """))

    # 4. Inquiries Table
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS inquiries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            property_id INT NOT NULL,
            user_id INT NOT NULL,
            message TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))

    # 5. Property Requests Table
    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS property_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            property_id INT NOT NULL,
            user_id INT NOT NULL,
            request_type VARCHAR(50) NOT NULL,
            message TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))

    db.session.commit()
    print("All tables created successfully in Aiven database!")