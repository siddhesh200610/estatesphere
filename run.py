import os
import mysql.connector
import urllib.parse as up
from dotenv import load_dotenv

load_dotenv()
u = up.urlparse(os.getenv("DATABASE_URL"))

conn = mysql.connector.connect(
    host=u.hostname,
    user=u.username,
    password=u.password,
    database=u.path[1:],
    port=u.port
)
c = conn.cursor()

c.execute("SELECT id FROM users WHERE email = 'admin@estatesphere.com'")
res = c.fetchone()
aid = res[0] if res else None

if aid:
    ps = [
        ("Palm Grove Villa", "A stunning luxury villa surrounded by palm trees and private pool.", 14500000, "Goa", "villa"),
        ("Skyline Heights Apartment", "Spacious 3 BHK apartment with breathtaking city skyline views.", 6500000, "Mumbai", "apartment"),
        ("Blue Sapphire House", "Independent duplex house with a lush green lawn and parking.", 8900000, "Bengaluru", "house"),
        ("Golden Avenue Plot", "Prime residential corner plot ready for immediate construction.", 4200000, "Pune", "plot"),
        ("Titanium Business Hub", "Premium commercial showroom space located on the main highway.", 25000000, "Ahmedabad", "commercial"),
        ("Serenity Woods Villa", "Peaceful eco-friendly gated community villa with modern architecture.", 9500000, "Hyderabad", "villa"),
        ("Sunshine Luxury House", "Traditional yet modern independent house with vintage finish.", 11500000, "Jaipur", "house"),
        ("Urban Nest Studio", "Fully furnished compact studio apartment ideal for tech professionals.", 3100000, "Bengaluru", "apartment"),
        ("Metro Logistics Warehouse", "Large industrial commercial warehouse space with loading docks.", 18000000, "Chennai", "commercial"),
        ("Pine Valley Land Parcel", "Scenic mountain-view land parcel ideal for a holiday retreat.", 5500000, "Shimla", "plot")
    ]
    
    query = "INSERT INTO properties (title, description, price, location, property_type, user_id) VALUES (%s, %s, %s, %s, %s, %s)"
    vals = [(p[0], p[1], p[2], p[3], p[4], aid) for p in ps]
    
    c.executemany(query, vals)
    conn.commit()
    print("SUCCESS! 10 properties add ho gayi hain.")
else:
    print("Error: Admin user nahi mila!")

c.close()
conn.close()
