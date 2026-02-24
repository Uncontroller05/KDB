from flask import Flask, request, jsonify, session
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change-this-secret")

CORS(app, supports_credentials=True)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "KD"),
    "password": os.getenv("DB_PASSWORD", "KD241305"),
    "database": os.getenv("DB_NAME", "kapda_dekho"),
}


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


def user_to_dict(row):
    return {"id": row[0], "name": row[1], "email": row[2]}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    db.close()

    if not row:
        session.pop("user_id", None)
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify({"user": user_to_dict(row)})


@app.post("/api/signup")
def signup():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        cur.close()
        db.close()
        return jsonify({"error": "Email already registered"}), 409

    cur.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
        (name, email, pw_hash.decode("utf-8")),
    )
    db.commit()

    user_id = cur.lastrowid
    cur.close()
    db.close()

    session["user_id"] = user_id
    return jsonify({"user": {"id": user_id, "name": name, "email": email}})


@app.post("/api/login")
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name, email, password_hash FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    cur.close()
    db.close()

    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    user_id, name, email, password_hash = row
    if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user_id
    return jsonify({"user": {"id": user_id, "name": name, "email": email}})


@app.post("/api/logout")
def logout():
    session.pop("user_id", None)
    return jsonify({"ok": True})


@app.get("/api/orders")
def list_orders():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, status, created_at FROM orders WHERE user_id = %s ORDER BY created_at DESC",
        (user_id,),
    )
    orders = cur.fetchall()

    result = []
    for order_id, status, created_at in orders:
        cur.execute(
            "SELECT product_name, price, qty, image_url FROM order_items WHERE order_id = %s",
            (order_id,),
        )
        items = [
            {
                "name": r[0],
                "price": r[1],
                "qty": r[2],
                "img": r[3],
            }
            for r in cur.fetchall()
        ]
        result.append(
            {
                "id": order_id,
                "status": status,
                "created_at": created_at.isoformat(),
                "items": items,
            }
        )

    cur.close()
    db.close()
    return jsonify({"orders": result})


@app.post("/api/orders")
def create_order():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json() or {}
    items = data.get("items") or []
    if not items:
        return jsonify({"error": "No items to order"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO orders (user_id, status) VALUES (%s, %s)",
        (user_id, "Placed"),
    )
    order_id = cur.lastrowid

    for item in items:
        name = (item.get("name") or "").strip()
        price = (item.get("price") or "").strip()
        qty = int(item.get("qty") or 1)
        img = item.get("img")
        if not name or not price:
            continue
        cur.execute(
            "INSERT INTO order_items (order_id, product_name, price, qty, image_url) VALUES (%s, %s, %s, %s, %s)",
            (order_id, name, price, qty, img),
        )

    db.commit()
    cur.close()
    db.close()

    return jsonify({"order_id": order_id})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
