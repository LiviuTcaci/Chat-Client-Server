# auth_service.py
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from database import SessionLocal
from models import Utilizatori
from datetime import datetime

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username & password required"}), 400

    session = SessionLocal()
    existing = session.query(Utilizatori).filter_by(nume_utilizator=username).first()
    if existing:
        session.close()
        return jsonify({"error": "Username already taken"}), 400

    new_user = Utilizatori(
        nume_utilizator=username,
        parola=generate_password_hash(password),
        rol="user",
        data_inregistrare=datetime.utcnow(),
        blocked=False
    )
    session.add(new_user)
    session.commit()
    session.close()

    return jsonify({"message": "Registration successful!"}), 200

@auth_bp.route("/forgot_password", methods=["POST"])
def forgot_password():
    """
    Demo endpoint for "forgot password".
    In production, you'd do email-based reset, token, etc.
    """
    data = request.json or request.form
    username = data.get("username", "").strip()
    new_password = data.get("new_password", "").strip()

    if not username or not new_password:
        return jsonify({"error": "Username and new_password are required"}), 400

    session = SessionLocal()
    user = session.query(Utilizatori).filter_by(nume_utilizator=username).first()
    if not user:
        session.close()
        return jsonify({"error": "User not found"}), 404

    # Set the new hashed password
    user.parola = generate_password_hash(new_password)
    session.commit()
    session.close()

    return jsonify({"message": f"Password for {username} has been reset!"}), 200