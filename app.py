"""
Chat Server with:
- DB schema referencing the ER diagram
- Registration & Login
- Pre-created admin user (username="admin", password="admin123")
- Admin changes user roles
- Block / Unblock
- Chat rooms: create + join
- Public, private messages
- Basic moderation (demo)
- Chat history + Clear chat (public or room)
"""

import eventlet
eventlet.monkey_patch()

from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import generate_password_hash, check_password_hash

from models import (
    SessionLocal, Utilizatori, Mesaje, CamereDeChat, UserChatRoom
)

app = Flask(__name__, static_folder="client", static_url_path="")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

sid_to_info = {}     # sid -> {"id_utilizator", "username", "role", "blocked"}
username_to_sid = {} # username -> sid

###########################################################
#                  HTTP ROUTES (Register)                 #
###########################################################
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/register", methods=["POST"])
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

###########################################################
#            SOCKET.IO EVENTS (Real-Time Chat)            #
###########################################################
@socketio.on("connect")
def handle_connect():
    print(f"[connect] SID={request.sid}")
    emit("server_message", {"text": "Connected. Please login or register."}, to=request.sid)

@socketio.on("disconnect")
def handle_disconnect():
    info = sid_to_info.pop(request.sid, None)
    if info:
        username = info["username"]
        username_to_sid.pop(username, None)
        print(f"[disconnect] {username} (SID={request.sid}) left chat.")
        emit("user_notification", {"text": f"{username} disconnected."}, broadcast=True)
    else:
        print(f"[disconnect] SID={request.sid} left (no info).")

@socketio.on("authenticate")
def handle_authenticate(data):
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    session = SessionLocal()
    user = session.query(Utilizatori).filter_by(nume_utilizator=username).first()
    if not user:
        emit("server_message", {"text": "User not found. Please register."}, to=request.sid)
        session.close()
        socketio.sleep(0.1)
        disconnect(request.sid)
        return

    if not check_password_hash(user.parola, password):
        emit("server_message", {"text": "Wrong password."}, to=request.sid)
        session.close()
        socketio.sleep(0.1)
        disconnect(request.sid)
        return

    if user.blocked:
        emit("server_message", {"text": f"You are blocked, {username}!"}, to=request.sid)
        session.close()
        socketio.sleep(0.1)
        disconnect(request.sid)
        return

    role = user.rol
    sid_to_info[request.sid] = {
        "id_utilizator": user.id_utilizator,
        "username": user.nume_utilizator,
        "role": role,
        "blocked": user.blocked
    }
    username_to_sid[user.nume_utilizator] = request.sid
    session.close()

    # Now emit a dedicated "login_success" to let the client know the user's role
    emit("login_success", {"username": user.nume_utilizator, "role": role}, to=request.sid)
    emit("server_message", {"text": f"Welcome, {username}! Role={role}."}, to=request.sid)
    emit("user_notification", {"text": f"{username} has connected."}, broadcast=True)
    print(f"[authenticate] {username}, role={role}, sid={request.sid}")

#
# Change Role (Admin only)
#
@socketio.on("change_role")
def handle_change_role(data):
    """
    data = { "target": "...", "new_role": "admin" or "user" }
    """
    admin_info = sid_to_info.get(request.sid, {})
    if admin_info.get("role") != "admin":
        emit("server_message", {"text": "Admin privileges required."}, to=request.sid)
        return

    target_name = data.get("target", "").strip()
    new_role = data.get("new_role", "").strip()
    if not target_name or new_role not in ("admin", "user"):
        emit("server_message", {"text": "Invalid role or target username."}, to=request.sid)
        return

    session = SessionLocal()
    user = session.query(Utilizatori).filter_by(nume_utilizator=target_name).first()
    if not user:
        emit("server_message", {"text": f"User '{target_name}' not found in DB."}, to=request.sid)
        session.close()
        return

    user.rol = new_role
    session.commit()
    session.close()

    # If they're online, update in-memory
    if target_name in username_to_sid:
        targ_sid = username_to_sid[target_name]
        if targ_sid in sid_to_info:
            sid_to_info[targ_sid]["role"] = new_role

    emit("server_message", {"text": f"{target_name}'s role changed to {new_role}."}, to=request.sid)
    print(f"[change_role] Admin {admin_info.get('username')} changed {target_name}'s role to {new_role}.")

#
# Block / Unblock
#
@socketio.on("block_user")
def handle_block_user(data):
    """
    data = {"target": "...", "action": "block" or "unblock"}
    """
    admin_info = sid_to_info.get(request.sid, {})
    if admin_info.get("role") != "admin":
        emit("server_message", {"text": "Admin privileges required."}, to=request.sid)
        return

    target = data.get("target", "").strip()
    action = data.get("action", "").strip()  # "block" or "unblock"
    if not target or action not in ("block", "unblock"):
        emit("server_message", {"text": "No target user or invalid action."}, to=request.sid)
        return

    session = SessionLocal()
    user = session.query(Utilizatori).filter_by(nume_utilizator=target).first()
    if not user:
        emit("server_message", {"text": f"User '{target}' not found."}, to=request.sid)
        session.close()
        return

    if action == "block":
        user.blocked = True
        msg_txt = f"User '{target}' has been blocked."
    else:
        user.blocked = False
        msg_txt = f"User '{target}' has been unblocked."

    session.commit()

    # if user is online and newly blocked, disconnect
    if action == "block" and target in username_to_sid:
        targ_sid = username_to_sid[target]
        emit("server_message", {"text": "You have been blocked by an admin."}, to=targ_sid)
        socketio.sleep(0.1)
        disconnect(targ_sid)

    session.close()

    emit("server_message", {"text": msg_txt}, to=request.sid)
    print(f"[block_user] Admin {admin_info.get('username')} performed {action} on {target}.")

#
# Public Message (store in DB)
#
@socketio.on("public_message")
def handle_public_message(data):
    text = data.get("text", "").strip()
    info = sid_to_info.get(request.sid, {})
    username = info.get("username", "???")
    user_id = info.get("id_utilizator", None)

    if not text:
        return

    session = SessionLocal()
    msg = Mesaje(
        id_utilizator=user_id,
        text_mesaj=text,
        tip_mesaj="public",
        timestamp=datetime.utcnow()
    )
    session.add(msg)
    session.commit()
    session.close()

    print(f"[public_message] {username}: {text}")
    emit("public_message", {"username": username, "text": text}, broadcast=True)

#
# Create Room
#
@socketio.on("create_room")
def handle_create_room(data):
    room_name = data.get("room", "").strip()
    if not room_name:
        return

    info = sid_to_info.get(request.sid, {})
    user_id = info.get("id_utilizator")

    session = SessionLocal()
    existing = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
    if existing:
        emit("server_message", {"text": f"Room '{room_name}' already exists."}, to=request.sid)
        session.close()
        return

    new_room = CamereDeChat(
        nume_camera=room_name,
        descriere="",
        data_creare=datetime.utcnow(),
        creator_id=user_id
    )
    session.add(new_room)
    session.commit()
    session.close()

    print(f"[create_room] {info.get('username')} created room={room_name}")
    emit("room_created", {"room": room_name}, to=request.sid)

#
# Join Room
#
@socketio.on("join_room")
def handle_join_room(data):
    room_name = data.get("room", "").strip()
    info = sid_to_info.get(request.sid, {})
    user_id = info.get("id_utilizator", None)
    username = info.get("username", "???")

    if not room_name or not user_id:
        return

    session = SessionLocal()
    room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
    if not room_db:
        emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=request.sid)
        session.close()
        return

    membership = session.query(UserChatRoom).filter_by(id_utilizator=user_id, id_camera=room_db.id_camera).first()
    if not membership:
        membership = UserChatRoom(
            id_utilizator=user_id,
            id_camera=room_db.id_camera
        )
        session.add(membership)
        session.commit()

    session.close()

    join_room(room_name)
    print(f"[join_room] {username} joined room={room_name}")

    emit("joined_room", {"room": room_name, "text": f"You joined room '{room_name}'."}, to=request.sid)
    emit("server_message", {"text": f"{username} joined '{room_name}'."}, room=room_name)

#
# Room Message
#
@socketio.on("room_message")
def handle_room_message(data):
    room_name = data.get("room", "").strip()
    text = data.get("text", "").strip()
    info = sid_to_info.get(request.sid, {})
    username = info.get("username", "???")
    user_id = info.get("id_utilizator", None)

    if not room_name or not text or not user_id:
        return

    session = SessionLocal()
    room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
    if not room_db:
        emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=request.sid)
        session.close()
        return

    msg = Mesaje(
        id_utilizator=user_id,
        id_camera=room_db.id_camera,
        text_mesaj=text,
        tip_mesaj="room",
        timestamp=datetime.utcnow()
    )
    session.add(msg)
    session.commit()
    session.close()

    print(f"[room_message] {username} (@{room_name}): {text}")
    emit("room_message", {"username": username, "text": text}, room=room_name)

#
# Private Message
#
@socketio.on("private_message")
def handle_private_message(data):
    to_user = data.get("to", "").strip()
    text = data.get("text", "").strip()
    from_info = sid_to_info.get(request.sid, {})
    from_username = from_info.get("username", "???")
    from_user_id = from_info.get("id_utilizator", None)

    if not to_user or not text or not from_user_id:
        return

    # check if dest is online
    if to_user not in username_to_sid:
        emit("server_message", {"text": f"User '{to_user}' not online."}, to=request.sid)
        return

    # store message (tip_mesaj=private) if you want to preserve it
    session = SessionLocal()
    from_user_db = session.query(Utilizatori).filter_by(id_utilizator=from_user_id).first()
    dest_user_db = session.query(Utilizatori).filter_by(nume_utilizator=to_user).first()
    if not dest_user_db:
        emit("server_message", {"text": f"User '{to_user}' not found."}, to=request.sid)
        session.close()
        return

    msg = Mesaje(
        id_utilizator=from_user_db.id_utilizator,
        text_mesaj=text,
        tip_mesaj="private",
        timestamp=datetime.utcnow()
    )
    session.add(msg)
    session.commit()
    session.close()

    print(f"[private_message] {from_username} -> {to_user}: {text}")
    dest_sid = username_to_sid[to_user]
    emit("private_message", {"from": from_username, "text": text}, to=dest_sid)
    emit("private_message", {"from": from_username, "text": f"(to {to_user}): {text}"}, to=request.sid)

#
# Get Chat History
#
@socketio.on("get_history")
def handle_get_history(data):
    """
    data = {
      "type": "public" or "room",
      "room": "...",  # used if type=="room"
    }
    We'll fetch last X messages from DB or all.
    """
    chat_type = data.get("type", "")
    room_name = data.get("room", "")
    # e.g. "public" => tip_mesaj="public"
    # e.g. "room" => tip_mesaj="room" with that id_camera

    session = SessionLocal()

    if chat_type == "public":
        # get all messages where tip_mesaj="public"
        msgs = session.query(Mesaje).filter_by(tip_mesaj="public").order_by(Mesaje.id_mesaj.asc()).all()
        history = []
        for m in msgs:
            user = session.query(Utilizatori).filter_by(id_utilizator=m.id_utilizator).first()
            username = user.nume_utilizator if user else "???"
            history.append({
                "username": username,
                "text": m.text_mesaj
            })
        emit("history_response", {"type": "public", "messages": history}, to=request.sid)

    elif chat_type == "room" and room_name:
        # find room id
        room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
        if not room_db:
            emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=request.sid)
            session.close()
            return

        msgs = session.query(Mesaje).filter_by(tip_mesaj="room", id_camera=room_db.id_camera).order_by(Mesaje.id_mesaj.asc()).all()
        history = []
        for m in msgs:
            user = session.query(Utilizatori).filter_by(id_utilizator=m.id_utilizator).first()
            username = user.nume_utilizator if user else "???"
            history.append({
                "username": username,
                "text": m.text_mesaj
            })
        emit("history_response", {"type": "room", "room": room_name, "messages": history}, to=request.sid)
    else:
        emit("server_message", {"text": "Invalid history request."}, to=request.sid)

    session.close()

#
# Clear Chat
#
@socketio.on("clear_chat")
def handle_clear_chat(data):
    """
    data = {
      "type": "public" or "room",
      "room": "...",
    }
    Admin only in this demo
    """
    admin_info = sid_to_info.get(request.sid, {})
    if admin_info.get("role") != "admin":
        emit("server_message", {"text": "Admin privileges required to clear chat."}, to=request.sid)
        return

    chat_type = data.get("type", "")
    room_name = data.get("room", "")

    session = SessionLocal()
    if chat_type == "public":
        # delete all public messages
        session.query(Mesaje).filter_by(tip_mesaj="public").delete()
        session.commit()
        emit("server_message", {"text": "Public chat cleared by Admin."}, broadcast=True)
        print("[clear_chat] Admin cleared public chat.")

    elif chat_type == "room" and room_name:
        # find room
        room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
        if not room_db:
            emit("server_message", {"text": f"Room '{room_name}' not found."}, to=request.sid)
            session.close()
            return
        # delete all room messages
        session.query(Mesaje).filter_by(tip_mesaj="room", id_camera=room_db.id_camera).delete()
        session.commit()
        emit("server_message", {"text": f"Chat for room '{room_name}' cleared by Admin."}, room=room_name)
        print(f"[clear_chat] Admin cleared room '{room_name}' chat.")
    else:
        emit("server_message", {"text": "Invalid clear_chat request."}, to=request.sid)

    session.close()

#
# Basic Moderation (demo)
#
@socketio.on("moderate_message")
def handle_moderate_message(data):
    admin_info = sid_to_info.get(request.sid, {})
    if admin_info.get("role") != "admin":
        emit("server_message", {"text": "Admin privileges required."}, to=request.sid)
        return

    room = data.get("room", "")
    action = data.get("action", "")

    if room:
        emit("server_message", {
            "text": f"(ADMIN) A message was moderated with '{action}' in room '{room}'."
        }, room=room)
    else:
        emit("server_message", {
            "text": f"(ADMIN) A message was moderated with '{action}' globally."
        }, broadcast=True)

    print(f"[moderate_message] Admin {admin_info.get('username')} action='{action}'.")

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    """
    Demo endpoint for "forgot password" – user provides username + newPassword
    In production, you'd typically email them a reset link or verification code,
    but here we do it directly for demonstration.
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
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)