# chat_events.py
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, disconnect
from werkzeug.security import check_password_hash
from database import SessionLocal
from models import Utilizatori, Mesaje, CamereDeChat, UserChatRoom

sid_to_info = {}     # sid -> {"id_utilizator", "username", "role", "blocked"}
username_to_sid = {} # username -> sid

def register_chat_events(socketio: SocketIO, app):

    @socketio.on("connect")
    def handle_connect():
        print(f"[connect] SID={app.request.sid}")
        emit("server_message", {"text": "Connected. Please login or register."}, to=app.request.sid)

    @socketio.on("disconnect")
    def handle_disconnect():
        info = sid_to_info.pop(app.request.sid, None)
        if info:
            username = info["username"]
            username_to_sid.pop(username, None)
            print(f"[disconnect] {username} (SID={app.request.sid}) left chat.")
            emit("user_notification", {"text": f"{username} disconnected."}, broadcast=True)
        else:
            print(f"[disconnect] SID={app.request.sid} left (no info).")

    @socketio.on("authenticate")
    def handle_authenticate(data):
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        session = SessionLocal()
        user = session.query(Utilizatori).filter_by(nume_utilizator=username).first()
        if not user:
            emit("server_message", {"text": "User not found. Please register."}, to=app.request.sid)
            session.close()
            socketio.sleep(0.1)
            disconnect(app.request.sid)
            return

        if not check_password_hash(user.parola, password):
            emit("server_message", {"text": "Wrong password."}, to=app.request.sid)
            session.close()
            socketio.sleep(0.1)
            disconnect(app.request.sid)
            return

        if user.blocked:
            emit("server_message", {"text": f"You are blocked, {username}!"}, to=app.request.sid)
            session.close()
            socketio.sleep(0.1)
            disconnect(app.request.sid)
            return

        role = user.rol
        sid_to_info[app.request.sid] = {
            "id_utilizator": user.id_utilizator,
            "username": user.nume_utilizator,
            "role": role,
            "blocked": user.blocked
        }
        username_to_sid[user.nume_utilizator] = app.request.sid
        session.close()

        # Now emit a dedicated "login_success" to let the client know the user's role
        emit("login_success", {"username": user.nume_utilizator, "role": role}, to=app.request.sid)
        emit("server_message", {"text": f"Welcome, {username}! Role={role}."}, to=app.request.sid)
        emit("user_notification", {"text": f"{username} has connected."}, broadcast=True)
        print(f"[authenticate] {username}, role={role}, sid={app.request.sid}")

    @socketio.on("change_role")
    def handle_change_role(data):
        admin_info = sid_to_info.get(app.request.sid, {})
        if admin_info.get("role") != "admin":
            emit("server_message", {"text": "Admin privileges required."}, to=app.request.sid)
            return

        target_name = data.get("target", "").strip()
        new_role = data.get("new_role", "").strip()
        if not target_name or new_role not in ("admin", "user"):
            emit("server_message", {"text": "Invalid role or target username."}, to=app.request.sid)
            return

        session = SessionLocal()
        user = session.query(Utilizatori).filter_by(nume_utilizator=target_name).first()
        if not user:
            emit("server_message", {"text": f"User '{target_name}' not found in DB."}, to=app.request.sid)
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

        emit("server_message", {"text": f"{target_name}'s role changed to {new_role}."}, to=app.request.sid)
        print(f"[change_role] Admin {admin_info.get('username')} changed {target_name}'s role to {new_role}.")

    @socketio.on("block_user")
    def handle_block_user(data):
        admin_info = sid_to_info.get(app.request.sid, {})
        if admin_info.get("role") != "admin":
            emit("server_message", {"text": "Admin privileges required."}, to=app.request.sid)
            return

        target = data.get("target", "").strip()
        action = data.get("action", "").strip()  # "block" or "unblock"
        if not target or action not in ("block", "unblock"):
            emit("server_message", {"text": "No target user or invalid action."}, to=app.request.sid)
            return

        session = SessionLocal()
        user = session.query(Utilizatori).filter_by(nume_utilizator=target).first()
        if not user:
            emit("server_message", {"text": f"User '{target}' not found."}, to=app.request.sid)
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

        emit("server_message", {"text": msg_txt}, to=app.request.sid)
        print(f"[block_user] Admin {admin_info.get('username')} performed {action} on {target}.")

    @socketio.on("public_message")
    def handle_public_message(data):
        text = data.get("text", "").strip()
        info = sid_to_info.get(app.request.sid, {})
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

    @socketio.on("create_room")
    def handle_create_room(data):
        room_name = data.get("room", "").strip()
        if not room_name:
            return

        info = sid_to_info.get(app.request.sid, {})
        user_id = info.get("id_utilizator")

        session = SessionLocal()
        existing = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
        if existing:
            emit("server_message", {"text": f"Room '{room_name}' already exists."}, to=app.request.sid)
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
        emit("room_created", {"room": room_name}, to=app.request.sid)

    @socketio.on("join_room")
    def handle_join_room(data):
        room_name = data.get("room", "").strip()
        info = sid_to_info.get(app.request.sid, {})
        user_id = info.get("id_utilizator", None)
        username = info.get("username", "???")

        if not room_name or not user_id:
            return

        session = SessionLocal()
        room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
        if not room_db:
            emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=app.request.sid)
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

        emit("joined_room", {"room": room_name, "text": f"You joined room '{room_name}'."}, to=app.request.sid)
        emit("server_message", {"text": f"{username} joined '{room_name}'."}, room=room_name)

    @socketio.on("room_message")
    def handle_room_message(data):
        room_name = data.get("room", "").strip()
        text = data.get("text", "").strip()
        info = sid_to_info.get(app.request.sid, {})
        username = info.get("username", "???")
        user_id = info.get("id_utilizator", None)

        if not room_name or not text or not user_id:
            return

        session = SessionLocal()
        room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
        if not room_db:
            emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=app.request.sid)
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

    @socketio.on("private_message")
    def handle_private_message(data):
        to_user = data.get("to", "").strip()
        text = data.get("text", "").strip()
        from_info = sid_to_info.get(app.request.sid, {})
        from_username = from_info.get("username", "???")
        from_user_id = from_info.get("id_utilizator", None)

        if not to_user or not text or not from_user_id:
            return

        # check if dest is online
        if to_user not in username_to_sid:
            emit("server_message", {"text": f"User '{to_user}' not online."}, to=app.request.sid)
            return

        session = SessionLocal()
        from_user_db = session.query(Utilizatori).filter_by(id_utilizator=from_user_id).first()
        dest_user_db = session.query(Utilizatori).filter_by(nume_utilizator=to_user).first()
        if not dest_user_db:
            emit("server_message", {"text": f"User '{to_user}' not found."}, to=app.request.sid)
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
        emit("private_message", {"from": from_username, "text": f"(to {to_user}): {text}"}, to=app.request.sid)

    @socketio.on("get_history")
    def handle_get_history(data):
        chat_type = data.get("type", "")
        room_name = data.get("room", "")
        session = SessionLocal()

        if chat_type == "public":
            msgs = session.query(Mesaje).filter_by(tip_mesaj="public").order_by(Mesaje.id_mesaj.asc()).all()
            history = []
            for m in msgs:
                user = session.query(Utilizatori).filter_by(id_utilizator=m.id_utilizator).first()
                username = user.nume_utilizator if user else "???"
                history.append({"username": username, "text": m.text_mesaj})
            emit("history_response", {"type": "public", "messages": history}, to=app.request.sid)

        elif chat_type == "room" and room_name:
            room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
            if not room_db:
                emit("server_message", {"text": f"Room '{room_name}' doesn't exist."}, to=app.request.sid)
                session.close()
                return

            msgs = session.query(Mesaje).filter_by(tip_mesaj="room", id_camera=room_db.id_camera).order_by(Mesaje.id_mesaj.asc()).all()
            history = []
            for m in msgs:
                user = session.query(Utilizatori).filter_by(id_utilizator=m.id_utilizator).first()
                username = user.nume_utilizator if user else "???"
                history.append({"username": username, "text": m.text_mesaj})
            emit("history_response", {"type": "room", "room": room_name, "messages": history}, to=app.request.sid)
        else:
            emit("server_message", {"text": "Invalid history request."}, to=app.request.sid)

        session.close()

    @socketio.on("clear_chat")
    def handle_clear_chat(data):
        admin_info = sid_to_info.get(app.request.sid, {})
        if admin_info.get("role") != "admin":
            emit("server_message", {"text": "Admin privileges required to clear chat."}, to=app.request.sid)
            return

        chat_type = data.get("type", "")
        room_name = data.get("room", "")

        session = SessionLocal()
        if chat_type == "public":
            session.query(Mesaje).filter_by(tip_mesaj="public").delete()
            session.commit()
            emit("server_message", {"text": "Public chat cleared by Admin."}, broadcast=True)
            print("[clear_chat] Admin cleared public chat.")
        elif chat_type == "room" and room_name:
            room_db = session.query(CamereDeChat).filter_by(nume_camera=room_name).first()
            if not room_db:
                emit("server_message", {"text": f"Room '{room_name}' not found."}, to=app.request.sid)
                session.close()
                return
            session.query(Mesaje).filter_by(tip_mesaj="room", id_camera=room_db.id_camera).delete()
            session.commit()
            emit("server_message", {"text": f"Chat for room '{room_name}' cleared by Admin."}, room=room_name)
            print(f"[clear_chat] Admin cleared room '{room_name}' chat.")
        else:
            emit("server_message", {"text": "Invalid clear_chat request."}, to=app.request.sid)

        session.close()

    @socketio.on("moderate_message")
    def handle_moderate_message(data):
        admin_info = sid_to_info.get(app.request.sid, {})
        if admin_info.get("role") != "admin":
            emit("server_message", {"text": "Admin privileges required."}, to=app.request.sid)
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