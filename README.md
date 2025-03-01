# RealTimeChat
A real-time chat application with client-server architecture, built with Flask, Socket.IO, and SQLite.

## Features

### User Features
- **Registration & Authentication**: Register an account and login to access chat features
- **Password Recovery**: Reset password if forgotten
- **Public Messaging**: Send messages to all connected users
- **Private Messaging**: Send confidential messages to specific users
- **Chat Rooms**: Create and join themed chat rooms
- **Notifications**: Receive notifications when users connect/disconnect
- **Message History**: View chat history for public and room messages

### Admin Features
- **User Management**: Change user roles (admin/user)
- **Moderation**: Block/unblock users who violate rules
- **Content Control**: Delete inappropriate messages
- **Clear Chat History**: Remove message history from public chat or specific rooms

## Technologies

- **Backend**:
  - Python 3.10+
  - Flask web framework
  - Flask-SocketIO for real-time communication
  - SQLAlchemy ORM
  - SQLite database

- **Frontend**:
  - HTML5/CSS3
  - JavaScript
  - Socket.IO client library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/RealTimeChat.git
cd RealTimeChat
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

5. Access the application at http://localhost:5001

## Project Structure

- `app.py`: Main Flask application with Socket.IO event handlers
- `auth_service.py`: Authentication-related HTTP routes
- `chat_events.py`: Socket.IO event handlers for chat functionality
- `database.py`: Database connection setup
- `models.py`: SQLAlchemy ORM models
- `client/`: Frontend static files
  - `index.html`: Main client interface

## Database Schema

The application uses the following database tables:

- **Utilizatori (Users)**: Stores user information
  - id_utilizator (PK)
  - nume_utilizator (username)
  - parola (password hash)
  - rol (role - admin/user)
  - data_inregistrare (registration date)
  - blocked (blocking status)

- **Mesaje (Messages)**: Stores all messages
  - id_mesaj (PK)
  - id_utilizator (FK)
  - id_camera (FK, optional)
  - text_mesaj (message content)
  - tip_mesaj (message type - public/private/room)
  - timestamp

- **CamereDeChat (Chat Rooms)**: Stores chat rooms
  - id_camera (PK)
  - nume_camera (room name)
  - descriere (description)
  - data_creare (creation date)
  - creator_id (FK)

- **UserChatRoom**: Many-to-many relationship between users and rooms
  - id_utilizator (PK, FK)
  - id_camera (PK, FK)
  - data_inregistrare (joining date)

- **Notificari (Notifications)**: Stores system notifications
  - id_notificare (PK)
  - id_utilizator (FK)
  - tip_notificare (notification type)
  - timestamp

## Socket.IO Events

### Client → Server
- `connect`: Initial connection to the server
- `authenticate`: User login with credentials
- `public_message`: Send a message to all users
- `private_message`: Send a message to a specific user
- `create_room`: Create a new chat room
- `join_room`: Join an existing chat room
- `room_message`: Send a message to a room
- `get_history`: Request chat history
- `clear_chat`: Clear chat history (admin only)
- `change_role`: Change a user's role (admin only)
- `block_user`: Block/unblock a user (admin only)
- `moderate_message`: Moderate messages (admin only)

### Server → Client
- `server_message`: System messages
- `user_notification`: User connection notifications
- `login_success`: Successful authentication
- `public_message`: Broadcast message to all users
- `private_message`: Private message to specific user
- `room_created`: Notification of room creation
- `joined_room`: Confirmation of joining a room
- `room_message`: Message in a room
- `history_response`: Response with chat history

## Default Admin Account
Username: admin  
Password: admin123

## License
This project is available under the MIT License.
