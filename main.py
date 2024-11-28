from flask import Flask, jsonify, request, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_mysqldb import MySQL
import logging
import os

# Initialize Flask App
app = Flask(__name__)

# Configurations from environment variables for security
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'muskan@321')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'rbac_system')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt_secret_key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 900  # Access token expires in 15 minutes

# Extensions
mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

def role_required(allowed_roles):
    def decorator(func):
        @jwt_required()
        def _check_user_role(*args, **kwargs):  # Changed function name to avoid conflict
            current_user = get_jwt_identity()
            if not current_user or current_user.get('role') not in allowed_roles:
                return jsonify({"error": "Access forbidden: insufficient permissions"}), 403
            return func(*args, **kwargs)
        return _check_user_role
    return decorator

@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user with an optional role."""
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'User')  # Default role is 'User'

    if not all([name, email, password]):
        return jsonify({"error": "All fields are required"}), 400

    if role not in ['Admin', 'User', 'Moderator']:
        return jsonify({"error": "Invalid role"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already exists"}), 400
        
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
            (name, email, hashed_password, role)
        )
        mysql.connection.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()


@app.route('/auth/login', methods=['POST'])
def login():
    """Login user and return access token."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[3], password):
            access_token = create_access_token(identity={"id": user[0], "role": user[4]})
            return jsonify({"access_token": access_token, "message": "Login successful!"}), 200

        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()

@app.route('/role/profile', methods=['GET'])
@jwt_required()
def user_profile():
    """Fetch current user profile."""
    current_user = get_jwt_identity()
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id, name, email, role FROM users WHERE id=%s", (current_user['id'],))
        user = cursor.fetchone()
        if user:
            return jsonify({
                "id": user[0],
                "name": user[1],
                "email": user[2],
                "role": user[3]
            }), 200
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logging.error(f"Error fetching user profile: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()

@app.route('/admin/users', methods=['GET'])
@role_required(['Admin'])
def view_all_users():
    """Admin: View all users."""
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id, name, email, role FROM users")
        users = cursor.fetchall()
        users_list = [{"id": u[0], "name": u[1], "email": u[2], "role": u[3]} for u in users]
        return jsonify(users_list), 200
    except Exception as e:
        logging.error(f"Error fetching users list: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()

# @app.route('/admin/users/<int:user_id>/update', methods=['PUT'])
@app.route('/admin/users/<int:user_id>/update', methods=['PUT'], endpoint='update_user_role')

@role_required(['Admin'])
def update_user_role(user_id):
    """Admin updates a user's role."""
    data = request.json
    new_role = data.get('role')

    if new_role not in ['Admin', 'User', 'Moderator']:
        return jsonify({"error": "Invalid role"}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        mysql.connection.commit()
        return jsonify({"message": f"User ID {user_id} role updated to {new_role}."}), 200
    except Exception as e:
        logging.error(f"Error updating user role: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()

# @app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'])
@app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'], endpoint='delete_user')
@role_required(['Admin'])
def delete_user(user_id):
    """Admin: Delete a user."""
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        mysql.connection.commit()
        return jsonify({"message": f"User ID {user_id} deleted successfully."}), 200
    except Exception as e:
        logging.error(f"Error deleting user: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()

# Main Function
if __name__ == '__main__':
    app.run(debug=True)