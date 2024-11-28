from flask_bcrypt import Bcrypt

# Initialize Bcrypt
bcrypt = Bcrypt()

# Generate hashed password
hashed_password = bcrypt.generate_password_hash("superadmin123").decode('utf-8')

# Print the hashed password
print("Hashed password:", hashed_password)
