# Flask RBAC System
A Flask-based Role-Based Access Control (RBAC) system with user authentication, registration, and role management. This project is designed to demonstrate secure API development using JWT for authentication and MySQL for data storage.

# Features
User Registration: Allows users to register with roles (Admin, User, Moderator).

User Authentication: Login with email and password to receive a JWT token.

Role-Based Access Control:

Admins can manage users (view, update roles, delete).

Users can view their profiles.

Secure Passwords: Passwords are hashed using Bcrypt.

API Endpoints: Exposes RESTful endpoints for the application.

# Technologies Used
Backend Framework: Flask

Database: MySQL

Authentication: Flask-JWT-Extended

Password Hashing: Flask-Bcrypt

Environment Management: Python os.environ

Logging: Built-in Python logging

API Testing: Postman
