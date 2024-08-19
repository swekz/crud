from flask import Flask, render_template, request, jsonify, url_for
from flask_restful import Api
from itsdangerous import URLSafeTimedSerializer
import re,jwt, bcrypt
from flask_mysqldb import MySQL
from bson import * 
import uuid as uuid
from flask_mail import Mail, Message      #Send mail to email 
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
api = Api(app)

#---------smtp connection ---------------------------------------------------------------------------------
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '2ke19mca09@kleit.ac.in'        # user your emailid here
app.config['MAIL_PASSWORD'] = 'sjyxrfwkvqlmuxus'           # use your app password of ur email id
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SECRET_KEY'] = 'secretkey'
app.config['SECRET_KEY1'] = 'secret'
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"
#---------mysql connection------------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234' 
app.config['MYSQL_DB'] = 'user_details'      # database name
mysql = MySQL(app)

# Define a secret key for JWT
JWT_SECRET_KEY = 'jwt_secret_key'

mail = Mail(app)
r = URLSafeTimedSerializer(app.config['SECRET_KEY1'])       #reset token

#---email validation
email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")


#--------------------------password encryption----------------------------------------------------------
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

#----------------------password validation--------------------------
def validate_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,16}$'
    match = re.search(pattern, password)
    return match is not None

def generate_access_token(email):
    access_token_expire = datetime.utcnow() + timedelta(minutes=3)  # Short-lived token
    access_payload = {
        'email': email,
        'exp': access_token_expire
    }
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm="HS256")
    return access_token

def generate_refresh_token(email):
    refresh_token_expire = datetime.utcnow() + timedelta(days=7)  # Long-lived token
    refresh_payload = {
        'email': email,
        'exp': refresh_token_expire
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm="HS256")
    return refresh_token

#-------------------user signup-------------------
@app.route("/signup", methods=['POST'])
def signup():
    # required parameter
    required_params = ['first_name','last_name','email', 'password', 'role']
    data = request.form
    
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})  
    
    email = data["email"]
    password = data["password"]
    role = data["role"]
    first_name = data["first_name"]
    last_name = data["last_name"]

    cur = mysql.connection.cursor()

    # Validate role
    if role not in ['admin', 'user']:
        return jsonify({"message": "Invalid role. Role must be 'admin' or 'user'.","success":False})


    # Validate password
    if not validate_password(password):
        return jsonify({"message":'Password must contain 8 to 16 characters,including at least alphanumeric,1 captial letter and special characters',"Success":False})    

    # Validate email
    elif not email_regex.match(email):
        return jsonify({"message": "Invalid email","Success":False})
    
    # Create table if it does not exist
    create_table_query = '''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(200),
        last_name VARCHAR(200),
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'user') NOT NULL
    )
    '''
    cur.execute(create_table_query)

    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user:
        return jsonify({"message": "Email already exists", "success": False})
    
    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insert user into MySQL database
    insert_query = "INSERT INTO users (first_name,last_name,email, password, role) VALUES (%s,%s,%s, %s, %s)"
    cur.execute(insert_query, (first_name,last_name,email, hashed_password, role))
    mysql.connection.commit()
    
    # Close connection
    cur.close()
    # mysql.close()
    return jsonify({'message':'User registered successfully','success':True})

#-------------------------------login-----------------------------------------------------------------
@app.post("/login")
def login():
    required_params = ['email', 'password']
    data = request.form
    
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})
    
    email = data["email"]
    password = data["password"]

    cur = mysql.connection.cursor()
    
    # Fetch user details from the database
    cur.execute("SELECT email, password FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    # Close cursor
    cur.close()

    if user is None:
        return jsonify({"message": "Sign up before login", "success": False})

    user_email, user_password = user

    if check_password(password, user_password):
        # Generate access and refresh tokens
        access_token = generate_access_token(email)
        refresh_token = generate_refresh_token(email)
        
        # Update user record with tokens
        cur = mysql.connection.cursor()

         # Check if 'access_token' column exists
        cur.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'access_token'
        """)
        access_token_exists = cur.fetchone()[0]
        
        # Check if 'refresh_token' column exists
        cur.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'refresh_token'
        """)
        refresh_token_exists = cur.fetchone()[0]
        
        # Add columns if they don't exist
        if access_token_exists == 0:
            cur.execute("""
                ALTER TABLE users ADD COLUMN access_token VARCHAR(255)
            """)
        if refresh_token_exists == 0:
            cur.execute("""
                ALTER TABLE users ADD COLUMN refresh_token VARCHAR(255)
            """)
        
        update_query = "UPDATE users SET access_token = %s, refresh_token = %s WHERE email = %s"
        cur.execute(update_query, (access_token, refresh_token, email))
        mysql.connection.commit()
        cur.close()

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            # 'user': {
            'email': email,
            # },
            'message': 'Successfully logged in',
            'success': True
        })
    else:
        cur.close()
        return jsonify({'message': 'Password is incorrect', 'success': False})

#----------User List API-------------------
@app.route("/users", methods=['GET'])
def get_users():
    jwtoken = request.headers.get('Authorization')

    if not jwtoken:
        return jsonify({'message': 'Token is missing', 'success': False})

    try:
        jwtoken = jwtoken.split(" ")[1]
        print(f"Received token: {jwtoken}")

        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']

        cur = mysql.connection.cursor()
        cur.execute("SELECT email, role, access_token FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        admin = cur.fetchone()

        if admin is None:
            cur.close()
            return jsonify({'message': 'invalid token', 'success': False})
        
        user_email, role, access_token = admin
        
        if role != 'admin':
            cur.close()
            return jsonify({'message': 'Only admin role can access', 'success': False})

        page = int(request.form.get('page'))
        per_page = int(request.form.get('per_page'))
        offset = (page - 1) * per_page

        cur.execute("SELECT email FROM users LIMIT %s OFFSET %s", (per_page, offset))
        users = [{'email': row[0]} for row in cur.fetchall()]

        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]
        total_pages = (total_users + per_page - 1) // per_page

        cur.close()

        return jsonify({
            "users": users,
            "page": page,
            "per_page": per_page,
            "total_users": total_users,
            "total_pages": total_pages,
            "success": True
        })

    except jwt.ExpiredSignatureError:
        #-----------after access token expires new access token will be generated------- 
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})

#----------------------update user details--------------
@app.put('/update_details')
def update_details():
    jwtoken = request.headers.get('Authorization')

    if not jwtoken:
        return jsonify({'message': 'Token is missing', 'success': False})

    try:
        jwtoken = jwtoken.split(" ")[1]
        print(f"Received token: {jwtoken}")

        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']

        cur = mysql.connection.cursor()
        cur.execute("SELECT email FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Admin not found', 'success': False})

        data = request.form
        update_fields = {}

        if data:
            # Collect fields to update
            if 'first_name' in data:
                update_fields['first_name'] = data['first_name']

            if 'last_name' in data:
                update_fields['last_name'] = data['last_name']

        if update_fields:
            # Construct the SET clause of the SQL query
            set_clause = ", ".join(f"{key} = %s" for key in update_fields.keys())
            values = list(update_fields.values()) + [email]
            
            update_query = f"UPDATE users SET {set_clause} WHERE email = %s"
            cur.execute(update_query, values)
            mysql.connection.commit()
        
        cur.close()
        return jsonify({"message": "Updated successfully", "updated": update_fields, "success": True})

    except jwt.ExpiredSignatureError:
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})
    
#---------------------delete user------------
@app.delete('/delete_user')
def delete_user():
    jwtoken = request.headers.get('Authorization')

    try:
        jwtoken = jwtoken.split(" ")[1]
        print(f"Received token: {jwtoken}")

        # Decode the JWT
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        if not decoded_token:
            raise jwt.ExpiredSignatureError

        email = decoded_token['email']

        # Connect to MySQL and check if the admin exists and has the correct role
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, role, access_token FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        admin = cur.fetchone()

        if not admin:
            cur.close()
            return jsonify({'message': 'Admin not found', "success": False})

        if admin[1] != 'admin':
            cur.close()
            return jsonify({'message': 'Only admin role can access', 'success': False})

        data = request.form
        user_email = data['user_email']

        # Check if the user exists
        cur.execute("SELECT email FROM users WHERE email = %s", (user_email,))
        user = cur.fetchone()

        if user:
            # Delete the user
            cur.execute("DELETE FROM users WHERE email = %s", (user_email,))
            mysql.connection.commit()
            cur.close()
            return jsonify({'message': 'User deleted', "success": True})
        else:
            cur.close()
            return jsonify({'message': 'User not found', "success": False})

    except jwt.ExpiredSignatureError:
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})

#----------------forgot password---------------------------------------------------------------------------
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    required_params = ['email']
    forgot = request.form
    
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in forgot]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})

    if request.method == 'POST':
        email = forgot['email']
        
        cur = mysql.connection.cursor()

        # Check if the email exists in the database
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            cur.close()
            return jsonify({"error": 'Email not found', "success": False})

        # Generate a password reset token and its expiration time
        rtoken = uuid.uuid4().hex
        expiry_time = datetime.utcnow() + timedelta(minutes=5)  # Token valid for 5 minutes

        # Check if the rtoken column exists, and add it if it doesn't
        cur.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'rtoken'
        """)
        rtoken_exists = cur.fetchone()[0]
        
        # Check if 'refresh_token' column exists
        cur.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'rtoken_expiry'
        """)
        rtoken_expiry_exists = cur.fetchone()[0]
        
        # Add columns if they don't exist
        if rtoken_exists == 0:
            cur.execute("""
                ALTER TABLE users ADD COLUMN rtoken VARCHAR(255)
            """)
        if rtoken_expiry_exists == 0:
            cur.execute("""
                ALTER TABLE users ADD COLUMN rtoken_expiry DATETIME
            """)

        # Save the password reset token and its expiration time in the database
        cur.execute("UPDATE users SET rtoken = %s, rtoken_expiry = %s WHERE id = %s", (rtoken, expiry_time, user[0]))
        mysql.connection.commit()

        # Send the password reset link to the user's email
        msg = Message('Password Reset Link', sender='swekz007@gmail.com', recipients=[email])
        msg.body = 'Click on the following link to reset your password: '
        msg.body += url_for('reset_password', rtoken=rtoken, _external=True)
        mail.send(msg)

        cur.close()
        return jsonify({"message": "Reset password link sent to email", "success": True})

#--------------------reset password--------------------------------------------------------------------------
@app.route('/reset_password/<rtoken>', methods=['GET', 'POST'])
def reset_password(*args, **kwargs):
    rtoken = kwargs.get('rtoken')

    cur = mysql.connection.cursor()

    # Find the user with the matching password reset token and expiry time
    cur.execute("SELECT id, rtoken_expiry FROM users WHERE rtoken = %s", (rtoken,))

    user = cur.fetchone()

    if not user:
        cur.close()
        return jsonify({"message": "Invalid token", "success": False})

    user_id, rtoken_expiry = user
    current_time = datetime.utcnow()

    # Check if the token has expired
    if current_time > rtoken_expiry:
        cur.close()
        return render_template('link.html', message="The password reset link has expired.")

    if request.method == 'GET':
        cur.close()
        return render_template('reset.html', rtoken=rtoken)

    if request.method == 'POST':
        # Get the new password from the request
        data = request.form
        password = data['password']
        confirm_password = data['confirm_password']

        if password != confirm_password:
            cur.close()
            return jsonify({"message": "Passwords do not match", "success": False})

        if not validate_password(password):
            cur.close()
            return jsonify({"message": "Password must contain 8 to 16 characters, including at least 1 alphanumeric, capital letter, and special characters", "success": False})

        # Hash the new password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update the user's password in the database and remove the reset token
        cur.execute("UPDATE users SET password = %s, rtoken = NULL, rtoken_expiry = NULL WHERE id = %s", (hashed_password, user_id))
        mysql.connection.commit()

        cur.close()
        return jsonify({"message": "Password updated", "success": True})

#---------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000, debug=True)
