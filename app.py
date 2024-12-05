from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, abort, send_file
import sqlite3
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import ast
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
app = Flask(__name__)
app.secret_key = os.urandom(24)
from werkzeug.utils import secure_filename
# Add these imports at the top of your file

import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)


from flask import Flask, request
from paypalserversdk.http.auth.o_auth_2 import ClientCredentialsAuthCredentials
from paypalserversdk.logging.configuration.api_logging_configuration import (
    LoggingConfiguration,
    RequestLoggingConfiguration,
    ResponseLoggingConfiguration,
)
from paypalserversdk.paypal_serversdk_client import PaypalServersdkClient
from paypalserversdk.controllers.orders_controller import OrdersController
from paypalserversdk.controllers.payments_controller import PaymentsController
from paypalserversdk.models.amount_with_breakdown import AmountWithBreakdown
from paypalserversdk.models.checkout_payment_intent import CheckoutPaymentIntent
from paypalserversdk.models.order_request import OrderRequest
from paypalserversdk.models.capture_request import CaptureRequest
from paypalserversdk.models.money import Money
from paypalserversdk.models.shipping_details import ShippingDetails
from paypalserversdk.models.shipping_option import ShippingOption
from paypalserversdk.models.shipping_type import ShippingType
from paypalserversdk.models.purchase_unit_request import PurchaseUnitRequest
from paypalserversdk.models.payment_source import PaymentSource
from paypalserversdk.models.card_request import CardRequest
from paypalserversdk.models.card_attributes import CardAttributes
from paypalserversdk.models.card_verification import CardVerification
from paypalserversdk.models.card_verification_method import CardVerificationMethod
from paypalserversdk.api_helper import ApiHelper


paypal_client: PaypalServersdkClient = PaypalServersdkClient(
    client_credentials_auth_credentials=ClientCredentialsAuthCredentials(
        o_auth_client_id="AeRRud6E1YCsRUXFGKENChRJrjO9cFdrdSmcuj-m8zer9glCyFiU5jSJQoMQPPI6e4JxDyulTG47OvsJ",
        o_auth_client_secret="EDNZIPk0RWPSXRUnu89uT5d1RGTdOD04DocwhBMUVwutiMOGiwGQzks3lgYICU_n-embN9fRHjvKiXdD",
    ),
    logging_configuration=LoggingConfiguration(
        log_level=logging.INFO,
        # Disable masking of sensitive headers for Sandbox testing.
        # This should be set to True (the default if unset)in production.
        mask_sensitive_headers=False,
        request_logging_config=RequestLoggingConfiguration(
            log_headers=True, log_body=True
        ),
        response_logging_config=ResponseLoggingConfiguration(
            log_headers=True, log_body=True
        ),
    ),
)

orders_controller: OrdersController = paypal_client.orders
payments_controller: PaymentsController = paypal_client.payments

# Initialize the Flask app with static folder configuration
app = Flask(__name__, static_folder='static')
# Set a secret key for the app
app.secret_key = 'dynrhn57hsyhsi8' 
# Email settings
sender_email = "codeflux001@gmail.com"
app_password = "tskt qivl uece vbjb "
admin_email = "codeflux001@gmail.com"

# Code storage directory
code_storage_dir = os.path.join(os.path.dirname(__file__), 'code-storage')
os.makedirs(code_storage_dir, exist_ok=True)  # Ensure directory exists

# Define the folder to save profile pictures
UPLOAD_FOLDER = 'static/images/profile_pictures'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dataset storage directory
uploaded_file_dir = os.path.join(os.path.dirname(__file__), 'datasets')
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'json', 'txt'}
# Check if the uploaded file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Track failed login attempts
failed_attempts = {}


# Initialize the SQLite databasedef init_db():
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Create users table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            dob DATE,
            country TEXT,
            profile_picture TEXT,
            otp TEXT,
            has_paid BOOLEAN DEFAULT 0
        )
    ''')
    
    # Check if 'has_paid' column exists, if not, add it
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'has_paid' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN has_paid BOOLEAN DEFAULT 0")
    
    # Create payments table
    c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            payment_id TEXT,
            status TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
def send_alert_email():
    try:
        msg = MIMEText("Dear admin, Your system has received attempted hack! Stay on High Alert!")
        msg['Subject'] = "Security Alert: Login Attempts Exceeded"
        msg['From'] = sender_email
        msg['To'] = admin_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, admin_email, msg.as_string())
        server.quit()
        print("Alert email sent successfully!")
    except Exception as e:
        print(f"Error sending alert email: {e}")

def send_otp(email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = "Your Code Flux OTP"
        body = f"Dear User, Welcome to Codeflux🤝! Your OTP code is: {otp}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        print("OTP email sent successfully!")
    except Exception as e:
        print(f"Error sending OTP email: {e}")
# Index route for launching the app
@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('home_page'))  # Redirect to home if logged in
    return render_template('index.html')  # Render index.html for guests

@app.route("/api/orders", methods=["POST"])
def create_order():
    request_body = request.get_json()
    # use the cart information passed from the front-end to calculate the order amount detals
    cart = request_body["cart"]
    order = orders_controller.orders_create(
        {
            "body": OrderRequest(
                intent=CheckoutPaymentIntent.CAPTURE,
                purchase_units=[
                    PurchaseUnitRequest(
                        amount=AmountWithBreakdown(
                            currency_code="USD",
                            value="20",
                        ),

                    )
                ],

            )
        }
    )
    return ApiHelper.json_serialize(order.body)


# Resources route
@app.route('/resources')
def resources():
    # Render the Resources page directly
    return render_template('resources.html')
# Privacy Policy route
@app.route('/privacy')
def privacy():
    # Render the Privacy Policy page directly
    return render_template('privacy.html')

# Terms of Service route
@app.route('/terms')
def terms():
    # Render the Terms of Service page directly
    return render_template('terms.html')

# Home route
@app.route('/home')
def home_page():
    email = session.get('email')
    if email:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT username, email, first_name, last_name, dob, country, profile_picture FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user:
            user_data = {
                'username': user[0],
                'email': user[1],
                'first_name': user[2],
                'last_name': user[3],
                'dob': user[4],
                'country': user[5],
                'profile_picture': user[6]  # This should match the filename
            }
            # Adjusting the URL generation to point to the correct directory
            profile_picture_url = url_for('static', filename='images/profile_pictures/' + user[6]) if user[6] else None
            print(f"Profile Picture URL: {profile_picture_url}")  # Log the generated URL
            return render_template('home.html', user=user_data)
    
    flash("You need to log in first.")
    return redirect(url_for('login'))

# security route
@app.route('/security')
def security():
    # Check if the user is logged in
    if 'logged_in' not in session:
        # Redirect to login page if not logged in
        flash("Please log in to access the Security page.")
        return redirect(url_for('login'))
    # If logged in, render the Security page
    return render_template('security.html')

# about route
@app.route('/about')
def about():
    # Check if the user is logged in
    if 'logged_in' not in session:
        # If not logged in, redirect to the login page
        flash("Please log in to access the About page.")
        return redirect(url_for('login'))
    
    # If logged in, proceed to the About page
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    global failed_attempts

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role')  # Optional, default to None if not provided

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Fetch user data by email
        c.execute("SELECT id, password FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            user_id, hashed_password = user

            # Compare the hashed password with the entered password
            if check_password_hash(hashed_password, password):
                failed_attempts[email] = 0

                # Generate OTP and update it in the database
                otp = str(random.randint(100000, 999999))
                send_otp(email, otp)

                conn = sqlite3.connect('database.db')
                c = conn.cursor()
                c.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
                conn.commit()
                conn.close()

                # Set session variables
                session['email'] = email
                session['user_id'] = user_id
                session['role'] = role

                return redirect(url_for('verify_otp'))
            else:
                # Password mismatch
                failed_attempts[email] = failed_attempts.get(email, 0) + 1
                if failed_attempts[email] == 4:
                    send_alert_email()
                flash("Invalid credentials, please try again.")
        else:
            # User not found
            flash("Invalid credentials, please try again.")

    return render_template('login.html')

# verify otp route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('email')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ? AND otp = ?", (email, otp))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            # Make sure user_id remains in session
            if 'user_id' not in session:
                session['user_id'] = user[0]  # Assuming id is the first column
            return redirect(url_for('home_page'))
        else:
            flash("Incorrect OTP, please try again.")
            return redirect(url_for('login'))
    return render_template('verify_otp.html')


# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            # Input validation
            if not username or not email or not password:
                flash("All fields are required.")
                return redirect(url_for('register'))
            
            # Hash the password
            hashed_password = generate_password_hash(password)
            
            conn = get_db()  # Use the get_db function you already have
            cursor = conn.cursor()
            
            try:
                # Insert new user
                cursor.execute("""
                    INSERT INTO users (username, email, password, has_paid) 
                    VALUES (?, ?, ?, ?)
                """, (username, email, hashed_password, 0))
                
                conn.commit()
                
                # Generate and send OTP
                otp = str(random.randint(100000, 999999))
                send_otp(email, otp)
                
                # Update OTP in database
                cursor.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
                conn.commit()
                
                # Set session variables
                session['email'] = email
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                user = cursor.fetchone()
                if user:
                    session['user_id'] = user[0]
                
                flash("Registration successful! Please verify your OTP.")
                return redirect(url_for('verify_otp'))
                
            except sqlite3.IntegrityError as e:
                conn.rollback()
                if "UNIQUE constraint failed: users.email" in str(e):
                    flash("Email already registered. Please use a different email.")
                elif "UNIQUE constraint failed: users.username" in str(e):
                    flash("Username already taken. Please choose a different username.")
                else:
                    flash("Registration failed. Please try again.")
                return redirect(url_for('register'))
                
            except Exception as e:
                conn.rollback()
                logging.error(f"Registration error: {str(e)}")
                flash("An error occurred during registration. Please try again.")
                return redirect(url_for('register'))
                
            finally:
                conn.close()
                
        except Exception as e:
            logging.error(f"Form processing error: {str(e)}")
            flash("An error occurred. Please try again.")
            return redirect(url_for('register'))
    
    # GET request - show registration form
    return render_template('registration.html')

# Route to update user profile
@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = session.get('email')  # Get the user's email from the session
    if email:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        country = request.form['country']
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture and profile_picture.filename != '':
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = None
        else:
            filename = None
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Update user details
        c.execute("""
            UPDATE users 
            SET first_name = ?, last_name = ?, dob = ?, country = ?, profile_picture = ?
            WHERE email = ?
        """, (first_name, last_name, dob, country, filename, email))
        conn.commit()
        conn.close()
        
        flash("Profile updated successfully!")
        return redirect(url_for('home_page'))
    
    flash("You need to log in first.")
    return redirect(url_for('login'))  # Redirect to login if not logged in

# Serializer for generating and decoding tokens
s = URLSafeTimedSerializer(app.secret_key)
# Email settings
sender_email = "codeflux001@gmail.com"
app_password = "tskt qivl uece vbjb"  # Ensure there are no extra spaces here
admin_email = "codeflux001@gmail.com"

# Send email link for reset password
def send_email(subject, recipient, body):
    """Sends an email for password reset."""
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))  # Attach the email body content
        
        # Initialize SMTP server with SSL
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        
        print("Password reset email sent successfully!")
    except Exception as e:
        print(f"Error sending password reset email: {e}")
# Forgot Password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user:
            # Generate a secure token for the reset link
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            email_body = f'Click the link to reset your password: {reset_url}'
            
            # Send the reset email
            send_email('Password Reset Request', email, email_body)
            flash('A password reset link has been sent to your email.', 'info')
            return render_template('forgot_password_success.html')
        else:
            flash('No account found with that email.', 'danger')
    
    return render_template('forgot_password.html')

# Reset Password route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token to get the email
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        # Update the user's password in the database, storing it as a hash
        hashed_password = generate_password_hash(new_password)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()
        
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)
# Quiz route
@app.route('/quiz')
def quiz():
    return render_template('quiz.html')  # Serve the quiz HTML

# Programming route
@app.route('/programming')
def programming():
    return render_template('programming.html')

# Pdfs routes
# Define the path to PDFs within the templates folder
PDF_DIRECTORY = os.path.join(app.root_path, 'templates', 'pdf')
@app.route('/pdfs/<path:filename>')
def serve_pdf(filename):
    try:
        return send_file(os.path.join(PDF_DIRECTORY, filename), mimetype='application/pdf')
    except FileNotFoundError:
        abort(404)

# Logout route        
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('logged_in', None)
    return redirect(url_for('login'))

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def user_has_paid(user_id):
    if not user_id:
        return False
        
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT has_paid 
            FROM users 
            WHERE id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        return bool(result['has_paid']) if result else False
    except Exception as e:
        logging.error(f"Error checking payment status: {str(e)}")
        return False
    finally:
        conn.close()

@app.context_processor
def utility_processor():
    def check_payment():
        if 'user_id' in session:
            return user_has_paid(session['user_id'])
        return False
    return dict(user_has_paid=check_payment)

@app.route('/payment')
def payment_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check if user has already paid
        cursor.execute('SELECT has_paid FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if user and user['has_paid']:
            flash("You have already purchased the course!")
            return redirect(url_for('mlai'))
            
        return render_template('payment.html', 
                             paypal_client_id=os.getenv("PAYPAL_CLIENT_ID"))
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        flash("An error occurred. Please try again.")
        return redirect(url_for('home_page'))
    finally:
        conn.close()

# Add a new route to check payment status
@app.route('/check_payment_status')
def check_payment_status():
    if 'user_id' not in session:
        return jsonify({'paid': False, 'message': 'Not logged in'})
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT has_paid FROM users WHERE id = ?', (session['user_id'],))
        result = cursor.fetchone()
        return jsonify({
            'paid': bool(result['has_paid']) if result else False,
            'message': 'Payment verified' if result and result['has_paid'] else 'Payment required'
        })
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        return jsonify({'paid': False, 'message': 'Error checking payment status'})
    finally:
        conn.close()


# Compiler route
@app.route('/compiler')
def compiler():
    return render_template('compiler.html')

# Compiler functionality with file upload
@app.route('/compile', methods=['POST'])
def compile_code():
    code = request.form.get('code')
    language = request.form.get('language')
    dataset = request.files.get('dataset')  # This will get the file

    file_path, compile_command, run_command = None, None, None

    if language == 'python':
        file_path = os.path.join(code_storage_dir, 'main.py')
        with open(file_path, 'w') as f:
            f.write(code)
        run_command = f'python {file_path}'
        
        required_libraries = detect_imports(code)
        install_libraries(required_libraries)

    elif language == 'java':
        file_path = os.path.join(code_storage_dir, 'Main.java')
        with open(file_path, 'w') as f:
            f.write(code)
        compile_command = f'javac {file_path}'
        run_command = f'java -cp {code_storage_dir} Main'

    elif language == 'cpp':
        file_path = os.path.join(code_storage_dir, 'main.cpp')
        with open(file_path, 'w') as f:
            f.write(code)
        compile_command = f'g++ {file_path} -o {code_storage_dir}/main'
        run_command = f'{code_storage_dir}/main'

    else:
        return jsonify({'output': 'Invalid language selected.'})

    # Handle file (dataset) processing if it's provided
    if dataset:
        if allowed_file(dataset.filename):
            filename = secure_filename(dataset.filename)
            dataset_path = os.path.join(uploaded_file_dir, filename)
            dataset.save(dataset_path)  # Save the file

        else:
            return jsonify({'output': 'Invalid file type. Allowed types are: csv, json, txt.'})

    if compile_command:
        compile_process = subprocess.run(
            compile_command, shell=True, text=True, capture_output=True
        )
        if compile_process.returncode != 0:
            return jsonify({'output': compile_process.stderr})

    run_process = subprocess.run(
        run_command, shell=True, text=True, capture_output=True
    )
    output = run_process.stdout if run_process.returncode == 0 else run_process.stderr

    return jsonify({'output': output})


@app.route('/get_code/<language>', methods=['GET'])
def get_code(language):
    code_files = {
        'python': 'main.py',
        'java': 'Main.java',
        'cpp': 'main.cpp'
    }

    if language in code_files:
        try:
            file_path = os.path.join(code_storage_dir, code_files[language])
            with open(file_path, 'r') as f:
                code = f.read()
            return jsonify({'code': code})
        except FileNotFoundError:
            return jsonify({'code': 'Code file not found for the selected language.'}), 404
    else:
        return jsonify({'code': 'Invalid language selected.'}), 400

def detect_imports(code):
    tree = ast.parse(code)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module)
    return imports - {"calendar"}  # Skip standard libraries like 'calendar'

def install_libraries(libraries):
    for library in libraries:
        try:
            if library in {"calendar"}:
                continue
            subprocess.run(['pip', 'install', library], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error installing {library}: {e}")

@app.route('/mlai')
def mlai_page():
    logging.info("Accessing ML/AI page - Starting access check")
    
    # Check if user is logged in
    if 'user_id' not in session:
        logging.warning("Access attempt without login - user_id not in session")
        flash("Please log in to access the ML/AI course content.")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    logging.info(f"User ID {user_id} attempting to access ML/AI content")
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check payment status with detailed query
        cursor.execute('''
            SELECT u.id, u.email, u.has_paid, 
                   COALESCE(p.status, 'NO_PAYMENT') as payment_status,
                   COALESCE(p.payment_date, 'NEVER') as last_payment_date
            FROM users u
            LEFT JOIN payments p ON u.id = p.user_id
            WHERE u.id = ?
            ORDER BY p.payment_date DESC
            LIMIT 1
        ''', (user_id,))
        result = cursor.fetchone()
        
        if result:
            logging.info(f"Payment check results for user {user_id}:")
            logging.info(f"has_paid status: {result['has_paid']}")
            logging.info(f"payment status: {result['payment_status']}")
            logging.info(f"last payment date: {result['last_payment_date']}")
            
            if result['has_paid']:
                logging.info(f"Access granted to user {user_id} - Payment verified")
                return render_template('mlai.html')
            else:
                logging.warning(f"Access denied to user {user_id} - No payment found")
                flash("Please complete the payment to access the ML/AI course content.")
                return redirect(url_for('payment_page'))
        else:
            logging.error(f"No user record found for user_id {user_id}")
            flash("User record not found. Please contact support.")
            return redirect(url_for('home_page'))
            
    except Exception as e:
        logging.error(f"Database error for user {user_id}: {str(e)}")
        logging.error(f"Full exception: {e}", exc_info=True)
        flash("An error occurred. Please try again.")
        return redirect(url_for('home_page'))
    finally:
        conn.close()
        logging.info(f"ML/AI page access check completed for user {user_id}")

# Add a decorator to enforce payment requirement
def payment_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning("Payment check: No user_id in session")
            flash("Please log in to access this content.")
            return redirect(url_for('login'))
            
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT has_paid FROM users WHERE id = ?', (session['user_id'],))
            result = cursor.fetchone()
            
            if not result or not result['has_paid']:
                logging.warning(f"Payment check: User {session['user_id']} has not paid")
                flash("Please complete the payment to access this content.")
                return redirect(url_for('payment_page'))
                
            return f(*args, **kwargs)
            
        except Exception as e:
            logging.error(f"Payment check error: {str(e)}")
            flash("An error occurred. Please try again.")
            return redirect(url_for('home_page'))
        finally:
            conn.close()
    return decorated_function

# Modify the capture_order function to properly set has_paid
@app.route("/api/orders/<order_id>/capture", methods=["POST"])
def capture_order(order_id):
    logging.info(f"Capturing order {order_id}")
    try:
        order = orders_controller.orders_capture(
            {"id": order_id, "prefer": "return=representation"}
        )
        
        order_data = ApiHelper.json_serialize(order.body)
        order_dict = ApiHelper.json_deserialize(order_data)
        
        logging.info(f"Payment status: {order_dict.get('status')}")
        
        if order_dict.get('status') == "COMPLETED":
            if 'user_id' in session:
                conn = get_db()
                cursor = conn.cursor()
                try:
                    # Update user payment status
                    cursor.execute('''
                        UPDATE users 
                        SET has_paid = 1 
                        WHERE id = ?
                    ''', (session['user_id'],))
                    
                    payment_info = order_dict.get('purchase_units', [{}])[0].get('payments', {}).get('captures', [{}])[0]
                    amount = payment_info.get('amount', {}).get('value', '0.00')
                    
                    cursor.execute('''
                        INSERT INTO payments (user_id, amount, payment_id, status)
                        VALUES (?, ?, ?, ?)
                    ''', (session['user_id'], float(amount), order_id, 'COMPLETED'))
                    
                    conn.commit()
                    logging.info(f"Payment recorded successfully for user {session['user_id']}")
                    
                except Exception as e:
                    conn.rollback()
                    logging.error(f"Database error in capture_order: {str(e)}")
                    raise e
                finally:
                    conn.close()
        
        return order_data
        
    except Exception as e:
        logging.error(f"Error capturing order: {str(e)}")
        return jsonify({
            "error": str(e),
            "message": "Failed to process payment"
        }), 500

# Add a function to verify database state
def verify_payment_status(user_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT u.id, u.email, u.has_paid, 
                   p.status as payment_status,
                   p.payment_date
            FROM users u
            LEFT JOIN payments p ON u.id = p.user_id
            WHERE u.id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        
        if result:
            logging.info(f"""
                Payment Status Check:
                User ID: {result['id']}
                Email: {result['email']}
                Has Paid: {result['has_paid']}
                Payment Status: {result['payment_status']}
                Payment Date: {result['payment_date']}
            """)
        else:
            logging.warning(f"No payment record found for user {user_id}")
            
    except Exception as e:
        logging.error(f"Error verifying payment status: {str(e)}")
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()  # Initialize the database
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)