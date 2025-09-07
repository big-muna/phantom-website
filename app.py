import os
import random
import time
import requests
import secrets
from datetime import datetime
from bitcoinlib.wallets import Wallet
from web3 import Web3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from flask_migrate import Migrate

# ----------------- App Setup -----------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ----------------- Database Setup -----------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://phantomrecovery_db_user:KasJByMOWqUSCCVwF7gMklNFJo2YV8rj@dpg-d2s6llq4d50c73dh7tm0-a/phantomrecovery_db"
)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ Correct SQLAlchemy & Migrate initialization
db = SQLAlchemy()
migrate = Migrate()
db.init_app(app)
migrate.init_app(app, db)

# ----------------- Paystack Config -----------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "your_paystack_secret_key")
PAYSTACK_URL = "https://api.paystack.co"

# ----------------- Ethereum Setup -----------------
INFURA_URL = os.getenv("INFURA_URL")
PRIVATE_KEY = os.getenv("WALLET_PRIVATE_KEY")
SENDER_ADDRESS = os.getenv("WALLET_ADDRESS")

# Connect to Ethereum via Infura
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

if w3.is_connected:
    print("✅ Connected to Ethereum network")
else:
    print("❌ Connection failed")

# Function to send ETH
def send_eth(to_address, amount_eth):
    try:
        amount_wei = w3.to_wei(amount_eth, "ether")  # updated to snake_case
        nonce = w3.eth.get_transaction_count(SENDER_ADDRESS)

        tx = {
            "nonce": nonce,
            "to": to_address,
            "value": amount_wei,
            "gas": 21000,
            "gasPrice": w3.to_wei("50", "gwei")
        }

        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return {"status": "success", "tx_hash": tx_hash.hex()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ----------------- Database Model -----------------
class User(db.Model):
    __tablename__ = "users"  # Use plural consistently

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # nullable=False is safer
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    profile_image = db.Column(db.String(200), nullable=True)

    btc_address = db.Column(db.String(200), nullable=True)
    eth_address = db.Column(db.String(200), nullable=True)
    eth_private_key = db.Column(db.String(200), nullable=True)

    btc_balance = db.Column(db.Float, default=0.0)
    eth_balance = db.Column(db.Float, default=0.0)
    usdt_balance = db.Column(db.Float, default=0.0)
    ngn_balance = db.Column(db.Float, default=0.0)

    def __repr__(self):
        return f"<User {self.username}>"

# ----------------- Email Config -----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME", "yourcompanyemail@gmail.com")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD", "your_app_password")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER", "yourcompanyemail@gmail.com")
mail = Mail(app)

# ----------------- File Upload Config -----------------
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ Auto-create tables on startup
with app.app_context():
    db.create_all()

class Withdrawal(db.Model):
    __tablename__ = "withdrawals"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    currency = db.Column(db.String(10), nullable=False)  # BTC, ETH, USDT, NGN
    amount = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(255), nullable=True)  # Wallet address or bank account
    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship("User", backref=db.backref("withdrawals", lazy=True))


# ----------------- Schema Helper -----------------
def ensure_schema():
    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()
    if "user" not in tables:
        db.create_all()
        return

    cols = [c["name"] for c in inspector.get_columns("user")]
    with db.engine.begin() as conn:
        if "btc_address" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN btc_address VARCHAR(200);'))
        if "eth_address" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN eth_address VARCHAR(200);'))
        if "eth_private_key" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN eth_private_key VARCHAR(200);'))
        if "btc_balance" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN btc_balance FLOAT DEFAULT 0.0;'))
        if "eth_balance" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN eth_balance FLOAT DEFAULT 0.0;'))
        if "usdt_balance" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN usdt_balance FLOAT DEFAULT 0.0;'))

# ----------------- Wallet Helpers -----------------
def create_eth_wallet():
    """Generate a new Ethereum wallet (address + private key)"""
    priv_key = "0x" + secrets.token_hex(32)
    w3 = Web3()
    acct = w3.eth.account.from_key(priv_key)
    return {"address": acct.address, "private_key": priv_key}

def create_btc_wallet():
    """Generate a new Bitcoin wallet using bitcoinlib"""
    w = Wallet.create(f"user_wallet_{random.randint(1, 999999)}")
    return w.get_key().address

# Example: Create wallet when new user registers
def initialize_user_wallet(user):
    if not user.eth_address:
        eth_wallet = create_eth_wallet()
        user.eth_address = eth_wallet["address"]
        user.eth_private_key = eth_wallet["private_key"]

    if not user.btc_address:
        user.btc_address = create_btc_wallet()

    db.session.commit()


# ----------------- Bank Withdrawal (Paystack) -----------------
def send_bank_transfer(amount, account_number, bank_code):
    """
    Sends money to a Nigerian bank account using Paystack.
    ✅ Uses real API if PAYSTACK_SECRET_KEY is set.
    ✅ Falls back to simulation mode for local testing.
    """
    paystack_key = os.getenv("PAYSTACK_SECRET_KEY")

    if not paystack_key:
        # ---------- Simulation Mode ----------
        print(f"[SIMULATION] Bank transfer: {amount} NGN -> {account_number} ({bank_code})")
        return {"status": "success", "message": "Simulated bank transfer (no real money sent)"}

    headers = {
        "Authorization": f"Bearer {paystack_key}",
        "Content-Type": "application/json"
    }

    try:
        # Step 1: Create Transfer Recipient
        recipient_payload = {
            "type": "nuban",
            "name": "Withdrawal User",
            "account_number": account_number,
            "bank_code": bank_code,
            "currency": "NGN"
        }
        r1 = requests.post("https://api.paystack.co/transferrecipient",
                           headers=headers, json=recipient_payload, timeout=30)
        recipient_data = r1.json()
        if not recipient_data.get("status"):
            return {"status": "error", "message": recipient_data.get("message", "Failed to create recipient")}

        recipient_code = recipient_data["data"]["recipient_code"]

        # Step 2: Initiate Transfer
        transfer_payload = {
            "source": "balance",
            "amount": int(amount * 100),  # NGN -> kobo
            "recipient": recipient_code,
            "reason": "User Withdrawal"
        }
        r2 = requests.post("https://api.paystack.co/transfer",
                           headers=headers, json=transfer_payload, timeout=30)
        result = r2.json()

        if result.get("status"):
            return {"status": "success", "message": "Bank transfer initiated", "data": result}
        else:
            return {"status": "error", "message": result.get("message", "Transfer failed")}

    except Exception as e:
        return {"status": "error", "message": str(e)}


# ----------------- Crypto Withdrawal (BTC) -----------------
def send_btc(destination_address, amount):
    """
    Sends BTC using bitcoinlib wallet.
    ✅ Uses real wallet if available.
    ✅ Falls back to simulation if wallet not found.
    """
    try:
        w = Wallet("my_wallet_name")
        tx = w.send_to(destination_address, amount)
        return {"status": "success", "txid": tx.txid}
    except Exception as e:
        print(f"[SIMULATION] BTC send failed: {str(e)}")
        return {"status": "success", "message": f"Simulated BTC send: {amount} BTC to {destination_address}"}
    
# ----------------- OAuth Setup -----------------
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET"),
    redirect_to="oauth_callback",
    scope=["profile", "email"]
)
facebook_bp = make_facebook_blueprint(
    client_id=os.getenv("FACEBOOK_APP_ID", "YOUR_FACEBOOK_APP_ID"),
    client_secret=os.getenv("FACEBOOK_APP_SECRET", "YOUR_FACEBOOK_APP_SECRET"),
    redirect_to="oauth_callback",
    scope=["email"]
)
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

# ----------------- Public Routes -----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/case")
def case():
    return render_template("case.html")  # or whatever template you want

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

# ----------------- Authentication -----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")

        if not username or not email or not password:
            flash("⚠️ Please fill all fields!", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already taken!", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered!", "warning")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user"] = user.username
            flash("✅ Login successful! Welcome.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid username or password!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/profile")
def profile():
    username = session.get("user")
    if not username:
        flash("⚠️ You need to log in first!", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("❌ User not found!", "danger")
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)


@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    username = session.get("user")
    if not username:
        flash("⚠️ You need to log in first!", "warning")
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first()
    if 'profile_image' not in request.files:
        flash("❌ No file part", "danger")
        return redirect(url_for('profile'))
    file = request.files['profile_image']
    if file.filename == '':
        flash("❌ No selected file", "danger")
        return redirect(url_for('profile'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_image = filename
        db.session.commit()
        flash("✅ Profile image updated!", "success")
        return redirect(url_for('profile'))
    else:
        flash("❌ Invalid file type", "danger")
        return redirect(url_for('profile'))

@app.route("/setting")
def setting():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    return render_template("setting.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

# ----------------- Password Reset -----------------
@app.route("/forgotten", methods=["GET", "POST"])
def forgotten():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        user = User.query.filter_by(username=username).first()
        if user:
            code = str(random.randint(100000, 999999))
            reset_entry = PasswordReset(username=username, code=code)
            db.session.add(reset_entry)
            db.session.commit()
            session["reset_username"] = username
            send_email(user.email, code, "password_reset")
            flash("📩 Check your email for the reset code.", "info")
        else:
            flash("📩 If this username exists, a reset code has been sent.", "info")
        return redirect(url_for("reset_password"))
    return render_template("forgotten.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    username = session.get("reset_username")
    if not username:
        return redirect(url_for("forgotten"))

    if request.method == "POST":
        code = request.form.get("code")
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        reset_entry = PasswordReset.query.filter_by(username=username, code=code).first()
        if reset_entry:
            if time.time() - reset_entry.created_at > 300:
                db.session.delete(reset_entry)
                db.session.commit()
                flash("❌ Code expired. Please request a new one.", "danger")
                return redirect(url_for("forgotten"))

            if new_password == confirm_password:
                user = User.query.filter_by(username=username).first()
                if not user:
                    flash("❌ User not found.", "danger")
                    return redirect(url_for("forgotten"))
                user.password = generate_password_hash(new_password)
                db.session.commit()
                db.session.delete(reset_entry)
                db.session.commit()
                flash("✅ Password reset successful! Please login.", "success")
                return redirect(url_for("login"))
            else:
                flash("❌ Passwords do not match.", "danger")
        else:
            flash("❌ Invalid reset code.", "danger")
    return render_template("reset_password.html")

# ----------------- OAuth Callback -----------------
@app.route("/oauth_callback")
def oauth_callback():
    user = None
    if google.authorized:
        resp = google.get("/oauth2/v1/userinfo")
        user_info = resp.json()
        email = (user_info.get("email") or "").lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            base = email.split("@")[0] or "user"
            candidate = base
            i = 1
            while User.query.filter_by(username=candidate).first():
                i += 1
                candidate = f"{base}{i}"
            user = User(username=candidate, email=email, password=generate_password_hash(os.urandom(16).hex()))
            db.session.add(user)
            db.session.commit()

    elif facebook.authorized:
        resp = facebook.get("/me?fields=name,email")
        user_info = resp.json()
        email = (user_info.get("email") or "").lower()
        name = (user_info.get("name") or "facebook_user").replace(" ", "").lower()[:80] or "facebook_user"
        user = User.query.filter_by(email=email).first() if email else None
        if not user:
            candidate = name
            i = 1
            while User.query.filter_by(username=candidate).first():
                i += 1
                candidate = f"{name}{i}"
            user = User(username=candidate, email=email or f"{candidate}@example.com",
                        password=generate_password_hash(os.urandom(16).hex()))
            db.session.add(user)
            db.session.commit()

    if user:
        session["user"] = user.username
        flash(f"✅ Logged in as {user.username}", "success")
        return redirect(url_for("dashboard"))

    flash("❌ OAuth login failed. Try again.", "danger")
    return redirect(url_for("login"))

# ----------------- Dashboard -----------------
@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=username)

# ----------------- Submit Case -----------------
@app.route("/submit", methods=["GET", "POST"])
def submit():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        issue_type = request.form.get("issue_type")
        amount_lost = request.form.get("amount_lost")
        transaction_id = request.form.get("transaction_id")
        notes = request.form.get("notes")

        try:
            msg = Message(
                subject="New Case Submission",
                sender="noreply@cryptoguard.com",
                recipients=["company@example.com"]
            )
            msg.body = f"""
New Case Submitted by {username}

Type: {issue_type}
Amount Lost: ${amount_lost}
Wallet / Tx ID: {transaction_id}
Notes: {notes}
"""
            mail.send(msg)
            flash("✅ Case submitted successfully. Our team will review it shortly.", "success")
        except Exception as e:
            flash("⚠️ Case saved, but failed to send email notification.", "danger")

        return redirect(url_for("dashboard"))

    return render_template("submit.html")

# ----------------- Withdrawal Route -----------------
@app.route("/withdrawal", methods=["GET", "POST"])
def withdrawal():
    # ⚠️ Removed login/session check (no need to be logged in)
    
    # Instead of session, we will just get the first user for demo/testing
    user = User.query.first()  # Or use any logic to load a test user
    if not user:
        flash("No user found in the database. Please create an account first.", "danger")
        return redirect(url_for("register"))

    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            flash("Invalid amount entered.", "danger")
            return redirect(url_for("withdrawal"))

        method = request.form.get("method")  # "bank" or "crypto"
        destination = request.form.get("destination")
        bank_code = request.form.get("bank_code", "")
        currency = request.form.get("currency", "NGN")

        if amount <= 0:
            flash("Invalid withdrawal amount.", "danger")
            return redirect(url_for("withdrawal"))

        # -------- BANK WITHDRAWALS (NGN) --------
        if method == "bank":
            if user.ngn_balance < amount:
                flash("Insufficient NGN balance.", "danger")
                return redirect(url_for("withdrawal"))

            result = send_bank_transfer(amount, destination, bank_code)

            if result["status"] == "success":
                user.ngn_balance -= amount
                db.session.commit()
                flash(f"✅ Withdrawal of ₦{amount} successful! Money on the way.", "success")
            else:
                flash(f"❌ Bank transfer failed: {result['message']}", "danger")

        # -------- CRYPTO WITHDRAWALS --------
        elif method == "crypto":
            if currency == "BTC" and user.btc_balance < amount:
                flash("Insufficient BTC balance.", "danger")
                return redirect(url_for("withdrawal"))
            elif currency == "ETH" and user.eth_balance < amount:
                flash("Insufficient ETH balance.", "danger")
                return redirect(url_for("withdrawal"))
            elif currency == "USDT" and user.usdt_balance < amount:
                flash("Insufficient USDT balance.", "danger")
                return redirect(url_for("withdrawal"))

            result = send_crypto(currency, destination, amount)

            if result["status"] == "success":
                if currency == "BTC":
                    user.btc_balance -= amount
                elif currency == "ETH":
                    user.eth_balance -= amount
                elif currency == "USDT":
                    user.usdt_balance -= amount

                db.session.commit()
                flash(f"✅ {currency} withdrawal successful!", "success")
            else:
                flash(f"❌ Crypto withdrawal failed: {result['message']}", "danger")

        else:
            flash("Invalid withdrawal method.", "danger")

        return redirect(url_for("withdrawal"))

    # Render withdrawal form directly (no login needed)
    return render_template("withdrawal.html", user=user, balances={
        "ngn": user.ngn_balance,
        "btc": user.btc_balance,
        "eth": user.eth_balance,
        "usdt": user.usdt_balance
    })
# ----------------- Wallet -----------------
# ----------------- Wallet Routes -----------------
@app.route("/wallet")
def wallet():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    # Get user from database
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("login"))

    # Auto-create wallet addresses if they don't exist
    if not user.btc_address:
        user.btc_address = create_btc_wallet()
    if not user.eth_address:
        eth_wallet = create_eth_wallet()
        user.eth_address = eth_wallet["address"]
        user.eth_private_key = eth_wallet["private_key"]
    db.session.commit()

    # Build wallet info list for template
    wallets = [
        {"coin": "BTC", "name": "Bitcoin", "balance": user.btc_balance, "address": user.btc_address},
        {"coin": "ETH", "name": "Ethereum", "balance": user.eth_balance, "address": user.eth_address},
        {"coin": "USDT", "name": "Tether", "balance": user.usdt_balance, "address": user.eth_address},  # USDT uses ETH address
    ]

    # Simple portfolio distribution (for charts)
    portfolio = [{"coin": w["coin"], "balance": w["balance"]} for w in wallets]

    # Example market trends (could be dynamic later)
    market_trends = [
        {"coin": "BTC", "price": 27300, "change": "+2.5%"},
        {"coin": "ETH", "price": 1800, "change": "-1.2%"},
        {"coin": "USDT", "price": 1.0, "change": "0%"},
    ]

    return render_template(
        "wallet.html",
        wallets=wallets,
        portfolio=portfolio,
        market_trends=market_trends,
        user=username
    )

@app.route("/wallet/receive", methods=["POST"])
def receive_funds():
    username = session.get("user")
    if not username:
        return jsonify({"status": "error", "message": "Login required"}), 401

    data = request.json
    coin = data.get("coin")
    try:
        amount = float(data.get("amount", 0))
    except:
        return jsonify({"status": "error", "message": "Invalid amount"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Update balance based on coin type
    if coin == "BTC":
        user.btc_balance += amount
    elif coin == "ETH":
        user.eth_balance += amount
    elif coin == "USDT":
        user.usdt_balance += amount
    else:
        return jsonify({"status": "error", "message": "Unsupported coin"}), 400

    db.session.commit()
    return jsonify({"status": "success", "message": f"{amount} {coin} added to wallet!"})

@app.route("/wallet/send", methods=["POST"])
def send_funds():
    username = session.get("user")
    if not username:
        return jsonify({"status": "error", "message": "Login required"}), 401

    data = request.json
    coin = data.get("coin")
    to_address = data.get("to_address")
    try:
        amount = float(data.get("amount", 0))
    except:
        return jsonify({"status": "error", "message": "Invalid amount"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Check balances before sending
    if coin == "ETH" and user.eth_balance < amount:
        return jsonify({"status": "error", "message": "Insufficient ETH balance"}), 400

    if coin == "ETH":
        # Send ETH using Web3
        w3 = Web3(Web3.HTTPProvider(os.getenv("WEB3_PROVIDER", "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID")))
        acct = w3.eth.account.from_key(user.eth_private_key)

        tx = {
            "nonce": w3.eth.get_transaction_count(acct.address),
            "to": to_address,
            "value": w3.to_wei(amount, "ether"),
            "gas": 21000,
            "gasPrice": w3.to_wei("20", "gwei"),
        }

        signed_tx = w3.eth.account.sign_transaction(tx, user.eth_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        # Deduct balance and save
        user.eth_balance -= amount
        db.session.commit()

        return jsonify({"status": "success", "tx_hash": tx_hash.hex()})

    return jsonify({"status": "error", "message": "Only ETH transfers are supported right now"}), 400

# ----------------- Activity -----------------
@app.route("/activity")
def activity():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    # Example: full user activity
    activities = [
        {"type": "case", "details": "Phishing Scam", "amount": "$1200", "date": "Yesterday"},
        {"type": "withdraw", "details": "BTC → ETH", "amount": "0.5 BTC", "date": "10:15 AM"},
        {"type": "swap", "details": "ETH → USDT", "amount": "2 ETH", "date": "Yesterday"},
        {"type": "withdraw", "details": "USDT", "amount": "1500 USDT", "date": "09:45 AM"},
        {"type": "case", "details": "Exchange Hack", "amount": "$5000", "date": "3 days ago"},
        {"type": "swap", "details": "USDT → BTC", "amount": "3000 USDT", "date": "3 days ago"},
        {"type": "swap", "details": "ETH", "amount": "1.5 ETH", "date": "1 week ago"},
    ]

    return render_template("activity.html", activities=activities, user=username)

@app.route("/track")
def track():
    # Ensure the user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    cases = Case.query.filter_by(user_id=user_id).order_by(Case.id.asc()).all()
    return render_template("track.html", cases=cases)

# ----------------- Helper -----------------
def send_email(to_email, code, purpose="password_reset"):
    try:
        msg = Message("Password Reset Code", recipients=[to_email])
        msg.body = f"Your reset code is: {code}" if purpose == "password_reset" else str(code)
        mail.send(msg)
    except Exception as e:
        print("❌ Error sending email:", e)

# ----------------- Run App -----------------
if __name__ == "__main__":
    with app.app_context():
        if os.getenv("RESET_DB") == "1":
            db.drop_all()
            db.create_all()
        else:
            ensure_schema()
    app.run(debug=True)
