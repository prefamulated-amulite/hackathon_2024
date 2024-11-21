from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import os
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    SelectField,
    FileField,
    BooleanField,
)
from wtforms.validators import InputRequired, Length, Email, ValidationError, EqualTo

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"  # Replace with your own secret key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["UPLOAD_FOLDER"] = "uploads"

# Email configuration
app.config["MAIL_SERVER"] = "smtp.example.com"  # Replace with your SMTP server
app.config["MAIL_PORT"] = 587  # Replace with your Mail port
app.config["MAIL_USERNAME"] = "your_email@example.com"  # Replace with your email
app.config["MAIL_PASSWORD"] = "your_password"  # Replace with your email password
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
mail = Mail(app)

# Ensure upload folder exists
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Available time slots
TIME_SLOTS = [
    "10:00 - 10:15 AM",
    "10:15 - 10:30 AM",
    "10:30 - 10:45 AM",
    "10:45 - 11:00 AM",
    "11:00 - 11:15 AM",
    "11:15 - 11:30 AM",
    # Add more time slots as needed
]

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150))  # For employees and admins
    is_employee = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    registrations = db.relationship("Registration", backref="user", lazy=True)

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute.")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_slot = db.Column(db.String(50), nullable=False)
    cv_filename = db.Column(db.String(100), nullable=False)
    cover_letter_filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)


# Forms
class CandidateRegistrationForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    name = StringField("Name", validators=[InputRequired(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[InputRequired(), EqualTo("password")]
    )
    time_slot = SelectField("Select Time Slot", choices=[])
    cv = FileField("Upload CV (PDF)", validators=[InputRequired()])
    cover_letter = FileField("Upload Cover Letter (PDF)", validators=[InputRequired()])
    submit = SubmitField("Register")

    def validate_email(self, email):
        try:
            validate_email(email.data)
        except EmailNotValidError as e:
            raise ValidationError(str(e))
        
class CandidateIntrestForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    name = StringField("Name", validators=[InputRequired(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[InputRequired(), EqualTo("password")]
    )
    cv = FileField("Upload CV (PDF)", validators=[InputRequired()])
    cover_letter = FileField("Upload Cover Letter (PDF)", validators=[InputRequired()])
    submit = SubmitField("Register")

    def validate_email(self, email):
        try:
            validate_email(email.data)
        except EmailNotValidError as e:
            raise ValidationError(str(e))


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    submit = SubmitField("Login")


class EmployeeLoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    submit = SubmitField("Login")


class AdminRegistrationForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[InputRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")


class EmployeeCreationForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=4, max=80)]
    )
    is_admin = BooleanField("Is Admin")
    submit = SubmitField("Create Employee")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Routes
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/admin_register", methods=["GET", "POST"])
def admin_register():
    # Check if an admin already exists
    admin_exists = User.query.filter_by(is_admin=True).first()
    if admin_exists:
        flash("Admin account already exists. Please log in.", "danger")
        return redirect(url_for("employee_login"))

    form = AdminRegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Create admin user
        admin_user = User(email=email, is_employee=True, is_admin=True)
        admin_user.password = password
        db.session.add(admin_user)
        db.session.commit()

        flash("Admin account created. You can now log in.", "success")
        return redirect(url_for("employee_login"))

    return render_template("admin_register.html", form=form)


@app.route("/create_employee", methods=["GET", "POST"])
@login_required
def create_employee():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("employee_dashboard"))

    form = EmployeeCreationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        is_admin = form.is_admin.data

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("User with this email already exists.", "danger")
            return redirect(url_for("create_employee"))

        # Create new employee
        new_employee = User(email=email, is_employee=True, is_admin=is_admin)
        new_employee.password = password
        db.session.add(new_employee)
        db.session.commit()

        flash("Employee account created.", "success")
        return redirect(url_for("employee_dashboard"))

    return render_template("create_employee.html", form=form)

@app.route("/register_intrest",  methods=["GET", "POST"])
def register_intrest():
    form = CandidateIntrestForm()
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        password = form.password.data
        cv_file = form.cv.data
        cover_letter_file = form.cover_letter.data

        # Save uploaded files
        cv_filename = secure_filename(cv_file.filename)
        cover_letter_filename = secure_filename(cover_letter_file.filename)
        cv_file.save(os.path.join(app.config["UPLOAD_FOLDER"], cv_filename))
        cover_letter_file.save(
            os.path.join(app.config["UPLOAD_FOLDER"], cover_letter_filename)
        )

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            user.password = password
            db.session.add(user)
            db.session.commit()
        else:
            flash("An account with this email already exists.", "warning")
            return redirect(url_for("login"))
        flash("Registration successful!", "success")
        return redirect(url_for("home"))
    return render_template("register_intrest.html", form=form)





@app.route("/register", methods=["GET", "POST"])
def register():
    form = CandidateRegistrationForm()
    # Get available time slots
    booked_slots = [reg.time_slot for reg in Registration.query.all()]
    available_slots = [
        (slot, slot) for slot in TIME_SLOTS if slot not in booked_slots
    ]
    form.time_slot.choices = available_slots

    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        password = form.password.data
        time_slot = form.time_slot.data
        cv_file = form.cv.data
        cover_letter_file = form.cover_letter.data

        # Save uploaded files
        cv_filename = secure_filename(cv_file.filename)
        cover_letter_filename = secure_filename(cover_letter_file.filename)
        cv_file.save(os.path.join(app.config["UPLOAD_FOLDER"], cv_filename))
        cover_letter_file.save(
            os.path.join(app.config["UPLOAD_FOLDER"], cover_letter_filename)
        )

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            user.password = password
            db.session.add(user)
            db.session.commit()
        else:
            flash("An account with this email already exists.", "warning")
            return redirect(url_for("login"))

        # Create registration
        registration = Registration(
            time_slot=time_slot,
            cv_filename=cv_filename,
            cover_letter_filename=cover_letter_filename,
            user_id=user.id,
        )
        db.session.add(registration)
        db.session.commit()

        # Send confirmation email
        try:
            msg = Message(
                "Speed Interview Registration Confirmation",
                sender=app.config["MAIL_USERNAME"],
                recipients=[email],
            )
            msg.body = f"Dear {name},\n\nYou have successfully registered for the speed interview.\n\nTime Slot: {time_slot}\n\nBest regards,\nSpeed Interview Team"
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email: {e}")

        flash("Registration successful! A confirmation email has been sent.", "success")
        return redirect(url_for("home"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and user.verify_password(password):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("candidate_dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route("/employee_login", methods=["GET", "POST"])
def employee_login():
    form = EmployeeLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email, is_employee=True).first()
        if user and user.verify_password(password):
            login_user(user)
            flash("Employee login successful.", "success")
            return redirect(url_for("employee_dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("employee_login"))
    return render_template("employee_login.html", form=form)


@app.route("/candidate_dashboard")
@login_required
def candidate_dashboard():
    if current_user.is_employee:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))
    registrations = Registration.query.filter_by(user_id=current_user.id).all()
    return render_template("candidate_dashboard.html", registrations=registrations)


@app.route("/employee_dashboard")
@login_required
def employee_dashboard():
    if not current_user.is_employee:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))
    registrations = Registration.query.all()
    return render_template("employee_dashboard.html", registrations=registrations)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    if not current_user.is_employee:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    with app.app_context():
        if not os.path.exists("database.db"):
            db.create_all()
            print("Database created.")
    app.run(debug=True)
