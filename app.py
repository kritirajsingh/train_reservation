from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_default_secret_key')

# Configure MySQL database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'mysql+mysqlconnector://root:pass@localhost/reservation')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True  # Enable SQLAlchemy echo for debugging

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    bookings = db.relationship('Booking', back_populates='user')

class Train(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    number = db.Column(db.String(50), nullable=False, unique=True)
    from_destination = db.Column(db.String(150), nullable=False)
    to_destination = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bookings = db.relationship('Booking', back_populates='train')

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    mobile_number = db.Column(db.String(50))
    address = db.Column(db.Text)
    valid_id = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    bookings = db.relationship('Booking', back_populates='customer')
    
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    train_id = db.Column(db.Integer, db.ForeignKey('train.id'), nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='bookings')
    customer = db.relationship('Customer', back_populates='bookings')
    train = db.relationship('Train', back_populates='bookings')


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('User already exists!', 'danger')
            return redirect(url_for('signup'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            print(f"Exception: {e}")  # Print exception for debugging
            return redirect(url_for('signup'))
    return render_template('index.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email and password are provided
        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return redirect(url_for('signin'))

        # Fetch the user by email
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('signin'))  # Redirect back to sign-in page

    return render_template('index.html')



@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('signin'))
    
    return render_template('dashboard.html')

@app.route('/manage_customers', methods=['GET', 'POST'])
def manage_customers():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('signin'))
    
    user_id = session['user_id']  # Get the logged-in user's ID

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        mobile_number = request.form.get('mobile_number')
        address = request.form.get('address')
        valid_id = request.form.get('valid_id')

        # Server-side validation
        if not re.match(r'^[A-Za-z]+$', first_name):
            flash('First name should contain only letters.', 'danger')
            return redirect(url_for('manage_customers'))
        if not re.match(r'^[A-Za-z]+$', last_name):
            flash('Last name should contain only letters.', 'danger')
            return redirect(url_for('manage_customers'))
        if not re.match(r'^\d{10}$', mobile_number):
            flash('Mobile number should be exactly 10 digits.', 'danger')
            return redirect(url_for('manage_customers'))
        
        new_customer = Customer(first_name=first_name, last_name=last_name, mobile_number=mobile_number, address=address, valid_id=valid_id, user_id=user_id)
        
        try:
            db.session.add(new_customer)
            db.session.commit()
            flash('Customer added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

        return redirect(url_for('manage_customers'))

    # Fetch only the customers added by the logged-in user
    customers = Customer.query.filter_by(user_id=user_id).all()
    return render_template('manage_customers.html', customers=customers)

@app.route('/manage_trains', methods=['GET', 'POST'])
def manage_trains():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('signin'))
    
    user_id = session['user_id']  # Get the logged-in user's ID

    if request.method == 'POST':
        name = request.form['name']
        number = request.form['number']
        from_destination = request.form['from_destination']
        to_destination = request.form['to_destination']
        date = request.form['date']

        # Validation checks
        if not re.match("^[A-Za-z ]+$", name):
            flash("Train name should contain only letters.", "danger")
        elif not re.match("^[0-9]+$", number):
            flash("Train number should contain only digits.", "danger")
        elif not re.match("^[A-Za-z ]+$", from_destination) or not re.match("^[A-Za-z ]+$", to_destination):
            flash("Destination fields should contain only letters.", "danger")
        else:
            new_train = Train(name=name, number=number, from_destination=from_destination, to_destination=to_destination, date=date, user_id=user_id)
            try:
                db.session.add(new_train)
                db.session.commit()
                flash("Train added successfully!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {e}', 'danger')

            return redirect(url_for('manage_trains'))

    # Fetch only the trains added by the logged-in user
    trains = Train.query.filter_by(user_id=user_id).all()
    return render_template('manage_trains.html', trains=trains)

@app.route('/manage_payment', methods=['GET', 'POST'])
def manage_payment():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('signin'))

    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        flash(f'Payment method {payment_method} selected.', 'success')
        # Add any additional handling or database storage logic here

    return render_template('manage_payment.html')

@app.route('/website_info')
def website_info():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('signin'))
    # Fetch and display website information
    return render_template('website_info.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    from flask_migrate import Migrate
    migrate = Migrate(app, db)
    
    app.run(debug=True)
