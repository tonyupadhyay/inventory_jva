# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps # Import wraps for the decorator

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_for_inventory_app_12345')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress SQLAlchemy warning
db = SQLAlchemy(app)

class User(db.Model):
    """
    User model for authentication. Stores username, hashed password, and email.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Store hashed passwords
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Establish a relationship with the Product model
    products = db.relationship('Product', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the hashed password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    """
    Product model for inventory items.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    price = db.Column(db.Float, nullable=False, default=0.0)
    category = db.Column(db.String(50), nullable=True)
    sku = db.Column(db.String(50), unique=True, nullable=True) # Stock Keeping Unit
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Link to User

    def __repr__(self):
        return f'<Product {self.name}>'

# --- Database Initialization (Run once to create tables) ---
# This block ensures tables are created when app.py is executed.
# It also adds a default admin user if no users exist.
with app.app_context():
    db.create_all()
    # Add a default admin user if the database is empty
    if not User.query.first():
        print("Creating default admin user: admin/password")
        admin_user = User(username='admin', email='admin@example.com')
        admin_user.set_password('password') # Set the password for the admin user
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created. Login with username 'admin' and password 'password'.")

# --- Helper function for login required ---
def login_required(f):
    """
    Decorator to protect routes that require user to be logged in.
    Redirects to login page if user is not in session.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
@login_required # Protect the dashboard
def index():
    """
    Displays the main inventory dashboard with a list of all products
    belonging to the currently logged-in user.
    """
    # Filter products by the current user's ID
    products = Product.query.filter_by(user_id=session['user_id']).all()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    """
    if 'user_id' in session: # If already logged in, redirect to dashboard
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Only allow login if the user is the 'admin' user
            if user.username == 'admin':
                session['user_id'] = user.id
                session['username'] = user.username
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Only admin users are allowed to log in.', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')

# The /register route has been removed to prevent new user registrations.
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     ...

@app.route('/logout')
def logout():
    """
    Logs out the current user by clearing the session.
    """
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required # Only logged-in users can add products
def add_product():
    """
    Handles adding new products to the inventory, associating them with the current user.
    """
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])
        category = request.form['category']
        sku = request.form['sku']
        current_user_id = session['user_id'] # Get the ID of the logged-in user

        # Basic validation for SKU uniqueness for the current user
        if sku:
            existing_sku = Product.query.filter_by(sku=sku, user_id=current_user_id).first()
            if existing_sku:
                flash('SKU already exists for your inventory. Please use a unique SKU.', 'danger')
                return render_template('add_edit_product.html', product=None)

        new_product = Product(name=name, description=description,
                              quantity=quantity, price=price,
                              category=category, sku=sku, user_id=current_user_id) # Assign user_id
        db.session.add(new_product)
        db.session.commit()
        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_edit_product.html', product=None) # Pass None for new product

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required # Only logged-in users can edit products
def edit_product(product_id):
    """
    Handles editing existing products, ensuring only the owner can edit.
    """
    product = Product.query.get_or_404(product_id)
    # Ensure the logged-in user owns this product
    if product.user_id != session['user_id']:
        flash('You are not authorized to edit this product.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.quantity = int(request.form['quantity'])
        product.price = float(request.form['price'])
        product.category = request.form['category']
        new_sku = request.form['sku']

        # Check for SKU uniqueness for the current user, excluding the current product's SKU
        if new_sku and new_sku != product.sku:
            existing_sku = Product.query.filter_by(sku=new_sku, user_id=session['user_id']).first()
            if existing_sku:
                flash('SKU already exists for your inventory. Please use a unique SKU.', 'danger')
                return render_template('add_edit_product.html', product=product)

        product.sku = new_sku
        db.session.commit()
        flash(f'Product "{product.name}" updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required # Only logged-in users can delete products
def delete_product(product_id):
    """
    Handles deleting products, ensuring only the owner can delete.
    """
    product = Product.query.get_or_404(product_id)
    # Ensure the logged-in user owns this product
    if product.user_id != session['user_id']:
        flash('You are not authorized to delete this product.', 'danger')
        return redirect(url_for('index'))

    db.session.delete(product)
    db.session.commit()
    flash(f'Product "{product.name}" deleted successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/print_inventory')
@login_required
def print_inventory():
    """
    Generates a print-friendly view of the current user's inventory.
    The user can then use their browser's print-to-PDF function.
    """
    products = Product.query.filter_by(user_id=session['user_id']).all()
    username = session.get('username', 'Admin') # Get username for the report title
    return render_template('inventory_print.html', products=products, username=username)


# --- Run the application ---
if __name__ == '__main__':
    # Ensure necessary folders exist
    if not os.path.exists('static'):
        os.makedirs('static')
    if not os.path.exists('templates'):
        os.makedirs('templates')

    app.run(debug=True) # debug=True is suitable for development
