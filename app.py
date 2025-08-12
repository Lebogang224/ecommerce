import os
import re
import bleach
from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from sqlalchemy import func
import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ecommerce.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    stock = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50))

class CartItem(db.Model):
    __tablename__ = 'cart_item'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    payment_method = db.Column(db.String(50))
    phone = db.Column(db.String(20), nullable=True) # Added phone number field
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    
# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=50), 
        Regexp(r'^[a-zA-Z0-9_]+$', message="Letters, numbers and underscores only")
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$', 
               message="At least 8 characters with 1 letter and 1 number")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), 
        EqualTo('password', message='Passwords do not match')
    ])
    submit = SubmitField('Register')  

# Routes
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check for existing username
        if User.query.filter_by(username=form.username.data).first():
            flash('Username taken', 'danger')
            return render_template('register.html', form=form)
            
        # Check for existing email
        if User.query.filter_by(email=form.email.data).first():
            flash('Email taken', 'danger')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(username=form.username.data, 
                    email=form.email.data, 
                    is_admin=False)
        try:
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registered successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error registering: {str(e)}', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('home'))

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    if product.stock <= 0:
        flash('Out of stock', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    quantity = int(request.form.get('quantity', 1))
    if quantity > product.stock:
        quantity = product.stock
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
    db.session.add(cart_item)
    db.session.commit()
    flash('Added to cart', 'success')
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    cart_items = current_user.cart_items
    total = sum(item.quantity * item.product.price for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/update_cart/<int:item_id>', methods=['POST'])
@login_required
def update_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id != current_user.id:
        abort(403)
    quantity = int(request.form['quantity'])
    if quantity <= 0:
        db.session.delete(cart_item)
    else:
        cart_item.quantity = quantity
    db.session.commit()
    flash('Cart updated', 'success')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id != current_user.id:
        abort(403)
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = current_user.cart_items
    if not cart_items:
        flash('Cart empty', 'info')
        return redirect(url_for('cart'))
    total = sum(item.quantity * item.product.price for item in cart_items)
    if request.method == 'POST':
        payment_method = request.form['payment_method']
        phone = request.form.get('phone') # Get phone number
        
        # Create the order with the phone number
        order = Order(user_id=current_user.id, 
                      total=total, 
                      payment_method=payment_method, 
                      phone=phone)
                      
        db.session.add(order)
        for item in cart_items:
            item.product.stock -= item.quantity
            db.session.delete(item)
        db.session.commit()
        flash('Order placed', 'success')
        return redirect(url_for('order_confirmation', order_id=order.id))
    return render_template('checkout.html', total=total)

@app.route('/order_confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return render_template('order_confirmation.html', order=order)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    products = Product.query.all()
    users = User.query.all()
    orders = Order.query.all()
    return render_template('admin.html', products=products, users=users, orders=orders)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        stock = int(request.form['stock'])
        category = request.form['category']
        image_url = request.form.get('image_url', '')
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = 'uploads/' + filename
        product = Product(name=name, price=price, description=description, image_url=image_url, stock=stock, category=category)
        db.session.add(product)
        db.session.commit()
        flash('Product added', 'success')
        return redirect(url_for('admin'))
    return render_template('add_product.html', product=None)

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        abort(403)
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.description = request.form['description']
        product.stock = int(request.form['stock'])
        product.category = request.form['category']
        image_url = request.form.get('image_url', '')
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_url = 'uploads/' + filename
        elif image_url:
            product.image_url = image_url
        db.session.commit()
        flash('Product updated', 'success')
        return redirect(url_for('admin'))
    return render_template('add_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        abort(403)
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted', 'success')
    return redirect(url_for('admin'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email', '')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click this link to reset your password: {reset_url}'
            try:
                mail.send(msg)
                flash('Reset link sent to your email', 'info')
            except Exception as e:
                app.logger.error(f'Email send error: {str(e)}')
                flash('Error sending reset email', 'danger')
        else:
            flash('Email not found', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('Invalid or expired link', 'danger')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)
        if len(password) < 8 or not re.search(r'\d', password) or not re.search(r'[a-zA-Z]', password):
            flash('Password must be at least 8 characters with letters and numbers', 'danger')
            return redirect(request.url)
        try:
            user.set_password(password)
            db.session.commit()
            flash('Password updated. Log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Password reset error: {str(e)}')
            flash('Error occurred', 'danger')
    return render_template('reset_password.html')

# Initialize Database
def create_admin_user():
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')
    if not admin_email or not admin_password:
        return
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(username='admin', email=admin_email, is_admin=True)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()

def create_sample_products():
    if Product.query.count() == 0:
        products = [
            Product(name="Sylvia's Homemade Atchar", price=55.00, description="Delicious homemade Atchar mix with a perfect blend of spices and fresh Atchar, made by Sylvia", image_url="uploads/Atchar.jpg", stock=50, category="Food"),
            Product(name="Sylvia's Homemade Chillies", price=50.00, description="Delicious homemade chilli mix with a perfect blend of spices and fresh chillies, made by Sylvia.", image_url="uploads/chillies.jpg", stock=20, category="Food")
        ]
        db.session.bulk_save_objects(products)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
        create_sample_products()
    app.run(debug=True)