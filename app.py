from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, DecimalField, PasswordField, SelectField
from wtforms.validators import DataRequired, Length, NumberRange, Email, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import os
import secrets
from PIL import Image

app = Flask(__name__)
# IMPORTANT: Change this to a strong, random key!
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_this_in_production_really'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Sets the view function for the login page
login_manager.login_message_category = 'info'


# This decorator is required by Flask-Login to load a user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# New Database Model for an Exchange Offer
class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # Can be 'pending', 'accepted', 'declined'

    # Relationships
    proposer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    offered_item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    desired_item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)

    def __repr__(self):
        return f"Offer(Proposer: {self.proposer_id}, Offered: {self.offered_item_id}, Desired: {self.desired_item_id}, Status: {self.status})"


# Update the User model to have an 'offers_made' relationship
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    items = db.relationship('Item', backref='author', lazy=True)
    offers_made = db.relationship('Offer', foreign_keys=[Offer.proposer_id], backref='proposer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


# Update the Item model to have a 'offers' relationship
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price_estimate = db.Column(db.Float, nullable=True)
    desired_exchange = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships for offers
    offered_on = db.relationship('Offer', foreign_keys=[Offer.desired_item_id], backref='desired_item', lazy=True)
    offered_by = db.relationship('Offer', foreign_keys=[Offer.offered_item_id], backref='offered_item', lazy=True)

    def __repr__(self):
        return f"Item('{self.name}', '{self.price_estimate}')"


# Helper function to save uploaded pictures
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)

    output_size = (500, 500)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


# New Form for making an offer
class OfferForm(FlaskForm):
    # This field will be populated dynamically in our route
    offered_item = SelectField('Your Item to Offer', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Submit Offer')


# Forms for Registration and Login
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # Custom validators to check for existing users
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class PostItemForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price_estimate = DecimalField('Estimated Value (Optional, for cash difference)', validators=[NumberRange(min=0)],
                                  places=2, render_kw={"placeholder": "e.g., 50.00"})
    desired_exchange = TextAreaField('What are you looking for in exchange?', validators=[DataRequired()])
    picture = FileField('Upload Item Image (Optional)',
                        validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Post Item')


# Route for the homepage
@app.route('/')
def index():
    items = Item.query.all()
    return render_template('index.html', items=items)


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)


# Route for user logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# Route for posting a new item (UPDATED with @login_required)
@app.route('/post_item', methods=['GET', 'POST'])
@login_required  # Requires a logged-in user to access this route
def post_item():
    form = PostItemForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
        else:
            picture_file = 'default.jpg'

        item = Item(
            name=form.name.data,
            description=form.description.data,
            price_estimate=form.price_estimate.data,
            desired_exchange=form.desired_exchange.data,
            image_file=picture_file,
            author=current_user  # Assigns the current user as the item's author
        )
        db.session.add(item)
        db.session.commit()
        flash('Your item has been posted!', 'success')
        return redirect(url_for('index'))
    return render_template('post_item.html', title='Post New Item', form=form)


# Route for an individual item's page
@app.route('/item/<int:item_id>')
def item_page(item_id):
    item = Item.query.get_or_404(item_id)  # Get the item by ID or return a 404 error
    return render_template('item.html', title=item.name, item=item)


# Route for a user to make an offer on an item
@app.route('/item/<int:item_id>/offer', methods=['GET', 'POST'])
@login_required
def make_offer(item_id):
    desired_item = Item.query.get_or_404(item_id)

    # Check if the user is the author of the item
    if desired_item.author == current_user:
        flash('You cannot make an offer on your own item.', 'warning')
        return redirect(url_for('item_page', item_id=item_id))

    # The choices for our select field will be the current user's items
    form = OfferForm()
    form.offered_item.choices = [(item.id, item.name) for item in current_user.items if item.id != desired_item.id]

    if form.validate_on_submit():
        offered_item = Item.query.get(form.offered_item.data)
        if offered_item:
            offer = Offer(
                proposer=current_user,
                offered_item=offered_item,
                desired_item=desired_item
            )
            db.session.add(offer)
            db.session.commit()
            flash('Your offer has been submitted!', 'success')
            return redirect(url_for('item_page', item_id=desired_item.id))
        else:
            flash('Invalid item selected for the offer.', 'danger')

    return render_template('offer_form.html', title=f"Make Offer on {desired_item.name}", form=form,
                           desired_item=desired_item)


# Route for a user's profile page
@app.route('/user/<string:username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    items = user.items
    return render_template('user_profile.html', user=user, items=items, title=f"{user.username}'s Profile")


# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
