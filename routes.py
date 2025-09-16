from flask import render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from app import app, db
from models import User, Message
from forms import RegistrationForm, LoginForm, MessageForm, DecryptForm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.security import check_password_hash
import base64

@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get messages for the current user
    received_messages = Message.query.filter_by(recipient_id=current_user.id)\
        .order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.id)\
        .order_by(Message.timestamp.desc()).all()
    
    return render_template('dashboard.html', 
                         received_messages=received_messages, 
                         sent_messages=sent_messages)

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    if form.validate_on_submit():
        # Find recipient
        recipient = User.query.filter_by(username=form.recipient.data).first()
        if not recipient:
            flash('Recipient not found.', 'danger')
            return render_template('send_message.html', title='Send Message', form=form)
        
        if recipient.id == current_user.id:
            flash('You cannot send a message to yourself.', 'warning')
            return render_template('send_message.html', title='Send Message', form=form)
        
        try:
            # 💡 CRITICAL FIX: Encrypt using RECIPIENT'S key, not sender's
            # Prompt sender to enter RECIPIENT'S password? ❌ No — that's bad UX and insecure.
            # Instead, we'll ask sender to enter THEIR OWN password for auth,
            # but encrypt with recipient's key derived from recipient's SALT (which is public)
            
            # Get recipient's salt (public info)
            recipient_salt = recipient.salt.encode('utf-8')
            
            # Derive key using recipient's salt + recipient's password
            # BUT — we don't have recipient's password! So we need a different approach.
            
            # 🆕 NEW APPROACH: Ask sender to enter RECIPIENT'S PASSWORD to encrypt
            # (This is not ideal for real-world, but works for demo)
            # In production, use public-key crypto (RSA/ECC)
            
            recipient_password = request.form.get('recipient_password')
            if not recipient_password:
                flash('Please enter the recipient\'s password to encrypt the message.', 'warning')
                return render_template('send_message.html', title='Send Message', form=form, ask_recipient_password=True)
            
            # Generate key using recipient's salt + recipient's password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=recipient_salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(recipient_password.encode()))
            fernet = Fernet(key)
            
            # Encrypt the message
            encrypted_content = fernet.encrypt(form.content.data.encode()).decode()
            
            # Create and save message
            message = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                encrypted_content=encrypted_content
            )
            db.session.add(message)
            db.session.commit()
            
            flash('Message sent successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error sending message: {str(e)}', 'danger')
    
    # Check if we need to show recipient password field
    ask_recipient_password = request.args.get('ask_recipient_password') == '1'
    return render_template('send_message.html', 
                         title='Send Message', 
                         form=form, 
                         ask_recipient_password=ask_recipient_password)

@app.route('/message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    # Check if current user is the recipient or sender
    if current_user.id != message.recipient_id and current_user.id != message.sender_id:
        abort(403)
    
    # Mark as read if current user is recipient
    if current_user.id == message.recipient_id and not message.is_read:
        message.is_read = True
        db.session.commit()
    
    form = DecryptForm()
    decrypted_content = None
    decryption_error = None
    
    if form.validate_on_submit():
        try:
            # 💡 Use CURRENT USER's password to derive key
            # If user is recipient → uses their password → matches encryption key
            # If user is sender → uses their password → WON'T WORK (by design)
            encryption_key = current_user.get_encryption_key(form.password.data)
            fernet = Fernet(encryption_key)
            
            # Decrypt message
            decrypted_content = fernet.decrypt(message.encrypted_content.encode()).decode()
            
        except InvalidToken:
            decryption_error = "Invalid password. Make sure you're using the correct password for this account."
        except Exception as e:
            decryption_error = f"Decryption failed: {str(e)}"
    
    return render_template('view_message.html', 
                         message=message, 
                         form=form, 
                         decrypted_content=decrypted_content,
                         decryption_error=decryption_error)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    # Check if current user is the sender or recipient
    if current_user.id != message.sender_id and current_user.id != message.recipient_id:
        abort(403)
    
    db.session.delete(message)
    db.session.commit()
    flash('Message deleted successfully.', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/api/messages')
@login_required
def api_messages():
    """API endpoint to get messages (for potential AJAX use)"""
    received = [{
        'id': msg.id,
        'sender': msg.sender.username,
        'timestamp': msg.timestamp.isoformat(),
        'is_read': msg.is_read
    } for msg in Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()]
    
    sent = [{
        'id': msg.id,
        'recipient': msg.recipient.username,
        'timestamp': msg.timestamp.isoformat(),
        'is_read': msg.is_read
    } for msg in Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()]
    
    return jsonify({
        'received': received,
        'sent': sent
    })

# Login manager user loader
from app import login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))