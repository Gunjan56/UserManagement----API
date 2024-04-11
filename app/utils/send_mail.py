import os
from flask_mail import Message, Mail
mail = Mail()

def send_reset_password_email(user_email, reset_link):
    msg = Message('Reset Your Password', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Reset your password: {reset_link}'
    mail.send(msg)
