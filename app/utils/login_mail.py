import os
from flask_mail import Message, Mail
mail = Mail()

def send_login_notification_email(user_email):
    msg = Message('!!Warnning!! - Incorrect Login attempts', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Warnning : Someone trying to access your account change \nyour password immediately.'
    mail.send(msg)