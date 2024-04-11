import os
from flask_mail import Message, Mail
mail = Mail()

def send_login_notification_email(user_email, deactivation_link):
    msg = Message('!!Warnning!! - Incorrect Login attempts', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Warnning : Someone trying to access your account change \nyour password immediately or click here to deactivate your account:  {deactivation_link}'
    mail.send(msg)
