from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from .models import User

class LoginForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('パスワード', validators=[DataRequired()])
    remember_me = BooleanField('ログイン状態を保持')
    submit = SubmitField('ログイン')

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('現在のパスワード', validators=[DataRequired()])
    new_password = PasswordField('新しいパスワード', validators=[
        DataRequired(), 
        Length(min=8, message='パスワードは8文字以上である必要があります')
    ])
    confirm_password = PasswordField('新しいパスワード（確認）', validators=[
        DataRequired(),
        EqualTo('new_password', message='パスワードが一致しません')
    ])
    submit = SubmitField('パスワードを変更')

class TOTPSetupForm(FlaskForm):
    token = StringField('認証コード', validators=[
        DataRequired(), 
        Length(min=6, max=6, message='認証コードは6桁です')
    ])
    submit = SubmitField('2FA を有効化')

class TOTPVerifyForm(FlaskForm):
    token = StringField('認証コード', validators=[
        DataRequired(), 
        Length(min=6, max=6, message='認証コードは6桁です')
    ])
    submit = SubmitField('認証')

class UserCreateForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('初期パスワード', validators=[
        DataRequired(), 
        Length(min=8, message='パスワードは8文字以上である必要があります')
    ])
    is_admin = BooleanField('管理者権限')
    submit = SubmitField('ユーザーを作成')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('このユーザー名は既に使用されています')