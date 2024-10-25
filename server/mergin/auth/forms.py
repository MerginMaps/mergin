# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

import safe
from flask_wtf import FlaskForm
from sqlalchemy import func
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import (
    DataRequired,
    Optional,
    Length,
    ValidationError,
    Email,
    EqualTo,
)

from .models import User
from ..app import UpdateForm, CustomStringField
from .utils import is_email_address_valid


def username_validation(form, field):
    from ..sync.utils import is_name_allowed

    if field.data and (not is_name_allowed(field.data) or "@" in field.data):
        raise ValidationError(
            f"Please don't start username with . and "
            f"use only alphanumeric or these -._! characters in {field.name}."
        )


class PasswordValidator:
    def __init__(self, min_length=8):
        self.min_length = min_length

    def __call__(self, form, field):
        if len(field.data) < self.min_length:
            raise ValidationError(
                "Passwords must be at least {} characters long.".format(self.min_length)
            )

        strength = safe.check(field.data, self.min_length)
        if not bool(strength):
            raise ValidationError("Password is not strong enough")


class LoginForm(FlaskForm):
    """Form with username and password fields for user to sign in."""

    login = CustomStringField(validators=[DataRequired(), Length(max=80)])
    password = PasswordField(validators=[DataRequired()])


class RegisterUserForm(FlaskForm):
    username = CustomStringField(
        "Username",
        validators=[validators.Length(min=4, max=25), username_validation],
    )
    email = CustomStringField(
        "Email Address",
        validators=[DataRequired(), Email()],
    )

    def validate(self):
        if not super().validate():
            return False
        if not is_email_address_valid(self.email.data):
            self.email.errors.append("Email address contains non-ASCII characters. Only ASCII emails are allowed.")
            return False

        user = User.query.filter(
            (func.lower(User.username) == func.lower(self.username.data.strip()))
            | (func.lower(User.email) == func.lower(self.email.data.strip()))
        ).first()
        if user:
            if user.username.lower() == self.username.data.lower().strip():
                self.username.errors.append("Already exists")
            if user.email.lower() == self.email.data.lower().strip():
                self.email.errors.append("Already exists")
            return False
        return True


class ResetPasswordForm(FlaskForm):
    email = CustomStringField(
        "Email Address",
        [DataRequired(), Email()],
    )


class UserPasswordForm(FlaskForm):
    password = PasswordField(
        "Password", [DataRequired(), PasswordValidator(min_length=8)]
    )
    confirm = PasswordField(
        "Confirm password",
        [DataRequired(), EqualTo("password", message="Passwords must match")],
    )


class UserRegistrationForm(RegisterUserForm, UserPasswordForm):
    pass


class UserChangePasswordForm(UserPasswordForm):
    old_password = StringField("Old Password", [DataRequired()])


class UserForm(UpdateForm):
    """Form to update user private props"""

    is_admin = BooleanField("Admin", [Optional()])
    active = BooleanField("Active", [Optional()])


class UserProfileDataForm(UpdateForm):
    """This form is for user profile update"""

    receive_notifications = BooleanField("Receive notifications", [Optional()])
    first_name = CustomStringField("First Name", [Optional()])
    last_name = CustomStringField("Last Name", [Optional()])
    email = CustomStringField("Email", [Optional(), Email()])


class ApiLoginForm(LoginForm):
    class Meta:
        csrf = False
        load_instance = True
