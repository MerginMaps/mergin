# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

import os
import pytz
from datetime import datetime, timedelta
from connexion import NoContent
from sqlalchemy import func, desc, asc
from sqlalchemy.sql.operators import is_
from flask import request, current_app, jsonify, abort, render_template
from flask_login import login_user, logout_user, current_user
from flask_wtf.csrf import generate_csrf

from .app import (
    auth_required,
    authenticate,
    do_register_user,
    send_confirmation_email,
    confirm_token,
    generate_confirmation_token,
    user_created,
    user_account_closed,
)
from .bearer import encode_token
from .models import User, LoginHistory
from .schemas import UserSchema, UserSearchSchema, UserProfileSchema, UserInfoSchema
from .forms import (
    LoginForm,
    UserPasswordForm,
    ResetPasswordForm,
    UserRegistrationForm,
    UserForm,
    UserProfileDataForm,
    UserChangePasswordForm,
    ApiLoginForm,
)
from .. import db


# public endpoints
def user_profile(user, return_all=True):
    """Return user profile in json format

    Will return just some public profile if not return_all

    :param user: User data that will be returned
    :type user: User

    :return: extended user profile with mergin service info
    :rtype: dict
    """
    data = UserProfileSchema().dump(user.profile)
    data["username"] = user.username
    data["id"] = user.id

    if return_all:
        data.update(
            {
                "email": user.email,
                "storage_limit": data["storage"],  # duplicate - we should remove it
                "receive_notifications": user.profile.receive_notifications,
                "verified_email": user.verified_email,
                "tier": "free",
                "registration_date": user.registration_date,
            }
        )
    return data


@auth_required
def get_user_public(username=None):  # noqa: E501
    """User profile info of logged user
    DEPRECATED endpoint only for backward compatibility.
    Response is the best guess user info in context of workspaces.

     # noqa: E501

    :param username: Username (ignored)
    :type username: str

    :rtype: UserDetail
    """
    user_workspace = current_app.ws_handler.get_by_name(current_user.username)
    all_workspaces = current_app.ws_handler.list_user_workspaces(current_user.username)
    user_info = {
        "username": current_user.username,
        "email": current_user.email,
        "disk_usage": user_workspace.disk_usage() if user_workspace else 0,
        "storage": user_workspace.storage if user_workspace else 104857600,
        "storage_limit": user_workspace.storage if user_workspace else 104857600,
        "organisations": {
            ws.name: ws.get_user_role(current_user) for ws in all_workspaces
        },
    }
    return user_info, 200


def _extract_first_error(errors):
    """
    For now, if the response is plain string,
    InputApp displays it in the nice
    notification window. Extract first error
    and just send that one to client
    """
    for key, value in errors.items():
        val = str(value[0])
        if key.lower() in val.lower():
            # e.g. Passwords must contain special character.
            # in this case we do not need to add key "password"
            # since it is obvious from where it comes from
            return val
        elif val.startswith("Field"):
            # e.g. Field must be longer than 4 characters
            # In this case the generic validator use Field
            # replace with the key (e.g. "Username")
            return val.replace("Field", key.capitalize())
        else:
            # show both key and value
            return val + "(" + key + ")"

    return "Unknown error in input fields"


def login_public():  # noqa: E501
    """Login user.

    Returns session token, expiration time and user profile info # noqa: E501

    :rtype: LoginResponse
    """
    form = ApiLoginForm()
    if form.validate():
        user = authenticate(form.login.data, form.password.data)
        if user and user.active:
            expire = datetime.now(pytz.utc) + timedelta(
                seconds=current_app.config["BEARER_TOKEN_EXPIRATION"]
            )
            token_data = {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "expire": str(expire),
            }
            token = encode_token(current_app.config["SECRET_KEY"], token_data)

            data = user_profile(user)
            data["session"] = {"token": token, "expire": expire}
            LoginHistory.add_record(user.id, request)
            return data
        else:
            abort(401, "Invalid username or password")
    abort(400, _extract_first_error(form.errors))


@auth_required
def close_user_account():
    """Close current user account
    Closing user account effectively means to inactivate user (will be removed by cron job) and remove explicitly
    shared projects as well clean references to created projects.
    """
    current_user.inactivate()
    # emit signal to be caught elsewhere
    user_account_closed.send(current_user)
    return NoContent, 204


# private endpoints
@auth_required
def search_users():  # pylint: disable=W0613,W0612
    """Find active users in workspace by ids, usernames or with ilike pattern using attribute (username/email)."""
    ids = request.args.get("id")
    names = request.args.get("names")
    like = request.args.get("like")
    workspace = current_app.ws_handler.get_by_name(request.args.get("namespace"))
    if not workspace:
        abort(404, "Workspace not found")

    if not workspace.user_is_member(current_user):
        abort(403, "You do not have permissions to search within workspace")

    if ids:
        ids = request.args.get("id")
        try:
            ids = map(int, ids.split(","))
            users_found = (
                User.query.filter(User.id.in_(ids), User.active.is_(True))
                .order_by(User.username)
                .limit(10)
                .all()
            )
        except (ValueError, AttributeError):
            users_found = []
    elif names:
        names = names.split(",")
        users_found = (
            User.query.filter(User.username.in_(names), User.active.is_(True))
            .order_by(User.username)
            .limit(10)
            .all()
        )
    elif like:
        users_found = User.search(like, limit=10, only_active=True)
    else:
        return [], 200

    users = [u for u in users_found if workspace.user_is_member(u)]
    return jsonify(UserSearchSchema(many=True).dump(users)), 200


def login():  # pylint: disable=W0613,W0612
    form = LoginForm()
    if form.validate():
        user = authenticate(form.login.data, form.password.data)
        if user and user.active:
            login_user(user)
            if not os.path.isfile(current_app.config["MAINTENANCE_FILE"]):
                LoginHistory.add_record(user.id, request)
            return "", 200
        else:
            abort(401, "Invalid username or password")
    return jsonify(form.errors), 401


def admin_login():  # pylint: disable=W0613,W0612
    """Login into admin interface"""
    form = LoginForm()
    if not form.validate():
        return jsonify(form.errors), 400

    user = authenticate(form.login.data, form.password.data)
    if user:
        if user.active and user.is_admin:
            login_user(user)
            return "", 200
        else:
            abort(403, "You do not have permissions")
    else:
        abort(401, "Invalid username or password")


@auth_required
def logout():  # pylint: disable=W0613,W0612
    logout_user()
    return "", 200


@auth_required
def change_password():  # pylint: disable=W0613,W0612
    form = UserChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.old_password.data):
            form.old_password.errors.append("The old password is incorrect")
            return jsonify(form.errors), 400
        current_user.assign_password(form.password.data)
        db.session.add(current_user)
        db.session.commit()
        return "", 200
    return jsonify(form.errors), 400


@auth_required
def resend_confirm_email():  # pylint: disable=W0613,W0612
    send_confirmation_email(
        current_app,
        current_user,
        "confirm-email",
        "email/email_confirmation.html",
        "Email confirmation",
    )
    return "", 200


def password_reset():  # pylint: disable=W0613,W0612
    form = ResetPasswordForm()
    if not form.validate():
        return jsonify(form.errors), 400

    user = User.query.filter(
        func.lower(User.email) == func.lower(form.email.data.strip())
    ).one_or_none()
    if not user:
        return jsonify({"email": ["Account with given email does not exist"]}), 404
    if not user.active:
        # user should confirm email first
        return jsonify({"email": ["Account is not active"]}), 400

    send_confirmation_email(
        current_app,
        user,
        "change-password",
        "email/password_reset.html",
        "Password reset",
    )
    return "", 200


def confirm_new_password(token):  # pylint: disable=W0613,W0612
    email = confirm_token(token)
    if not email:
        abort(400, "Invalid token")

    user = User.query.filter_by(email=email).first_or_404()
    if not user.active:
        abort(400, "Account is not active")

    form = UserPasswordForm.from_json(request.json)
    if form.validate():
        user.assign_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return "", 200
    return jsonify(form.errors), 400


def confirm_email(token):  # pylint: disable=W0613,W0612
    email = confirm_token(token)
    if not email:
        abort(400, "Invalid token")

    user = User.query.filter_by(email=email).first_or_404()
    if user.verified_email:
        return "", 200

    if not user.check_password(""):
        user.verified_email = True
        db.session.add(user)
        db.session.commit()

    return "", 200


@auth_required
def update_user_profile():  # pylint: disable=W0613,W0612
    form = UserProfileDataForm.from_json(request.json)
    email_changed = current_user.email != form.email.data.strip()
    if not form.validate_on_submit():
        return jsonify(form.errors), 400
    if email_changed:
        user = User.query.filter(
            func.lower(User.email) == func.lower(form.email.data.strip())
        ).first()
        if user:
            form.email.errors.append("Email already exists")
            return jsonify(form.errors), 400
        current_user.verified_email = False

    form.update_obj(current_user.profile)
    form.update_obj(current_user)
    db.session.add(current_user)
    db.session.commit()
    if email_changed:
        resend_confirm_email()

    return "", 200


@auth_required
def refresh_csrf_token():
    """
    Generate new csrf token, used in case that client ask for new one from reason that old one is expired
    :return: string token
    """
    return jsonify({"csrf": generate_csrf()})


# admin endpoints
@auth_required(permissions=["admin"])
def register_user():  # pylint: disable=W0613,W0612
    """Create new user and send information email"""
    from ..celery import send_email_async

    form = UserRegistrationForm()
    if form.validate():
        user = do_register_user(form.username.data, form.email.data, form.password.data)
        user_created.send(user, source="admin")
        token = generate_confirmation_token(current_app, user.email)
        confirm_url = f"confirm-email/{token}"
        html = render_template(
            "email/user_created.html",
            confirm_url=confirm_url,
            user=user,
            password=form.password.data,
        )
        email_data = {
            "subject": "Invitation to Mergin Maps",
            "html": html,
            "recipients": [user.email],
            "sender": current_app.config["MAIL_DEFAULT_SENDER"],
        }
        send_email_async.delay(**email_data)
        return jsonify(UserSchema().dump(user)), 201

    return jsonify(form.errors), 400


@auth_required(permissions=["admin"])
def get_user(username):
    user = User.query.filter(User.username == username).first_or_404()
    data = UserSchema().dump(user)
    return data, 200


@auth_required(permissions=["admin"])
def update_user(username):  # pylint: disable=W0613,W0612
    form = UserForm.from_json(request.json)
    if not form.validate_on_submit():
        return jsonify(form.errors), 400

    user = User.query.filter_by(username=username).first_or_404("User not found")
    form.update_obj(user)
    # remove inactive since flag for ban or re-activation
    user.inactive_since = None
    db.session.add(user)
    db.session.commit()
    return jsonify(UserSchema().dump(user))


@auth_required(permissions=["admin"])
def delete_user(username):  # pylint: disable=W0613,W0612
    user = User.query.filter_by(username=username).first_or_404("User not found")
    user.inactivate()
    user_account_closed.send(user)
    # force 'delete' user
    user.anonymize()
    return "", 204


@auth_required(permissions=["admin"])
def get_paginated_users(
    page, per_page, order_by=None, descending=False, like=None
):  # noqa: E501
    """List mergin users

    Returns paginated list of users, optionally filtered by username. # noqa: E501

    :param page: page number
    :type page: int
    :param per_page: Number of results per page
    :type per_page: int
    :param order_by: Order by field
    :type order_by: str
    :param descending: Order of sorting
    :type descending: bool
    :param like: Filter users with usernames or emails with ilike pattern
    :type like: str

    :rtype: Dict[str: List[User], str: Integer]
    """
    users = User.query.filter(
        is_(User.username.ilike("deleted_%"), False) | is_(User.active, True)
    )

    if like:
        attr = User.email if "@" in like else User.username
        users = users.filter(attr.ilike(f"%{like}%"))

    if descending and order_by:
        users = users.order_by(desc(User.__table__.c[order_by]))
    elif not descending and order_by:
        users = users.order_by(asc(User.__table__.c[order_by]))

    result = users.paginate(page, per_page).items
    total = users.paginate(page, per_page).total

    result_users = UserSchema(many=True).dump(result)

    data = {"users": result_users, "total": total}
    return data, 200


@auth_required
def get_user_info():
    user_info = UserInfoSchema().dump(current_user)
    workspaces = current_app.ws_handler.list_user_workspaces(current_user.username)
    user_info["workspaces"] = [
        {"id": ws.id, "name": ws.name, "role": ws.get_user_role(current_user)}
        for ws in workspaces
    ]
    preferred_workspace = current_app.ws_handler.get_preferred(current_user)
    user_info["preferred_workspace"] = (
        preferred_workspace.id if preferred_workspace else None
    )
    invitations = current_app.ws_handler.list_user_invitations(current_user)
    user_info["invitations"] = [
        {"uuid": inv.uuid, "workspace": inv.workspace.name, "role": inv.role}
        for inv in invitations
    ]
    return user_info, 200
