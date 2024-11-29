# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

from datetime import datetime, timedelta
import pytest
import json
from flask import url_for
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from unittest.mock import patch

from ..auth.models import User, UserProfile, LoginHistory
from ..auth.tasks import anonymize_removed_users
from .. import db
from ..sync.models import Project
from . import (
    test_workspace_id,
    json_headers,
    DEFAULT_USER,
    test_workspace_name,
    test_project,
)
from .utils import add_user, login_as_admin, login


@pytest.fixture(scope="function")
def client(app):
    client = app.test_client()
    return client


# login tests: success, success with trailing space, success with email login, invalid password, missing password, wrong headers
test_login_data = [
    ({"login": "mergin", "password": "ilovemergin"}, json_headers, 200),
    ({"login": "mergin  ", "password": "ilovemergin"}, json_headers, 200),
    ({"login": "mergin@mergin.com", "password": "ilovemergin"}, json_headers, 200),
    (
        {"login": "mergin", "password": "ilovemergin"},
        {**json_headers, "X-Device-Id": None},
        200,
    ),
    ({"login": "mergin", "password": "ilovemergi"}, json_headers, 401),
    ({"login": "mergin"}, json_headers, 401),
    ({"login": "mergin", "password": "ilovemergin"}, {}, 415),
    # case insensitive login
    ({"login": "merGIN", "password": "ilovemergin"}, json_headers, 200),
    ({"login": "merGIN@MERgin.com", "password": "ilovemergin"}, json_headers, 200),
]


@pytest.mark.parametrize("data,headers,expected", test_login_data)
def test_login(client, data, headers, expected):
    resp = client.post(
        url_for("/.mergin_auth_controller_login"),
        data=json.dumps(data),
        headers=headers,
    )
    assert resp.status_code == expected
    if expected == 200:
        user = User.query.filter_by(username=DEFAULT_USER[0]).first()
        login_history = (
            LoginHistory.query.filter_by(user_id=user.id)
            .order_by(desc(LoginHistory.timestamp))
            .first()
        )
        assert login_history
        assert login_history.device_id == str(headers.get("X-Device-Id"))


def test_logout(client):
    login_as_admin(client)
    resp = client.get(url_for("/.mergin_auth_controller_logout"))
    assert resp.status_code == 200


# user registration tests
test_user_reg_data = [
    ("test", "test@test.com", "#pwd1234", 201),  # success
    (
        "TesTUser",
        "test@test.com",
        "#pwd1234",
        201,
    ),  # tests with upper case, but user does not exist
    (
        "TesTUser2",
        "test2@test.com",
        "#pwd1234",
        201,
    ),  # tests with upper case, but user does not exist
    ("bob", "test@test.com", "#pwd1234", 400),  # invalid (short) username
    ("test", "test.com", "#pwd1234", 400),  # invalid email
    ("mergin", "test@test.com", "#pwd1234", 400),  # existing user
    (
        "MerGin",
        "tests@test.com",
        "#pwd1234",
        400,
    ),  # tests with upper case but mergin already exists
    (
        "  mergin  ",
        "tests@test.com",
        "#pwd1234",
        400,
    ),  # tests with blank spaces, but mergin user already exists
    (
        "XmerginX",
        " tests@test.com  ",
        "#pwd1234",
        201,
    ),  # tests with blank spaces, whitespace to be removed
    (
        "mergin2",
        " mergin@mergin.com  ",
        "#pwd1234",
        400,
    ),  # tests with blank spaces, but email already exists
    (
        "mergin3",
        " merGIN@mergin.com  ",
        "#pwd1234",
        400,
    ),  # tests with upper case, but email already exists
    ("XmerginX", " mergin@mergin.com  ", "#pwd123", 400),  # invalid password
]


@pytest.mark.parametrize("username,email,pwd,expected", test_user_reg_data)
def test_user_register(client, username, email, pwd, expected):
    login_as_admin(client)
    url = url_for("/.mergin_auth_controller_register_user")
    data = {"username": username, "email": email, "password": pwd, "confirm": pwd}
    resp = client.post(url, data=json.dumps(data), headers=json_headers)
    assert resp.status_code == expected
    if expected == 201:
        user = User.query.filter_by(username=username).first()
        assert user
        assert user.active
        assert not user.verified_email  # awaits user confirmation


def test_confirm_email(app, client):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    token = serializer.dumps(
        "mergin@mergin.com", salt=app.config["SECURITY_PASSWORD_SALT"]
    )
    resp = client.post(url_for("/.mergin_auth_controller_confirm_email", token=token))
    assert resp.status_code == 200

    user = User.query.filter_by(username="mergin").first()
    # tests with old registered user
    user.verified_email = False
    user.registration_date = datetime.utcnow() - timedelta(days=1)
    db.session.commit()
    resp = client.post(url_for("/.mergin_auth_controller_confirm_email", token=token))
    assert resp.status_code == 200

    # try again with freshly registered user
    user.verified_email = False
    user.registration_date = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    resp = client.post(url_for("/.mergin_auth_controller_confirm_email", token=token))
    assert resp.status_code == 200

    # try again
    resp = client.post(url_for("/.mergin_auth_controller_confirm_email", token=token))
    assert resp.status_code == 200

    # invalid token
    resp = client.post(url_for("/.mergin_auth_controller_confirm_email", token="token"))
    assert resp.status_code == 400

    # not-existing user
    resp = client.post(
        url_for(
            "/.mergin_auth_controller_confirm_email",
            token=serializer.dumps(
                "tests@mergin.com", salt=app.config["SECURITY_PASSWORD_SALT"]
            ),
        )
    )
    assert resp.status_code == 404


def test_confirm_password(app, client):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    token = serializer.dumps(
        "mergin@mergin.com", salt=app.config["SECURITY_PASSWORD_SALT"]
    )

    form_data = {"password": "ilovemergin#0", "confirm": "ilovemergin#0"}
    resp = client.post(
        url_for("/.mergin_auth_controller_confirm_new_password", token=token),
        data=json.dumps(form_data),
        headers=json_headers,
    )
    assert resp.status_code == 200

    # invalid token
    resp = client.post(
        url_for("/.mergin_auth_controller_confirm_new_password", token="token"),
        data=json.dumps(form_data),
        headers=json_headers,
    )
    assert resp.status_code == 400

    # not-existing user
    resp = client.post(
        url_for(
            "/.mergin_auth_controller_confirm_new_password",
            token=serializer.dumps(
                "tests@mergin.com", salt=app.config["SECURITY_PASSWORD_SALT"]
            ),
        ),
        data=json.dumps(form_data),
        headers=json_headers,
    )
    assert resp.status_code == 404

    # add inactive user
    user = User(
        username="tests", passwd="testuser", is_admin=True, email="tests@mergin.com"
    )
    user.active = False
    db.session.add(user)
    db.session.commit()
    resp = client.post(
        url_for(
            "/.mergin_auth_controller_confirm_new_password",
            token=serializer.dumps(
                "tests@mergin.com", salt=app.config["SECURITY_PASSWORD_SALT"]
            ),
        )
    )
    assert resp.status_code == 400


# reset password tests: success, no email, not-existing user
test_reset_data = [
    ({"email": "mergin@mergin.com"}, 200),
    ({"email": "Mergin@mergin.com"}, 200),  # case insensitive
    ({}, 400),
    ({"email": "tests@mergin.com"}, 404),
]


@pytest.mark.parametrize("data,expected", test_reset_data)
def test_reset_password(client, data, expected):
    resp = client.post(
        url_for("/.mergin_auth_controller_password_reset"),
        data=json.dumps(data),
        headers=json_headers,
    )
    assert resp.status_code == expected


def test_change_password(client):
    username = "user_test"
    old_password = "user_password"
    new_password = "Test#tests"

    user = User(
        username=username,
        passwd=old_password,
        is_admin=True,
        email="user_test@mergin.com",
    )
    user.active = True
    user.profile = UserProfile()
    db.session.add(user)
    db.session.commit()

    resp = client.post(
        url_for("/.mergin_auth_controller_login"),
        data=json.dumps({"login": username, "password": old_password}),
        headers=json_headers,
    )
    assert resp.status_code == 200

    # tests old password incorrect
    resp = client.post(
        url_for("/.mergin_auth_controller_change_password"),
        data=json.dumps(
            {
                "old_password": "old_password_incorrect",
                "password": new_password,
                "confirm": new_password,
            }
        ),
        headers=json_headers,
    )
    assert resp.status_code == 400

    # tests correct old password
    resp = client.post(
        url_for("/.mergin_auth_controller_change_password"),
        data=json.dumps(
            {
                "old_password": old_password,
                "password": new_password,
                "confirm": new_password,
            }
        ),
        headers=json_headers,
    )
    assert resp.status_code == 200

    # tests login with old password
    resp = client.post(
        url_for("/.mergin_auth_controller_login"),
        data=json.dumps({"login": username, "password": old_password}),
        headers=json_headers,
    )
    assert resp.status_code == 401

    # tests login with new password
    resp = client.post(
        url_for("/.mergin_auth_controller_login"),
        data=json.dumps({"login": username, "password": new_password}),
        headers=json_headers,
    )
    assert resp.status_code == 200


def test_remove_user(client):
    """Test force removal of user by admin"""
    login_as_admin(client)
    user = add_user("tests", "tests")

    resp = client.delete(
        url_for("/.mergin_auth_controller_delete_user", username=user.username)
    )
    assert resp.status_code == 204
    assert not User.query.filter_by(username="tests").count()
    assert user.username.startswith("deleted_") and not user.active

    resp = client.delete(
        url_for("/.mergin_auth_controller_delete_user", username="tests")
    )
    assert resp.status_code == 404

    # try to login but user should not be found
    resp = client.post(
        url_for("/.mergin_auth_controller_login"),
        data=json.dumps({"login": "tests", "password": "tests"}),
        headers=json_headers,
    )
    assert resp.status_code == 401


# login tests: success, success with email login, invalid password, missing password, wrong headers
test_api_login_data = [
    ({"login": "mergin", "password": "ilovemergin"}, json_headers, 200),
    ({"login": "mergin@mergin.com", "password": "ilovemergin"}, json_headers, 200),
    ({"login": "mergin", "password": "ilovemergi"}, json_headers, 401),
    ({"login": "mergin"}, json_headers, 400),
    ({"login": "mergin", "password": "ilovemergin"}, {}, 415),
]


@pytest.mark.parametrize("data,headers,expected", test_api_login_data)
def test_api_login(client, data, headers, expected):
    resp = client.post("/v1/auth/login", data=json.dumps(data), headers=headers)
    assert resp.status_code == expected
    if expected == 200:
        user = User.query.filter_by(username=DEFAULT_USER[0]).first()
        login_history = (
            LoginHistory.query.filter_by(user_id=user.id)
            .order_by(desc(LoginHistory.timestamp))
            .first()
        )
        assert login_history


def test_api_login_from_urllib(client):
    with patch("mergin.auth.models.get_user_agent") as mock:
        mock.return_value = "DB-sync/0.1"
        resp = client.post(
            "/v1/auth/login",
            data=json.dumps({"login": "mergin", "password": "ilovemergin"}),
            headers=json_headers,
        )
        assert resp.status_code == 200
        user = User.query.filter_by(username=DEFAULT_USER[0]).first()
        login_history = (
            LoginHistory.query.filter_by(user_id=user.id)
            .order_by(desc(LoginHistory.timestamp))
            .first()
        )
        assert not login_history


def test_api_user_profile(client):
    """tests public API endpoint to get user details"""
    resp = client.get("/v1/user/mergin")
    assert resp.status_code == 401

    login_as_admin(client)
    resp = client.get("/v1/user/mergin")
    assert resp.status_code == 200
    assert resp.json["username"] == "mergin"
    assert resp.json["organisations"] == {
        test_workspace_name: "owner"
    }  # default workspace
    # tests legacy properties are in response
    for key in ["storage", "storage_limit", "disk_usage"]:
        assert key in resp.json


def test_update_user(client):
    login_as_admin(client)
    user = User.query.filter_by(username="mergin").first()
    data = {"active": False}
    resp = client.patch(
        url_for("/.mergin_auth_controller_update_user", username=user.username),
        data=json.dumps(data),
        headers=json_headers,
    )
    assert resp.status_code == 200
    assert not user.active

    user.is_admin = False
    db.session.add(user)
    db.session.commit()
    resp = client.patch(
        url_for("/.mergin_auth_controller_update_user", username=user.username),
        data=json.dumps(data),
        headers=json_headers,
    )
    assert resp.status_code == 403


def test_update_user_profile(client):
    login_as_admin(client)
    user = User.query.filter_by(username="mergin").first()
    user.verified_email = True

    user2 = User("tests", "m@m.com", "testspass", False)
    db.session.add(user2)
    db.session.commit()
    assert user.profile.receive_notifications
    assert user.verified_email

    # update profile
    resp = client.post(
        url_for("/.mergin_auth_controller_update_user_profile"),
        data=json.dumps({"email": "m@m.com"}),
        headers=json_headers,
    )
    assert resp.status_code == 400
    assert "Email already exists" in resp.json.get("email")

    # update profile
    resp = client.post(
        url_for("/.mergin_auth_controller_update_user_profile"),
        data=json.dumps(
            {"first_name": "  John", "last_name": "Doe ", "email": "john@doe.com "}
        ),
        headers=json_headers,
    )
    assert resp.status_code == 200
    assert user.email == "john@doe.com"
    assert user.profile.first_name == "John"
    assert user.profile.last_name == "Doe"

    # update profile
    resp = client.post(
        url_for("/.mergin_auth_controller_update_user_profile"),
        data=json.dumps(
            {"receive_notifications": False, "email": "changed_email@mergin.co.uk"}
        ),
        headers=json_headers,
    )
    assert resp.status_code == 200

    user = User.query.filter_by(username="mergin").first()
    assert not user.profile.receive_notifications
    assert not user.verified_email
    assert user.email == "changed_email@mergin.co.uk"


def test_search_user(client):
    user = User.query.filter_by(username="mergin").first()

    # query without workspace
    assert client.get("/app/auth/user/search").status_code == 400

    # anonymous user
    assert client.get("/app/auth/user/search?namespace=tests").status_code == 401

    login_as_admin(client)
    # not existing workspace
    assert client.get("/app/auth/user/search?namespace=tests").status_code == 404

    ws = client.application.config["GLOBAL_WORKSPACE"]
    # no query params to filter users
    resp = client.get(f"/app/auth/user/search?namespace={ws}")
    assert resp.status_code == 200
    assert len(resp.json) == 0

    add_user("fero.mrkva", "tests")
    add_user("palomrmrkva", "tests")
    add_user("mrkvajozef", "tests")
    add_user("mrk", "tests")
    url = f"/app/auth/user/search?namespace={ws}"
    resp = client.get(url + "&like=erg")
    assert "mer" in resp.json[0]["username"]
    assert set(resp.json[0].keys()) == {"id", "name", "username", "email"}

    # search by email
    resp = client.get(url + f"&like={user.email}")
    assert resp.json[0]["username"] == "mergin"
    resp = client.get(url + "&like=@mergin.com")
    assert len(resp.json) == 5  # all users since this is default domain

    # all search levels (1. exact 2. prefix, 3. word start 4. anywhere)
    resp = client.get(url + "&like=mrk")
    assert "mrk" in resp.json[0]["username"]
    assert "mrkvajozef" in resp.json[1]["username"]
    assert "fero.mrkva" in resp.json[2]["username"]
    assert "palomrmrkva" in resp.json[3]["username"]
    assert 4 == len(resp.json)

    # search levels without exact (1. prefix, 2. word start 3. anywhere)
    resp = client.get(url + "&like=mrkv")
    assert "mrkvajozef" in resp.json[0]["username"]
    assert "fero.mrkva" in resp.json[1]["username"]
    assert "palomrmrkva" in resp.json[2]["username"]
    assert 3 == len(resp.json)

    # just exact search level
    resp = client.get(url + "&like=mrkvajozef")
    assert "mrkvajozef" in resp.json[0]["username"]
    assert 1 == len(resp.json)

    # just prefix search level
    resp = client.get(url + "&like=palo")
    assert "palomrmrkva" in resp.json[0]["username"]
    assert 1 == len(resp.json)

    # just word start search level
    resp = client.get(url + "&like=.mrk")
    assert "fero.mrkva" in resp.json[0]["username"]
    assert 1 == len(resp.json)

    # just anywhere search level
    resp = client.get(url + "&like=kva")
    assert "fero.mrkva" in resp.json[0]["username"]
    assert "mrkvajozef" in resp.json[1]["username"]
    assert "palomrmrkva" in resp.json[2]["username"]
    assert 3 == len(resp.json)

    resp = client.get(url + f"&id={user.id}")
    assert resp.json[0]["username"] == user.username

    resp = client.get(url + f"&names={user.username}")
    assert resp.json[0]["username"] == user.username

    # no such user
    resp = client.get(url + "&like=tests")
    assert len(resp.json) == 0

    # invalid query par
    resp = client.get(url + f"&id=1,a")
    assert len(resp.json) == 0


def test_csrf_refresh_token(client):
    resp = client.get(url_for("/.mergin_auth_controller_refresh_csrf_token"))
    assert resp.status_code == 401

    login_as_admin(client)
    resp = client.get(url_for("/.mergin_auth_controller_refresh_csrf_token"))
    assert resp.json["csrf"]


def test_close_user_account(client):
    """Test closing user account via public API call and admin actions to enable/ban user"""
    username = "alice"
    user = add_user(username, "pwd")
    login(client, username, "pwd")
    # user closes account
    resp = client.delete("/v1/user")
    assert resp.status_code == 204
    assert user.active is False
    assert user.inactive_since
    # login is not possible
    assert (
        client.post(
            url_for("/.mergin_auth_controller_login"),
            data=json.dumps({"login": user.username, "password": "pwd"}),
            headers=json_headers,
        ).status_code
        == 401
    )

    login_as_admin(client)
    # email is still occupied
    data = {
        "username": user.username + "_new",
        "email": user.email,
        "password": "Pwd123###",
        "confirm": "Pwd123###",
    }
    assert (
        client.post(
            url_for("/.mergin_auth_controller_register_user"),
            data=json.dumps(data),
            headers=json_headers,
        ).status_code
        == 400
    )

    resp = client.get(
        url_for("/.mergin_auth_controller_get_user", username=user.username)
    )
    assert resp.json["scheduled_removal"]

    # admin can re-enable account
    resp = client.patch(
        url_for("/.mergin_auth_controller_update_user", username=user.username),
        data=json.dumps({"active": True}),
        headers=json_headers,
    )
    assert resp.status_code == 200
    assert user.active is True
    assert not user.inactive_since
    # admin can ban user
    resp = client.patch(
        url_for("/.mergin_auth_controller_update_user", username=user.username),
        data=json.dumps({"active": False}),
        headers=json_headers,
    )
    assert resp.status_code == 200
    assert user.active is False
    assert not user.inactive_since
    # admin can force delete user
    resp = client.delete(
        url_for("/.mergin_auth_controller_delete_user", username=username)
    )
    assert resp.status_code == 204
    assert not User.query.filter_by(username=username).first()
    assert user.username.startswith("deleted_") and not user.active

    user = User.query.filter_by(username=DEFAULT_USER[0]).first()
    # check default project
    project = Project.query.filter_by(workspace_id=test_workspace_id).first()
    assert user.id in project.access.owners

    resp = client.delete("/v1/user")
    assert resp.status_code == 204
    user = User.query.filter_by(username=DEFAULT_USER[0]).first()
    # tests only basic functionality - inactivate user and project
    # more complex testing is done in close mergin account tests case
    assert not user.active
    assert user.inactive_since
    assert (
        project.access.owners == []
    )  # project will be removed by cron job, but is not accessible

    # login should fail now
    data = {"login": DEFAULT_USER[0], "password": DEFAULT_USER[1]}
    resp = client.post("/v1/auth/login", data=json.dumps(data), headers=json_headers)
    assert resp.status_code == 401

    # mimic expiry, call celery job and check user is gone
    user.inactive_since = datetime.today() - timedelta(
        client.application.config["ACCOUNT_EXPIRATION"] + 1
    )
    db.session.commit()
    users_number = User.query.count()
    anonymize_removed_users()
    assert not User.query.filter_by(username=DEFAULT_USER[0]).first()
    assert User.query.count() == users_number


def test_paginate_users(client):
    """Test admin paginate user endpoint"""
    add_user("alice", "tests")  # 2
    add_user("bob", "tests")  # 3
    # username starts 'deleted_' but is active -> should be listed
    deleted_active = add_user("deleted_active", "tests")  # 4
    # user is inactive but username does not start 'deleted_' -> should be listed
    user_inactive = add_user("user_inactive", "user_inactive")  # 5
    user_inactive.active = False
    db.session.commit()
    # username starts 'deleted_' and is inactive -> should not be listed
    deleted_inactive = add_user("deleted_inactive", "deleted_inactive")  # not listed
    deleted_inactive.active = False
    db.session.commit()
    login(client, *DEFAULT_USER)
    url = "/app/admin/users?page=1&per_page=10"
    # get 5 users (default + 5 new added - 1 deleted & inactive)
    resp = client.get(url)
    list_of_usernames = [user["username"] for user in resp.json["users"]]
    assert resp.json["total"] == 5
    assert resp.json["users"][0]["username"] == "mergin"
    assert user_inactive.username in list_of_usernames
    assert deleted_active.username in list_of_usernames
    assert deleted_inactive.username not in list_of_usernames
    # order by username
    resp = client.get(url + "&order_by=username")
    assert resp.json["total"] == 5
    assert resp.json["users"][0]["username"] == "alice"
    # exact match with username
    resp = client.get(url + "&like=bob")
    assert resp.json["total"] == 1
    assert resp.json["users"][0]["username"] == "bob"
    # ilike search with email
    resp = client.get(url + "&like=@mergin.com")
    assert resp.json["total"] == 5
    # exact search by email
    resp = client.get(url + "&like=alice@mergin.com")
    assert resp.json["total"] == 1
    assert resp.json["users"][0]["username"] == "alice"
    # invalid paging
    assert client.get("/app/admin/users?page=2&per_page=10").status_code == 404


def test_user_info(client):
    """Test user profile of logged-in user"""
    login(client, *DEFAULT_USER)
    resp = client.get("/v1/user/profile")
    assert resp.json["username"] == DEFAULT_USER[0]
    assert len(resp.json["workspaces"]) == 1
    assert resp.json["preferred_workspace"] == 1
    assert len(resp.json["invitations"]) == 0
    # make sure there is no private information
    assert "passwd" not in resp.json


# login tests: success, success with email login, invalid password, missing password, not admin user
test_admin_login_data = [
    ({"login": "mergin", "password": "ilovemergin"}, 200),
    ({"login": "mergin@mergin.com", "password": "ilovemergin"}, 200),
    ({"login": "mergin", "password": "ilovemergi"}, 401),
    ({"login": "mergin"}, 400),
    ({"login": "user", "password": "user"}, 403),
]


@pytest.mark.parametrize("data,expected", test_admin_login_data)
def test_admin_login(client, data, expected):
    add_user("user", "user")
    resp = client.post("/app/admin/login", data=json.dumps(data), headers=json_headers)
    assert resp.status_code == expected


def test_update_project_v2(client):
    project = Project.query.filter_by(
        workspace_id=test_workspace_id, name=test_project
    ).first()
    data = {"name": "new_project_name"}
    resp = client.patch(f"v2/projects/{project.id}", json=data)
    assert resp.status_code == 401
    user = add_user("test", "test")
    login(client, "test", "test")
    resp = client.patch(f"v2/projects/{project.id}", json=data)
    assert resp.status_code == 403
    login_as_admin(client)
    resp = client.patch(f"v2/projects/{project.id}", json=data)
    assert resp.status_code == 204


user_data = [
    ("user1", True, 201),  # no problem
    ("user\260", True, 201),  # non-ascii character
    ("usér", True, 201),  # non-ascii character
    ("user\\", True, 400),  # disallowed character
    ("日人日本人", True, 201),  # non-ascii character
    ("usér", False, 400),  # not utf-8 encoding
    ("us er", True, 400),  # whitespace
    ("us—er", True, 400),  # dash
]


@pytest.mark.parametrize("username,utf8,expected", user_data)
def test_user_email_format(client, username, expected, utf8):
    login_as_admin(client)
    email = username + "@example.com"
    if not utf8:
        # simulate server misinterpreting the input encoding
        email = email.encode("latin1").decode("utf-8", errors="replace")
    url = url_for("/.mergin_auth_controller_register_user")
    data = {
        "username": username,
        "email": email,
        "password": "#pwd1234",
        "confirm": "#pwd1234",
    }
    resp = client.post(url, data=json.dumps(data), headers=json_headers)
    assert resp.status_code == expected
