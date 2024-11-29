# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

from __future__ import annotations
import datetime
from typing import List, Optional
import bcrypt
from flask import current_app, request
from sqlalchemy import or_, func, CheckConstraint

from .. import db
from ..sync.utils import get_user_agent, get_ip, get_device_id


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), info={"label": "Username"})
    email = db.Column(db.String(120))

    passwd = db.Column(db.String(80), info={"label": "Password"})  # salted + hashed

    active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean)
    verified_email = db.Column(db.Boolean, default=False)
    inactive_since = db.Column(db.DateTime(), nullable=True, index=True)
    registration_date = db.Column(
        db.DateTime(),
        nullable=False,
        info={"label": "Date of creation of user account"},
        default=datetime.datetime.utcnow,
    )

    __table_args__ = (
        db.Index("ix_user_username", func.lower(username), unique=True),
        db.Index("ix_user_email", func.lower(email), unique=True),
    )

    def __init__(self, username, email, passwd, is_admin=False):
        self.username = username
        self.email = email
        self.assign_password(passwd)
        self.is_admin = is_admin

    def __repr__(self):
        return "<User %r>" % self.username

    def check_password(self, password):
        if isinstance(password, str):
            password = password.encode("utf-8")
        return bcrypt.checkpw(password, self.passwd.encode("utf-8"))

    def assign_password(self, password):
        if isinstance(password, str):
            password = password.encode("utf-8")
        self.passwd = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")

    @property
    def is_authenticated(self):
        """For Flask-Login"""
        return True

    @property
    def is_active(self):
        """For Flask-Login"""
        return self.active

    @property
    def is_anonymous(self):
        """For Flask-Login"""
        return False

    def get_id(self):
        """For Flask-Login ... must return unicode user ID"""
        return str(self.id)

    @staticmethod
    def search(like: str, limit: int = 10, only_active: bool = True) -> List[User]:
        """
        Find users using ilike pattern within username/email

        Results are returned in following order:
        1.) exact match - ordered by attribute
        2.) match is on start of the string - ordered by attribute
        3.) match is on start of words - ordered by attribute
        4.) match is anywhere - ordered by attribute
        """
        if only_active:
            users_query = User.query.filter_by(active=True)
        else:
            users_query = User.query
        attr = User.email if "@" in like else User.username
        # try with exact match
        users_found = (
            users_query.filter(attr.ilike(like)).order_by(attr).limit(limit).all()
        )
        # we keep searching until we have enough results
        if len(users_found) < limit:
            # prefix match except the previous results
            query_prefix = attr.ilike(f"{like}%") & User.id.notin_(
                [usr.id for usr in users_found]
            )
            users_prefix = (
                users_query.filter(query_prefix)
                .order_by(attr)
                .limit(limit - len(users_found))
                .all()
            )
            users_found.extend(users_prefix)
            if len(users_found) < limit:
                # match on start of words except the previous results
                query_prefix_words = attr.op("~")(
                    f"[\\.|\\-|_| ]{like}.*"
                ) & User.id.notin_([usr.id for usr in users_found])
                users_prefix_words = (
                    users_query.filter(query_prefix_words)
                    .order_by(attr)
                    .limit(limit - len(users_found))
                    .all()
                )
                users_found.extend(users_prefix_words)
                if len(users_found) < limit:
                    # match anywhere except the previous results
                    query_match_anywhere = attr.ilike(f"%{like}%") & User.id.notin_(
                        [usr.id for usr in users_found]
                    )
                    users_anywhere = (
                        users_query.filter(query_match_anywhere)
                        .order_by(attr)
                        .limit(limit - len(users_found))
                        .all()
                    )
                    users_found.extend(users_anywhere)
        return users_found

    @property
    def removal_at(self) -> Optional[datetime.timedelta]:
        """Timestamp of pending user removal. While user is waiting for removal, it is not possible to create
        another user with the same username/email
        """
        if not self.inactive_since:
            return
        return self.inactive_since + datetime.timedelta(
            days=current_app.config["ACCOUNT_EXPIRATION"]
        )

    def inactivate(self) -> None:
        """Inactivate user account and remove explicitly shared projects as well clean references to created projects.
        User is then safe to be removed.
        """
        from ..sync.models import Project, ProjectAccess, AccessRequest, RequestStatus

        shared_projects = Project.query.filter(
            or_(
                Project.access.has(ProjectAccess.owners.contains([self.id])),
                Project.access.has(ProjectAccess.writers.contains([self.id])),
                Project.access.has(ProjectAccess.editors.contains([self.id])),
                Project.access.has(ProjectAccess.readers.contains([self.id])),
            )
        ).all()

        for p in shared_projects:
            for key in ("owners", "writers", "editors", "readers"):
                value = set(getattr(p.access, key))
                if self.id in value:
                    value.remove(self.id)
                setattr(p.access, key, list(value))
            db.session.add(p)

        # decline all access requests
        for req in (
            AccessRequest.query.filter_by(requested_by=self.id)
            .filter(AccessRequest.status.is_(None))
            .all()
        ):
            req.resolve(RequestStatus.DECLINED, resolved_by=self.id)

        # inactivate user account to prevent login and mark for clean up
        self.active = False
        self.inactive_since = datetime.datetime.utcnow()
        db.session.commit()

    def anonymize(self):
        """Anonymize user object in database - remove personal information"""
        ts = round(datetime.datetime.utcnow().timestamp() * 1000)
        del_str = f"deleted_{ts}"
        self.username = del_str
        self.email = None
        self.passwd = None
        self.profile.first_name = None
        self.profile.last_name = None
        db.session.commit()


class UserProfile(db.Model):
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    )
    receive_notifications = db.Column(db.Boolean, default=True, index=True)
    first_name = db.Column(db.String(256), nullable=True, info={"label": "First name"})
    last_name = db.Column(db.String(256), nullable=True, info={"label": "Last name"})

    user = db.relationship(
        "User",
        uselist=False,
        backref=db.backref(
            "profile", single_parent=True, uselist=False, cascade="all,delete"
        ),
    )

    def name(self):
        return f'{self.first_name if self.first_name else ""} {self.last_name if self.last_name else ""}'.strip()


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(), default=datetime.datetime.utcnow, index=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    user_agent = db.Column(db.String, index=True)
    ip_address = db.Column(db.String, index=True)
    ip_geolocation_country = db.Column(db.String, index=True)
    device_id = db.Column(db.String, index=True, nullable=True)

    def __init__(self, user_id: int, ua: str, ip: str, device_id: Optional[str] = None):
        self.user_id = user_id
        self.user_agent = ua
        self.ip_address = ip
        self.device_id = device_id

    @staticmethod
    def add_record(user_id: int, req: request) -> None:
        ua = get_user_agent(req)
        ip = get_ip(req)
        device_id = get_device_id(req)
        # ignore login attempts coming from urllib - related to db sync tool
        if "DB-sync" in ua:
            return
        lh = LoginHistory(user_id, ua, ip, device_id)
        db.session.add(lh)
        db.session.commit()
