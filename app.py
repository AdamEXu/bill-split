from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlencode
import requests
import os
from dotenv import load_dotenv
import uuid
from datetime import datetime
import openai
import base64
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-change-this")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///billsplit.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# OpenAI configuration
openai_client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


# Database Models
class User(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    profile_picture = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    group_memberships = db.relationship("GroupMember", backref="user", lazy=True)
    bill_participations = db.relationship("BillParticipant", backref="user", lazy=True)


class Group(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    members = db.relationship("GroupMember", backref="group", lazy=True)
    bills = db.relationship("Bill", backref="group", lazy=True)
    creator = db.relationship("User", backref="created_groups")


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(50), db.ForeignKey("group.id"), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("group_id", "user_id"),)


class Bill(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    group_id = db.Column(db.String(50), db.ForeignKey("group.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    subtotal = db.Column(db.Float, nullable=False)  # Amount before tax/tip
    tax_amount = db.Column(db.Float, default=0.0)
    tip_amount = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, nullable=False)  # subtotal + tax + tip
    split_method = db.Column(
        db.String(20), default="equal"
    )  # 'equal', 'itemized', 'percentage', 'custom'
    created_by = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    participants = db.relationship("BillParticipant", backref="bill", lazy=True)
    items = db.relationship("BillItem", backref="bill", lazy=True)
    creator = db.relationship("User", backref="created_bills")


class BillItem(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    bill_id = db.Column(db.String(50), db.ForeignKey("bill.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)
    is_shared = db.Column(
        db.Boolean, default=False
    )  # True for shared items like appetizers

    # Relationships
    item_participants = db.relationship(
        "BillItemParticipant", backref="item", lazy=True
    )


class BillItemParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.String(50), db.ForeignKey("bill_item.id"), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    share_percentage = db.Column(db.Float, default=100.0)  # For shared items

    __table_args__ = (db.UniqueConstraint("item_id", "user_id"),)


class BillParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.String(50), db.ForeignKey("bill.id"), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    amount_owed = db.Column(db.Float, nullable=False)
    custom_amount = db.Column(db.Float)  # For custom splitting
    percentage = db.Column(db.Float)  # For percentage splitting
    paid = db.Column(db.Boolean, default=False)

    __table_args__ = (db.UniqueConstraint("bill_id", "user_id"),)


class UserDebt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(50), db.ForeignKey("group.id"), nullable=False)
    debtor_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    creditor_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    debtor = db.relationship("User", foreign_keys=[debtor_id])
    creditor = db.relationship("User", foreign_keys=[creditor_id])

    __table_args__ = (db.UniqueConstraint("group_id", "debtor_id", "creditor_id"),)


class MobileToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # For future token expiration


# Helper functions
def get_current_user():
    # Check for regular web session
    if "user_id" in session:
        return User.query.get(session["user_id"])

    # Check for mobile session token in Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        print(f"Mobile token validation: {token}")

        # Look up token in database
        mobile_token = MobileToken.query.filter_by(token=token).first()
        if mobile_token:
            print(f"Token valid, user_id: {mobile_token.user_id}")
            return User.query.get(mobile_token.user_id)
        else:
            print("Token not found in database")

    return None


def create_user(google_id, email, name, profile_picture):
    user = User(id=google_id, email=email, name=name, profile_picture=profile_picture)
    db.session.add(user)
    db.session.commit()
    return user


def calculate_bill_splits(
    bill,
    participants,
    items=None,
    split_method="equal",
    custom_amounts=None,
    percentages=None,
):
    """Calculate how much each participant owes based on split method"""
    splits = {}

    if split_method == "equal":
        # Split total amount equally
        amount_per_person = bill.total_amount / len(participants)
        for participant_id in participants:
            splits[participant_id] = amount_per_person

    elif split_method == "itemized" and items:
        # Calculate based on items each person ordered
        for participant_id in participants:
            splits[participant_id] = 0.0

        # Add up item costs for each participant
        for item in items:
            item_participants = item.get("participants", [])
            if item.get("is_shared", False):
                # Shared item - split among all participants
                cost_per_person = (item["price"] * item.get("quantity", 1)) / len(
                    participants
                )
                for participant_id in participants:
                    splits[participant_id] += cost_per_person
            else:
                # Individual item - split among item participants
                if item_participants:
                    cost_per_person = (item["price"] * item.get("quantity", 1)) / len(
                        item_participants
                    )
                    for participant_id in item_participants:
                        if participant_id in splits:
                            splits[participant_id] += cost_per_person

        # Add proportional tax and tip
        subtotal_splits = sum(splits.values())
        if subtotal_splits > 0:
            for participant_id in participants:
                proportion = splits[participant_id] / subtotal_splits
                splits[participant_id] += (
                    bill.tax_amount + bill.tip_amount
                ) * proportion

    elif split_method == "percentage" and percentages:
        # Split by percentage
        for participant_id in participants:
            percentage = percentages.get(participant_id, 0) / 100.0
            splits[participant_id] = bill.total_amount * percentage

    elif split_method == "custom" and custom_amounts:
        # Custom amounts
        for participant_id in participants:
            splits[participant_id] = custom_amounts.get(participant_id, 0)

    return splits


def update_debt_tracking(group_id, bill, splits):
    """Update debt tracking between users"""
    # For now, we'll implement a simple system where the bill creator is owed money
    # In a more complex system, you might want to optimize debts between all users

    bill_creator = bill.created_by

    for participant_id, amount_owed in splits.items():
        if participant_id != bill_creator and amount_owed > 0:
            # Find or create debt record
            debt = UserDebt.query.filter_by(
                group_id=group_id, debtor_id=participant_id, creditor_id=bill_creator
            ).first()

            if debt:
                debt.amount += amount_owed
                debt.last_updated = datetime.utcnow()
            else:
                debt = UserDebt(
                    group_id=group_id,
                    debtor_id=participant_id,
                    creditor_id=bill_creator,
                    amount=amount_owed,
                )
                db.session.add(debt)


def parse_receipt_with_ai(image_file):
    """
    Parse a receipt image using OpenAI's GPT-5 vision capabilities.

    Args:
        image_file: File object containing the receipt image

    Returns:
        dict: Parsed receipt data with structure:
        {
            'success': bool,
            'data': {
                'title': str,
                'subtotal': float,
                'tax_amount': float,
                'tip_amount': float,
                'total_amount': float,
                'items': [
                    {
                        'name': str,
                        'price': float,
                        'quantity': int
                    }
                ]
            },
            'error': str (if success is False)
        }
    """
    try:
        # Read and encode the image
        image_data = image_file.read()
        image_base64 = base64.b64encode(image_data).decode("utf-8")

        # Create the prompt for structured receipt parsing
        prompt = """
        Please analyze this receipt image and extract the following information in JSON format:

        {
            "title": "Restaurant/Store name or descriptive title",
            "subtotal": 0.00,
            "tax_amount": 0.00,
            "tip_amount": 0.00,
            "total_amount": 0.00,
            "items": [
                {
                    "name": "Item name",
                    "price": 0.00,
                    "quantity": 1
                }
            ]
        }

        Instructions:
        - Extract the exact amounts as numbers (no currency symbols)
        - If tip is not shown, set tip_amount to 0.00
        - If tax is not shown separately, set tax_amount to 0.00
        - For items, extract individual line items with their prices
        - If quantity is not specified, assume 1
        - If you can't find subtotal, calculate it from items total
        - Ensure total_amount = subtotal + tax_amount + tip_amount
        - Use a descriptive title based on the restaurant/store name
        - Return only valid JSON, no additional text
        """

        # Make the API call to GPT-5 with vision
        response = openai_client.chat.completions.create(
            model="gpt-5",  # Using the latest GPT-5 model
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_base64}",
                                "detail": "high",
                            },
                        },
                    ],
                }
            ],
            max_completion_tokens=1000,  # GPT-5 uses max_completion_tokens instead of max_tokens
            # Note: GPT-5 only supports default temperature of 1, so we omit the temperature parameter
        )

        # Parse the response
        content = response.choices[0].message.content.strip()

        # Try to extract JSON from the response
        try:
            # Remove any markdown code blocks if present
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            parsed_data = json.loads(content)

            # Validate the parsed data structure
            required_fields = [
                "title",
                "subtotal",
                "tax_amount",
                "tip_amount",
                "total_amount",
                "items",
            ]
            for field in required_fields:
                if field not in parsed_data:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}",
                    }

            # Ensure numeric fields are floats
            for field in ["subtotal", "tax_amount", "tip_amount", "total_amount"]:
                try:
                    parsed_data[field] = float(parsed_data[field])
                except (ValueError, TypeError):
                    parsed_data[field] = 0.0

            # Validate and clean items
            if not isinstance(parsed_data["items"], list):
                parsed_data["items"] = []

            cleaned_items = []
            for item in parsed_data["items"]:
                if isinstance(item, dict) and "name" in item and "price" in item:
                    cleaned_item = {
                        "name": str(item["name"]),
                        "price": float(item.get("price", 0.0)),
                        "quantity": int(item.get("quantity", 1)),
                    }
                    cleaned_items.append(cleaned_item)

            parsed_data["items"] = cleaned_items

            return {"success": True, "data": parsed_data}

        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Failed to parse AI response as JSON: {str(e)}",
            }

    except Exception as e:
        return {"success": False, "error": f"Error processing receipt: {str(e)}"}


# Routes
@app.route("/")
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Get user's groups
    groups = (
        db.session.query(Group)
        .join(GroupMember)
        .filter(GroupMember.user_id == user.id)
        .all()
    )
    return render_template("dashboard.html", user=user, groups=groups)


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/auth/google")
def auth_google():
    # Check if this is a mobile app request
    is_mobile = request.args.get("mobile") == "true"

    google_auth_url = "https://accounts.google.com/o/oauth2/auth?" + urlencode(
        {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": url_for("auth_google_callback", _external=True),
            "response_type": "code",
            "scope": "email profile",
            "state": "mobile" if is_mobile else "web",  # Pass mobile flag through state
        }
    )
    return redirect(google_auth_url)


@app.route("/auth/google/callback")
def auth_google_callback():
    try:
        code = request.args.get("code")
        if not code:
            return render_template(
                "error.html", error="No authentication code received."
            )

        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": url_for("auth_google_callback", _external=True),
            },
        ).json()

        if "error" in token_response or "access_token" not in token_response:
            return render_template(
                "error.html", error="Failed to authenticate with Google."
            )

        user_response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token_response['access_token']}"},
        ).json()

        if "error" in user_response or "email" not in user_response:
            return render_template(
                "error.html", error="Failed to get user information from Google."
            )

        # Get user info
        google_id = user_response.get("id", "")
        email = user_response["email"]
        name = user_response.get("name", email.split("@")[0])
        profile_picture = user_response.get("picture", "")

        # Check if user exists, create if not
        user = User.query.get(google_id)
        if not user:
            user = create_user(google_id, email, name, profile_picture)

        # Create session
        session["user_id"] = user.id

        # Check if this was a mobile request
        state = request.args.get("state", "web")
        if state == "mobile":
            # For mobile, include session ID in the callback URL
            # Generate a simple session token (in production, use something more secure)
            import secrets

            session_token = secrets.token_urlsafe(32)

            # Store token in database
            mobile_token = MobileToken(token=session_token, user_id=user.id)
            db.session.add(mobile_token)
            db.session.commit()

            print(f"Generated mobile token: {session_token} for user: {user.id}")
            print(f"Stored token in database")
            return redirect(
                f"billsplit://success?session_token={session_token}&user_id={user.id}"
            )
        else:
            # Redirect to web app
            return redirect("/")

    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return render_template(
            "error.html", error="An unexpected error occurred during authentication."
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Group management routes
@app.route("/groups/create", methods=["GET", "POST"])
def create_group():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description", "")

        if not name:
            return render_template("create_group.html", error="Group name is required")

        # Create group
        group = Group(name=name, description=description, created_by=user.id)
        db.session.add(group)
        db.session.flush()  # Get the group ID

        # Add creator as member
        member = GroupMember(group_id=group.id, user_id=user.id)
        db.session.add(member)
        db.session.commit()

        return redirect(url_for("view_group", group_id=group.id))

    return render_template("create_group.html")


@app.route("/groups/<group_id>")
def view_group(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return render_template("error.html", error="You are not a member of this group")

    group = Group.query.get_or_404(group_id)
    members = (
        db.session.query(User)
        .join(GroupMember)
        .filter(GroupMember.group_id == group_id)
        .all()
    )
    bills = (
        Bill.query.filter_by(group_id=group_id).order_by(Bill.created_at.desc()).all()
    )

    return render_template(
        "group.html", group=group, members=members, bills=bills, user=user
    )


@app.route("/groups/<group_id>/add_member", methods=["POST"])
def add_member(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    email = request.form.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Find user by email
    new_user = User.query.filter_by(email=email).first()
    if not new_user:
        return jsonify({"error": "User not found. They need to sign up first."}), 404

    # Check if already member
    existing = GroupMember.query.filter_by(
        group_id=group_id, user_id=new_user.id
    ).first()
    if existing:
        return jsonify({"error": "User is already a member"}), 400

    # Add member
    member = GroupMember(group_id=group_id, user_id=new_user.id)
    db.session.add(member)
    db.session.commit()

    return jsonify({"success": True, "message": f"{new_user.name} added to group"})


# Bill management routes
@app.route("/groups/<group_id>/bills/create", methods=["GET", "POST"])
def create_bill(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return render_template("error.html", error="You are not a member of this group")

    group = Group.query.get_or_404(group_id)
    members = (
        db.session.query(User)
        .join(GroupMember)
        .filter(GroupMember.group_id == group_id)
        .all()
    )

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description", "")
        subtotal = request.form.get("subtotal") or request.form.get(
            "total_amount"
        )  # Backward compatibility
        tax_amount = request.form.get("tax_amount", "0")
        tip_amount = request.form.get("tip_amount", "0")
        split_method = request.form.get("split_method", "equal")
        participant_ids = request.form.getlist("participants")

        if not title or not subtotal:
            return render_template(
                "create_bill.html",
                group=group,
                members=members,
                error="Title and subtotal are required",
            )

        try:
            subtotal = float(subtotal)
            tax_amount = float(tax_amount)
            tip_amount = float(tip_amount)
            total_amount = subtotal + tax_amount + tip_amount
        except ValueError:
            return render_template(
                "create_bill.html",
                group=group,
                members=members,
                error="Invalid amounts",
            )

        if not participant_ids:
            return render_template(
                "create_bill.html",
                group=group,
                members=members,
                error="At least one participant is required",
            )

        # Create bill
        bill = Bill(
            group_id=group_id,
            title=title,
            description=description,
            subtotal=subtotal,
            tax_amount=tax_amount,
            tip_amount=tip_amount,
            total_amount=total_amount,
            split_method=split_method,
            created_by=user.id,
        )
        db.session.add(bill)
        db.session.flush()

        # Handle items if provided (for itemized bills)
        items_data = []
        if split_method == "itemized":
            # Parse items from form data
            item_names = request.form.getlist("item_name")
            item_prices = request.form.getlist("item_price")
            item_quantities = request.form.getlist("item_quantity")
            item_shared = request.form.getlist("item_shared")

            for i, name in enumerate(item_names):
                if name and i < len(item_prices):
                    try:
                        price = float(item_prices[i])
                        quantity = (
                            int(item_quantities[i]) if i < len(item_quantities) else 1
                        )
                        is_shared = str(i) in item_shared

                        # Create bill item
                        bill_item = BillItem(
                            bill_id=bill.id,
                            name=name,
                            price=price,
                            quantity=quantity,
                            is_shared=is_shared,
                        )
                        db.session.add(bill_item)
                        db.session.flush()

                        items_data.append(
                            {
                                "id": bill_item.id,
                                "name": name,
                                "price": price,
                                "quantity": quantity,
                                "is_shared": is_shared,
                                "participants": (
                                    participant_ids
                                    if is_shared
                                    else request.form.getlist(f"item_{i}_participants")
                                ),
                            }
                        )
                    except (ValueError, IndexError):
                        continue

        # Calculate splits based on method
        if split_method == "custom":
            custom_amounts = {}
            for participant_id in participant_ids:
                amount = request.form.get(f"custom_amount_{participant_id}", "0")
                try:
                    custom_amounts[participant_id] = float(amount)
                except ValueError:
                    custom_amounts[participant_id] = 0
            splits = calculate_bill_splits(
                bill,
                participant_ids,
                custom_amounts=custom_amounts,
                split_method=split_method,
            )
        elif split_method == "percentage":
            percentages = {}
            for participant_id in participant_ids:
                percentage = request.form.get(f"percentage_{participant_id}", "0")
                try:
                    percentages[participant_id] = float(percentage)
                except ValueError:
                    percentages[participant_id] = 0
            splits = calculate_bill_splits(
                bill,
                participant_ids,
                percentages=percentages,
                split_method=split_method,
            )
        else:
            splits = calculate_bill_splits(
                bill, participant_ids, items=items_data, split_method=split_method
            )

        # Create bill participants
        for participant_id in participant_ids:
            amount_owed = splits.get(participant_id, 0)
            participant = BillParticipant(
                bill_id=bill.id,
                user_id=participant_id,
                amount_owed=amount_owed,
                custom_amount=(
                    splits.get(participant_id) if split_method == "custom" else None
                ),
                percentage=(
                    request.form.get(f"percentage_{participant_id}")
                    if split_method == "percentage"
                    else None
                ),
            )
            db.session.add(participant)

        # Update debt tracking
        update_debt_tracking(group_id, bill, splits)

        db.session.commit()
        return redirect(url_for("view_bill", bill_id=bill.id))

    return render_template("create_bill.html", group=group, members=members)


@app.route("/bills/<bill_id>")
def view_bill(bill_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    bill = Bill.query.get_or_404(bill_id)

    # Check if user is member of the group
    membership = GroupMember.query.filter_by(
        group_id=bill.group_id, user_id=user.id
    ).first()
    if not membership:
        return render_template("error.html", error="You are not a member of this group")

    participants = (
        db.session.query(BillParticipant, User)
        .join(User)
        .filter(BillParticipant.bill_id == bill_id)
        .all()
    )

    return render_template("bill.html", bill=bill, participants=participants, user=user)


@app.route("/bills/<bill_id>/mark_paid", methods=["POST"])
def mark_paid(bill_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    participant = BillParticipant.query.filter_by(
        bill_id=bill_id, user_id=user.id
    ).first()
    if not participant:
        return jsonify({"error": "You are not a participant in this bill"}), 403

    participant.paid = True
    db.session.commit()

    return jsonify({"success": True, "message": "Marked as paid"})


# API endpoints for mobile app
@app.route("/api/debug/tokens", methods=["GET"])
def debug_tokens():
    tokens = MobileToken.query.all()
    return jsonify(
        {
            "mobile_tokens": [
                {
                    "token": t.token,
                    "user_id": t.user_id,
                    "created_at": t.created_at.isoformat(),
                }
                for t in tokens
            ],
            "mobile_tokens_count": len(tokens),
        }
    )


@app.route("/api/user", methods=["GET"])
def api_get_user():
    print("=== /api/user called ===")
    print(f"Request headers: {dict(request.headers)}")

    user = get_current_user()
    if not user:
        print("No user found, returning 401")
        return jsonify({"error": "Not authenticated"}), 401

    print(f"User found: {user.id}")
    return jsonify(
        {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "profile_picture": user.profile_picture,
        }
    )


@app.route("/api/groups", methods=["GET", "POST"])
def api_groups():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "GET":
        groups = (
            db.session.query(Group)
            .join(GroupMember)
            .filter(GroupMember.user_id == user.id)
            .all()
        )

        return jsonify(
            [
                {
                    "id": group.id,
                    "name": group.name,
                    "description": group.description,
                    "created_at": group.created_at.isoformat(),
                }
                for group in groups
            ]
        )

    elif request.method == "POST":
        data = request.get_json()
        if not data or not data.get("name"):
            return jsonify({"error": "Group name is required"}), 400

        # Create group
        group = Group(
            name=data["name"],
            description=data.get("description", ""),
            created_by=user.id,
        )
        db.session.add(group)
        db.session.flush()

        # Add creator as member
        member = GroupMember(group_id=group.id, user_id=user.id)
        db.session.add(member)
        db.session.commit()

        return (
            jsonify(
                {
                    "id": group.id,
                    "name": group.name,
                    "description": group.description,
                    "created_at": group.created_at.isoformat(),
                }
            ),
            201,
        )


@app.route("/api/groups/<group_id>", methods=["GET"])
def api_get_group(group_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    group = Group.query.get_or_404(group_id)
    members = (
        db.session.query(User)
        .join(GroupMember)
        .filter(GroupMember.group_id == group_id)
        .all()
    )

    return jsonify(
        {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at.isoformat(),
            "members": [
                {
                    "id": member.id,
                    "name": member.name,
                    "email": member.email,
                    "profile_picture": member.profile_picture,
                }
                for member in members
            ],
        }
    )


@app.route("/api/groups/<group_id>/members", methods=["POST"])
def api_add_group_member(group_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Find user by email
    new_user = User.query.filter_by(email=email).first()
    if not new_user:
        return jsonify({"error": "User not found. They need to sign up first."}), 404

    # Check if already member
    existing = GroupMember.query.filter_by(
        group_id=group_id, user_id=new_user.id
    ).first()
    if existing:
        return jsonify({"error": "User is already a member"}), 400

    # Add member
    member = GroupMember(group_id=group_id, user_id=new_user.id)
    db.session.add(member)
    db.session.commit()

    return jsonify(
        {
            "success": True,
            "message": f"{new_user.name} added to group",
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "profile_picture": new_user.profile_picture,
            },
        }
    )


@app.route("/api/groups/<group_id>/bills", methods=["GET", "POST"])
def api_group_bills(group_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    if request.method == "GET":
        bills = (
            Bill.query.filter_by(group_id=group_id)
            .order_by(Bill.created_at.desc())
            .all()
        )

        return jsonify(
            [
                {
                    "id": bill.id,
                    "title": bill.title,
                    "description": bill.description,
                    "subtotal": bill.subtotal,
                    "tax_amount": bill.tax_amount,
                    "tip_amount": bill.tip_amount,
                    "total_amount": bill.total_amount,
                    "split_method": bill.split_method,
                    "created_at": bill.created_at.isoformat(),
                }
                for bill in bills
            ]
        )

    elif request.method == "POST":
        data = request.get_json()
        if not data or not data.get("title") or not data.get("subtotal"):
            return jsonify({"error": "Title and subtotal are required"}), 400

        try:
            subtotal = float(data["subtotal"])
            tax_amount = float(data.get("tax_amount", 0))
            tip_amount = float(data.get("tip_amount", 0))
            total_amount = subtotal + tax_amount + tip_amount
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid amounts"}), 400

        participant_ids = data.get("participants", [])
        if not participant_ids:
            return jsonify({"error": "At least one participant is required"}), 400

        split_method = data.get("split_method", "equal")

        # Create bill
        bill = Bill(
            group_id=group_id,
            title=data["title"],
            description=data.get("description", ""),
            subtotal=subtotal,
            tax_amount=tax_amount,
            tip_amount=tip_amount,
            total_amount=total_amount,
            split_method=split_method,
            created_by=user.id,
        )
        db.session.add(bill)
        db.session.flush()

        # Handle items for itemized bills
        items_data = []
        if split_method == "itemized" and data.get("items"):
            for item_data in data["items"]:
                if item_data.get("name") and item_data.get("price"):
                    bill_item = BillItem(
                        bill_id=bill.id,
                        name=item_data["name"],
                        price=float(item_data["price"]),
                        quantity=int(item_data.get("quantity", 1)),
                        is_shared=bool(item_data.get("is_shared", False)),
                    )
                    db.session.add(bill_item)
                    db.session.flush()

                    items_data.append(
                        {
                            "id": bill_item.id,
                            "name": item_data["name"],
                            "price": float(item_data["price"]),
                            "quantity": int(item_data.get("quantity", 1)),
                            "is_shared": bool(item_data.get("is_shared", False)),
                            "participants": item_data.get(
                                "participants",
                                participant_ids if item_data.get("is_shared") else [],
                            ),
                        }
                    )

        # Calculate splits
        if split_method == "custom":
            custom_amounts = data.get("custom_amounts", {})
            splits = calculate_bill_splits(
                bill,
                participant_ids,
                custom_amounts=custom_amounts,
                split_method=split_method,
            )
        elif split_method == "percentage":
            percentages = data.get("percentages", {})
            splits = calculate_bill_splits(
                bill,
                participant_ids,
                percentages=percentages,
                split_method=split_method,
            )
        else:
            splits = calculate_bill_splits(
                bill, participant_ids, items=items_data, split_method=split_method
            )

        # Create bill participants
        for participant_id in participant_ids:
            amount_owed = splits.get(participant_id, 0)
            participant = BillParticipant(
                bill_id=bill.id,
                user_id=participant_id,
                amount_owed=amount_owed,
                custom_amount=(
                    splits.get(participant_id) if split_method == "custom" else None
                ),
                percentage=(
                    data.get("percentages", {}).get(participant_id)
                    if split_method == "percentage"
                    else None
                ),
            )
            db.session.add(participant)

        # Update debt tracking
        update_debt_tracking(group_id, bill, splits)

        db.session.commit()

        return (
            jsonify(
                {
                    "id": bill.id,
                    "title": bill.title,
                    "description": bill.description,
                    "subtotal": bill.subtotal,
                    "tax_amount": bill.tax_amount,
                    "tip_amount": bill.tip_amount,
                    "total_amount": bill.total_amount,
                    "split_method": bill.split_method,
                    "created_at": bill.created_at.isoformat(),
                }
            ),
            201,
        )


@app.route("/api/bills/<bill_id>", methods=["GET"])
def api_get_bill(bill_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    bill = Bill.query.get_or_404(bill_id)

    # Check if user is member of the group
    membership = GroupMember.query.filter_by(
        group_id=bill.group_id, user_id=user.id
    ).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    participants = (
        db.session.query(BillParticipant, User)
        .join(User)
        .filter(BillParticipant.bill_id == bill_id)
        .all()
    )
    items = BillItem.query.filter_by(bill_id=bill_id).all()

    return jsonify(
        {
            "id": bill.id,
            "title": bill.title,
            "description": bill.description,
            "subtotal": bill.subtotal,
            "tax_amount": bill.tax_amount,
            "tip_amount": bill.tip_amount,
            "total_amount": bill.total_amount,
            "split_method": bill.split_method,
            "created_at": bill.created_at.isoformat(),
            "participants": [
                {
                    "user": {
                        "id": participant_user.id,
                        "name": participant_user.name,
                        "email": participant_user.email,
                        "profile_picture": participant_user.profile_picture,
                    },
                    "amount_owed": participant.amount_owed,
                    "paid": participant.paid,
                    "custom_amount": participant.custom_amount,
                    "percentage": participant.percentage,
                }
                for participant, participant_user in participants
            ],
            "items": [
                {
                    "id": item.id,
                    "name": item.name,
                    "price": item.price,
                    "quantity": item.quantity,
                    "is_shared": item.is_shared,
                }
                for item in items
            ],
        }
    )


@app.route("/api/bills/<bill_id>/pay", methods=["POST"])
def api_mark_bill_paid(bill_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    participant = BillParticipant.query.filter_by(
        bill_id=bill_id, user_id=user.id
    ).first()
    if not participant:
        return jsonify({"error": "You are not a participant in this bill"}), 403

    participant.paid = True
    db.session.commit()

    return jsonify({"success": True, "message": "Marked as paid"})


@app.route("/api/groups/<group_id>/debts", methods=["GET"])
def api_get_group_debts(group_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Check if user is member of group
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this group"}), 403

    # Get all debts in the group
    debts = (
        db.session.query(
            UserDebt, User.name.label("debtor_name"), User.name.label("creditor_name")
        )
        .join(User, UserDebt.debtor_id == User.id)
        .join(User, UserDebt.creditor_id == User.id, aliased=True)
        .filter(UserDebt.group_id == group_id)
        .all()
    )

    return jsonify(
        [
            {
                "debtor_id": debt.debtor_id,
                "debtor_name": debt.debtor.name,
                "creditor_id": debt.creditor_id,
                "creditor_name": debt.creditor.name,
                "amount": debt.amount,
                "last_updated": debt.last_updated.isoformat(),
            }
            for debt, _, _ in debts
        ]
    )


@app.route("/api/parse-receipt", methods=["POST"])
def api_parse_receipt():
    """API endpoint to parse receipt images using OpenAI vision"""
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    # Check if file was uploaded
    if "receipt_image" not in request.files:
        return jsonify({"success": False, "error": "No receipt image provided"}), 400

    file = request.files["receipt_image"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    # Validate file type
    allowed_extensions = {"png", "jpg", "jpeg", "gif", "webp"}
    if not (
        "." in file.filename
        and file.filename.rsplit(".", 1)[1].lower() in allowed_extensions
    ):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Invalid file type. Please upload an image.",
                }
            ),
            400,
        )

    try:
        # Parse the receipt using our AI function
        result = parse_receipt_with_ai(file)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


# Initialize database
def init_db():
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    init_db()
    if os.environ.get("PROD") == "TRUE":
        import subprocess
        import sys

        port = os.environ.get("PORT", "5001")
        print(f"Starting production server with gunicorn on port {port}")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "gunicorn",
                "--bind",
                f"0.0.0.0:{port}",
                "--workers",
                "2",
                "app:app",
            ]
        )
    else:
        app.run(debug=True, port=5001)
