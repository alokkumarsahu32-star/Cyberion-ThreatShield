
import os
import getpass

from dotenv import load_dotenv
from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import User

load_dotenv(override=True)

username = os.getenv("ADMIN_USERNAME", "admin")
new_password = getpass.getpass("Enter your new admin password: ")
confirm_password = getpass.getpass("Confirm your new admin password: ")

if len(new_password) < 12:
    raise SystemExit("Password must be at least 12 characters.")

if new_password != confirm_password:
    raise SystemExit("Passwords do not match.")

with SessionLocal() as db:
    user = db.scalar(select(User).where(User.username == username))

    if user is None:
        raise SystemExit(
            f"Admin '{username}' not found. Check ADMIN_USERNAME in .env."
        )

    user.password_hash = hash_password(new_password)
    db.commit()

print("Admin password changed successfully.")
