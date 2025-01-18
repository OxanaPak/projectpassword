from flask import Flask, request, render_template, session, redirect
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet
import certifi
import os

app=Flask(__name__)

app.config["MONGO_URI"] = "mongodb+srv://sanasana13:MongoDB1@cluster0.ohxkw.mongodb.net/PasswordSystem?retryWrites=true&w=majority&tlsCAFile="+ certifi.where()
mongo=PyMongo(app)
app.secret_key = "a_super_secure_random_key_12345"
encryption_key = b"LNtI82KaTzHUwVLJ0yQ23iQQcRXap4kKXNwOLfuQ0bE="
cipher = Fernet(encryption_key)
users_collection = mongo.db.users
passwords_collection = mongo.db.passwords
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()
def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="POST":
        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]
        if users_collection.find_one({"username":username}):
            return "The user already exists!"
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "username": username,
            "email": email,
            "password": hashed_password
        })
        session["username"] = username  
        return redirect("/profile")
    return render_template("index.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username":username})
        if not user:
            return "Invalid username or password!"
        if not check_password_hash(user["password"], password):
            return "invalid username or password!"
        session["username"] = username 
        return redirect("/profile")
    return render_template("login.html")
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    search_query = request.args.get("search", "").lower() 

    all_sites = passwords_collection.find({"username": username}).distinct("site")

    if search_query:
        filtered_sites = [site for site in all_sites if search_query in site.lower()]
    else:
        filtered_sites = all_sites

    return render_template("profile.html", username=username, sites=filtered_sites, search_query=search_query)

@app.route("/site/<site_name>")
def site_details(site_name):
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    logins = passwords_collection.find({"username": username, "site": site_name})
    decrypted_logins = []
    for entry in logins:
        if entry.get("password") is not None:
            try:
                decrypted_password = decrypt_password(entry["password"])
            except Exception:
                decrypted_password = "Unreadable (Decryption Error)"
            decrypted_logins.append({
                "login": entry.get("login", "Unknown Login"),
                "password": decrypted_password
            })

    return render_template("site_details.html", site_name=site_name, logins=decrypted_logins)
@app.route("/delete_login/<site_name>/<login>", methods=["POST"])
def delete_login(site_name, login):
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    passwords_collection.delete_one({"username": username, "site": site_name, "login": login})
    return redirect(f"/site/{site_name}")

@app.route("/add_site", methods=["POST"])
def add_site():
    if "username" not in session:
        return "You are not logged in!", 401

    site = request.form["site"]
    username = session["username"]
    if passwords_collection.find_one({"username": username, "site": site}):
        return "Site already exists!"
    passwords_collection.insert_one({"username": username, "site": site, "login": None, "password": None})
    return redirect("/profile")
@app.route("/logout")
def logout():
    session.clear()  
    return redirect("/")  

@app.route("/add_login/<site_name>", methods=["POST"])
def add_login(site_name):
    if "username" not in session:
        return "You are not logged in!", 401

    login = request.form["login"]
    password = request.form["password"]
    username = session["username"]
    encrypted_password = encrypt_password(password)
    passwords_collection.insert_one({
        "username": username,
        "site": site_name,
        "login": login,
        "password": encrypted_password
    })

    return redirect(f"/site/{site_name}")


@app.route("/")
def home():
    return render_template("index.html")
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=1000, debug=True)
