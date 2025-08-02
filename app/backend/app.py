from flask import Flask, request, jsonify, render_template, redirect, session
import os
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretpassword"

# DB setup
def init_db():
    conn = sqlite3.connect('recon.db')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        program TEXT,
        target TEXT,
        tool TEXT,
        severity TEXT,
        description TEXT
    )''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if not session.get("logged_in"):
        return redirect('/login')
    return render_template("app/frontend/templates/dashboard.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        if request.form["password"] == "hunter2":
            session["logged_in"] = True
            return redirect('/')
        return "Wrong password"
    return render_template("app/frontend/templates/login.html")

@app.route('/logout')
def logout():
    session["logged_in"] = False
    return redirect('/login')

@app.route('/api/findings', methods=["GET", "POST"])
def findings():
    conn = sqlite3.connect('recon.db')
    cur = conn.cursor()
    if request.method == "POST":
        data = request.json
        cur.execute("INSERT INTO findings (program, target, tool, severity, description) VALUES (?, ?, ?, ?, ?)", 
                    (data['program'], data['target'], data['tool'], data['severity'], data['description']))
        conn.commit()
    cur.execute("SELECT * FROM findings")
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
