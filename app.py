# =============================================================================
# app.py — A small Flask web app (intentionally vulnerable!)
# =============================================================================
# This app is PURPOSE-BUILT to have security issues so our scanning tools
# have real findings to catch. In a real job, you'd NEVER write code like this.
# Each vulnerability is labeled so you can see what the scanners flag.
#
# We're building a simple "user notes" API with these endpoints:
#   GET  /           → Health check (is the app running?)
#   GET  /notes      → Get all notes
#   POST /notes      → Create a new note
#   GET  /notes/<id> → Get a specific note by ID
# =============================================================================

import sqlite3  # Built-in Python database — lightweight, no server needed
import os       # For accessing environment variables and OS-level stuff

from flask import Flask, request, jsonify, render_template_string

# ---------------------------------------------------------------------------
# Create the Flask application instance
# ---------------------------------------------------------------------------
# Flask is a "micro web framework" — it handles HTTP requests/responses
# and routing (mapping URLs to Python functions) with minimal boilerplate.
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ===========================================================================
# 🚨 INTENTIONAL VULNERABILITY #1: Hardcoded Secret
# ===========================================================================
# In real apps, secrets (API keys, passwords, database credentials) should
# NEVER be in source code. They should come from environment variables or
# a secrets manager (like AWS Secrets Manager or HashiCorp Vault).
#
# TruffleHog (our secret scanner) should catch this.
# ===========================================================================
API_SECRET_KEY = "sk-proj-abc123superSecretKey456def789ghi012jkl345"
DATABASE_PASSWORD = "postgres://admin:password123@localhost:5432/mydb"

# ===========================================================================
# 🚨 INTENTIONAL VULNERABILITY #2: Debug mode enabled
# ===========================================================================
# Flask's debug mode shows detailed error pages with a Python console.
# If this runs in production, attackers can execute arbitrary Python code
# through the debugger. Semgrep (our SAST tool) should catch this.
# ===========================================================================
app.config["DEBUG"] = True


def get_db():
    """
    Connect to our SQLite database.

    SQLite stores the entire database in a single file (notes.db).
    This is great for small apps and demos — no database server needed.

    The 'connect' function returns a connection object we use to run SQL.
    """
    conn = sqlite3.connect("notes.db")

    # Row factory lets us access columns by name (row["title"])
    # instead of by index (row[0]). Much more readable.
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the database table if it doesn't exist yet.

    This runs once when the app starts. The 'notes' table has:
      - id: Auto-incrementing primary key (unique identifier)
      - title: The note's title (text, required)
      - content: The note's body (text, required)
      - created_at: Timestamp, auto-set to current time
    """
    conn = get_db()

    # Triple-quotes let us write multi-line strings in Python.
    # This SQL creates the table only if it doesn't already exist,
    # so it's safe to run multiple times.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 'commit' saves the changes to disk. Without this, the CREATE TABLE
    # would be rolled back (undone) when the connection closes.
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Route: Health Check
# ---------------------------------------------------------------------------
# The @app.route decorator tells Flask: "when someone visits '/', run this
# function." This is the simplest endpoint — just confirms the app is alive.
# Every production app has something like this for monitoring/load balancers.
# ---------------------------------------------------------------------------
@app.route("/")
def health_check():
    return jsonify({
        "status": "healthy",
        "app": "Security Pipeline Demo"
    })


# ---------------------------------------------------------------------------
# Route: Get All Notes
# ---------------------------------------------------------------------------
# GET /notes — Returns every note in the database as JSON.
# 'fetchall()' retrieves all rows from the query result.
# We convert each Row object to a dict so Flask can serialize it to JSON.
# ---------------------------------------------------------------------------
@app.route("/notes", methods=["GET"])
def get_notes():
    conn = get_db()
    notes = conn.execute("SELECT * FROM notes").fetchall()
    conn.close()

    # Convert sqlite3.Row objects → dicts → JSON response
    return jsonify([dict(note) for note in notes])


# ---------------------------------------------------------------------------
# Route: Create a Note
# ---------------------------------------------------------------------------
# POST /notes — Creates a new note from JSON in the request body.
# Example request body: {"title": "My Note", "content": "Hello world"}
#
# request.get_json() parses the JSON body that the client sent.
# We insert it into the database and return the new note's ID.
# ---------------------------------------------------------------------------
@app.route("/notes", methods=["POST"])
def create_note():
    data = request.get_json()

    # Basic validation: make sure required fields are present
    if not data or "title" not in data or "content" not in data:
        # 400 = "Bad Request" — the client sent invalid data
        return jsonify({"error": "title and content are required"}), 400

    conn = get_db()

    # =======================================================================
    # 🚨 INTENTIONAL VULNERABILITY #3: SQL Injection
    # =======================================================================
    # This uses Python string formatting to build the SQL query.
    # An attacker could send a title like:
    #   '; DROP TABLE notes; --
    # which would DELETE THE ENTIRE TABLE.
    #
    # The SAFE way is parameterized queries (shown commented out below).
    # Semgrep should catch this SQL injection vulnerability.
    #
    # SAFE version (what you'd use in production):
    #   cursor = conn.execute(
    #       "INSERT INTO notes (title, content) VALUES (?, ?)",
    #       (data["title"], data["content"])
    #   )
    # =======================================================================
    query = "INSERT INTO notes (title, content) VALUES ('{}', '{}')".format(
        data["title"], data["content"]
    )
    cursor = conn.execute(query)

    conn.commit()
    note_id = cursor.lastrowid  # Get the auto-generated ID of the new row
    conn.close()

    # 201 = "Created" — the resource was successfully created
    return jsonify({"id": note_id, "message": "Note created"}), 201


# ---------------------------------------------------------------------------
# Route: Get a Single Note
# ---------------------------------------------------------------------------
# GET /notes/<id> — Returns one note by its ID.
# The <int:note_id> in the route means Flask will:
#   1. Extract the number from the URL (e.g., /notes/5 → note_id=5)
#   2. Automatically reject non-integer values with a 404
# ---------------------------------------------------------------------------
@app.route("/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    conn = get_db()

    # The '?' is a parameter placeholder — SQLite safely substitutes the value.
    # This is the CORRECT way to handle user input in SQL (unlike the INSERT above).
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()  # fetchone() returns a single row (or None)
    conn.close()

    if note is None:
        # 404 = "Not Found" — the requested resource doesn't exist
        return jsonify({"error": "Note not found"}), 404

    return jsonify(dict(note))


# ===========================================================================
# 🚨 INTENTIONAL VULNERABILITY #4: Server-Side Template Injection (SSTI)
# ===========================================================================
# render_template_string() compiles user input as a Jinja2 template.
# An attacker could send: {{ config.items() }} to dump all app config,
# or even execute arbitrary Python code on the server.
#
# This is one of the most dangerous web vulnerabilities — it gives
# attackers full Remote Code Execution (RCE). Semgrep should catch this.
#
# The SAFE way: use render_template() with a .html FILE, never pass
# user input directly into a template string.
# ===========================================================================
@app.route("/search")
def search():
    # request.args.get() reads query parameters from the URL
    # e.g., /search?q=hello → q = "hello"
    q = request.args.get("q", "")

    # Directly embedding user input into a template = SSTI vulnerability
    template = "<h1>Search results for: " + q + "</h1>"
    return render_template_string(template)


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------
# This block only runs when you execute "python app.py" directly.
# It does NOT run when the file is imported as a module.
#
# host="0.0.0.0" means "listen on all network interfaces" — required
# inside Docker containers so the app is reachable from outside the container.
# (By default Flask only listens on 127.0.0.1/localhost)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()  # Create the database table on first run

    # =======================================================================
    # 🚨 INTENTIONAL VULNERABILITY #5: Debug mode in production
    # =======================================================================
    # debug=True here AGAIN — Semgrep should flag this too.
    # In production you'd use a proper WSGI server like Gunicorn:
    #   gunicorn app:app --bind 0.0.0.0:5000
    # =======================================================================
    app.run(host="0.0.0.0", port=5000, debug=True)
