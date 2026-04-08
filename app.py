# =============================================================================
# app.py — A small Flask web app (REMEDIATED version)
# =============================================================================
# This is the FIXED version of our intentionally vulnerable app.
# Every vulnerability that Semgrep flagged has been remediated.
# Compare this file to the original (in git history) to see what changed.
#
# Endpoints:
#   GET  /           → Health check (is the app running?)
#   GET  /notes      → Get all notes
#   POST /notes      → Create a new note
#   GET  /notes/<id> → Get a specific note by ID
#   GET  /search?q=  → Search notes (now safe from SSTI)
# =============================================================================

import sqlite3  # Built-in Python database — lightweight, no server needed
import os       # For accessing environment variables and OS-level stuff

from flask import Flask, request, jsonify
# ---------------------------------------------------------------------------
# FIX: Removed 'render_template_string' from the import.
# We now use 'render_template' which loads HTML from a file in /templates/,
# keeping user input out of the template compilation step entirely.
# (We actually don't even need render_template for our search endpoint
# anymore — we return JSON instead, which is safer and more consistent
# with the rest of our API.)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Create the Flask application instance
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ===========================================================================
# FIX #1: Secrets loaded from environment variables (was: hardcoded)
# ===========================================================================
# os.environ.get() reads a value from the operating system's environment.
# The second argument is a default used ONLY during local development.
#
# In production, these are set via:
#   - Docker: docker run -e API_SECRET_KEY=real_key ...
#   - GitHub Actions: stored in repo Settings → Secrets
#   - Cloud: AWS Secrets Manager, Azure Key Vault, etc.
#
# This way, secrets are NEVER in source code or git history.
# ===========================================================================
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "dev-only-placeholder")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///notes.db")

# ===========================================================================
# FIX #2: Debug mode controlled by environment variable (was: hardcoded True)
# ===========================================================================
# In development: set FLASK_DEBUG=1 in your terminal
# In production: don't set it (defaults to False)
#
# This ensures the interactive debugger is NEVER accidentally exposed.
# The debugger lets anyone execute arbitrary Python on your server —
# it's the difference between "website has a bug" and "attacker owns your server."
# ===========================================================================
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"


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
    # FIX #3: Parameterized query (was: string formatting → SQL injection)
    # =======================================================================
    # The '?' placeholders tell SQLite: "I'm going to give you the values
    # separately — treat them as DATA, never as SQL commands."
    #
    # Even if an attacker sends a title like: '; DROP TABLE notes; --
    # SQLite would just store that as a literal string, not execute it.
    #
    # This is called a "parameterized query" or "prepared statement" and
    # is the #1 defense against SQL injection in ANY language/database.
    #
    # BEFORE (vulnerable):
    #   query = "INSERT ... VALUES ('{}', '{}')".format(data["title"], ...)
    #   cursor = conn.execute(query)
    #
    # AFTER (safe):
    #   cursor = conn.execute("INSERT ... VALUES (?, ?)", (title, content))
    # =======================================================================
    cursor = conn.execute(
        "INSERT INTO notes (title, content) VALUES (?, ?)",
        (data["title"], data["content"])
    )

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
    # This was already correct in the original version.
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()  # fetchone() returns a single row (or None)
    conn.close()

    if note is None:
        # 404 = "Not Found" — the requested resource doesn't exist
        return jsonify({"error": "Note not found"}), 404

    return jsonify(dict(note))


# ===========================================================================
# FIX #4: Search returns safe JSON (was: SSTI via render_template_string)
# ===========================================================================
# BEFORE (vulnerable):
#   template = "<h1>Search results for: " + q + "</h1>"
#   return render_template_string(template)
#
# That was dangerous in TWO ways:
#   1. SSTI: render_template_string() compiles the string as a Jinja2
#      template. An attacker sending {{ config }} or {{ ''.__class__ }}
#      could execute arbitrary Python on the server.
#   2. XSS: User input concatenated into raw HTML could inject
#      <script> tags that run in other users' browsers.
#
# AFTER (safe):
#   Return a JSON response. jsonify() automatically escapes all values,
#   making both SSTI and XSS impossible. This is also more consistent
#   with the rest of our API (all other endpoints return JSON too).
#
# If you DID need to render HTML, the safe way is:
#   1. Create a template FILE: templates/search.html
#   2. Use render_template("search.html", query=q)
#   Jinja2 auto-escapes variables in template files, blocking XSS.
#   And since the template structure is in a file (not a string built
#   from user input), SSTI is impossible.
# ===========================================================================
@app.route("/search")
def search():
    # request.args.get() reads query parameters from the URL
    # e.g., /search?q=hello → q = "hello"
    q = request.args.get("q", "")

    conn = get_db()

    # Use parameterized query with LIKE for safe searching.
    # The '%' wildcards mean "match anything before and after the search term."
    # The '?' placeholder keeps the user input safely separated from SQL.
    notes = conn.execute(
        "SELECT * FROM notes WHERE title LIKE ? OR content LIKE ?",
        (f"%{q}%", f"%{q}%")
    ).fetchall()
    conn.close()

    return jsonify({
        "query": q,
        "count": len(notes),
        "results": [dict(note) for note in notes]
    })


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
    # FIX #5: Debug mode reads from environment variable (was: hardcoded True)
    # =======================================================================
    # In development: FLASK_DEBUG=1 python app.py
    # In production: use Gunicorn instead of app.run() entirely:
    #   gunicorn app:app --bind 0.0.0.0:5000
    # =======================================================================
    app.run(host="0.0.0.0", port=5000)
