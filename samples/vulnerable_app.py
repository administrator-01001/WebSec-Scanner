from flask import Flask, request, Response
import subprocess
import os

app = Flask(__name__)

DB = {"users": {"1": {"name": "Admin", "role": "admin"}, "2": {"name": "User", "role": "user"}}}


@app.route("/")
def index():
    return """
    <html>
    <head><title>Test App</title></head>
    <body>
        <h1>Welcome</h1>
        <p>Powered by Flask</p>
        <form action="/search" method="GET">
            <input name="q" placeholder="Search...">
            <button>Search</button>
        </form>
        <a href="/user?id=1">Profile</a>
        <a href="/api/data">API</a>
        <form action="/submit" method="POST">
            <input name="name">
            <input name="email">
            <button>Submit</button>
        </form>
    </body>
    </html>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Search results for: {q}</h1><p>No results found.</p>"


@app.route("/submit", methods=["POST"])
def submit():
    name = request.form.get("name", "")
    return f"<h1>Thanks {name}</h1>"


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    user_data = DB["users"].get(uid)
    if user_data:
        return f"<h1>{user_data['name']}</h1><p>Role: {user_data['role']}</p>"
    return "<h1>User not found</h1>", 404


@app.route("/api/data")
def api_data():
    return {"status": "ok", "data": [1, 2, 3]}


@app.route("/api/admin")
def api_admin():
    return {"status": "ok", "secret": "flag{admin_access}"}


@app.route("/debug")
def debug():
    return {"env": dict(os.environ), "cwd": os.getcwd()}


@app.route("/config")
def config():
    return {"db_host": "localhost", "db_user": "root", "db_pass": "secret123"}


@app.route("/.env")
def env():
    return "DB_PASSWORD=supersecret\nAPI_KEY=12345\nSECRET=abcde"


@app.route("/redirect")
def redir():
    target = request.args.get("url", "/")
    return Response(status=302, headers={"Location": target})


@app.route("/webhook")
def webhook():
    return {"webhook": "active"}


@app.route("/graphql")
def graphql():
    return {"error": "GraphQL endpoint requires POST"}


@app.route("/file")
def file():
    path = request.args.get("path", "")
    try:
        with open(path) as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
