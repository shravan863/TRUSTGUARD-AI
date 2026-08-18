import flask
from detector import analyze_text

app = flask.Flask(__name__)

# Limit incoming request size to 16 KB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# Add security headers to every response
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )

    return response


@app.errorhandler(413)
def request_too_large(error):
    return "Request too large. Maximum size is 16 KB.", 413


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    user_input = ""

    if flask.request.method == "POST":
        user_input = flask.request.form.get("message", "").strip()

        if user_input:
            result = analyze_text(user_input)

    return flask.render_template(
        "index.html",
        result=result,
        user_input=user_input
    )


if __name__ == "__main__":
    app.run(debug=False)
