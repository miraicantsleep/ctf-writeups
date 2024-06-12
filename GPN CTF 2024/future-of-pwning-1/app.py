from flask import Flask, request, redirect, url_for
import subprocess

app = Flask(__name__)


@app.route("/")
def upload_form():
    return """
    <!doctype html>
    <html>
    <body>
        <h2>ForwardCom Emulator</h2>
        Please upload a binary to emulate.
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return redirect(url_for("upload_form"))
    file = request.files["file"]
    file.save("/tmp/binary.ex")
    data = subprocess.check_output(["/app/forw", "-emu", "/tmp/binary.ex"])
    return data[-500:]

if __name__ == "__main__":
    app.run(debug=False)
