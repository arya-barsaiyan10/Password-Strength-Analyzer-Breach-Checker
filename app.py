from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

def check_breach(password):
    sha1 = __import__('hashlib').sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = requests.get(url)
    for line in resp.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0

def password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_+=" for c in password): score += 1
    return score

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        pw = request.form['password']
        strength = password_strength(pw)
        breach_count = check_breach(pw)
        result = f"Strength: {strength}/4<br>"
        result += "Breached: " + ("Yes" if breach_count else "No")
        if breach_count:
            result += f" ({breach_count} times)"
    return render_template_string("""
        <h1>Password Strength & Breach Checker</h1>
        <form method="post">
            Password: <input name="password" type="password">
            <button type="submit">Check</button>
        </form>
        <div>{{ result|safe }}</div>
    """, result=result)

if __name__ == '__main__':
    app.run(debug=True)
