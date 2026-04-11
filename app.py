from flask import Flask, render_template_string, request, jsonify, session, redirect
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
import geoip2.database

# ---------------- APP ----------------
app = Flask(__name__)
app.secret_key = "secret"
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------------- DB ----------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_db"]

collection = db["threats"]        # ✅ FIXED (was wrong before)
users = db["users"]
blocklist = db["blocklist"]

# ---------------- GEOIP ----------------
try:
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    reader = None

# ---------------- AUTO BLOCK ----------------
def auto_block():
    threats = collection.find({"severity": "critical"})

    for t in threats:
        ip = t.get("indicator")

        if not ip:
            continue

        exists = blocklist.find_one({"ip": ip, "active": True})

        if not exists:
            blocklist.insert_one({
                "ip": ip,
                "reason": "Auto-blocked",
                "active": True
            })

            socketio.emit("alert", {"ip": ip})

# ---------------- LOGIN ----------------
@app.route('/', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")

        user = users.find_one({"username": u, "password": p})

        if user:
            session["user"] = u
            return redirect("/dashboard")

    return render_template_string(LOGIN_HTML)

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if "user" not in session:
        return redirect("/")

    auto_block()

    total = collection.count_documents({})
    ip = collection.count_documents({"type": "ip"})
    domain = collection.count_documents({"type": "domain"})
    url = collection.count_documents({"type": "url"})
    hashv = collection.count_documents({"type": "hash"})
    c2 = collection.count_documents({"type": "c2"})

    return render_template_string(DASHBOARD_HTML,
        total=total, ip=ip, domain=domain,
        url=url, hash=hashv, c2=c2
    )

# ---------------- API CHART ----------------
@app.route('/api/chart')
def chart():
    data = list(collection.aggregate([
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]))
    return jsonify(data)

# ---------------- API GEO ----------------
@app.route('/api/geo')
def geo():
    if not reader:
        return jsonify([])

    ips = collection.find({"type": "ip"}).limit(50)
    result = []

    for d in ips:
        ip = d.get("indicator")
        try:
            r = reader.city(ip)
            result.append({
                "ip": ip,
                "lat": r.location.latitude,
                "lon": r.location.longitude
            })
        except:
            continue

    return jsonify(result)

# ---------------- SOCKET ----------------
@socketio.on('connect')
def connect():
    emit("msg", {"data": "connected"})

# ---------------- HTML ----------------

LOGIN_HTML = """
<h2>Login</h2>
<form method="POST">
<input name="username" placeholder="username"><br>
<input name="password" type="password" placeholder="password"><br>
<button>Login</button>
</form>
"""

DASHBOARD_HTML = """
<h1>🔥 Threat Intelligence Dashboard</h1>

<p>Total: {{total}}</p>
<p>IP: {{ip}}</p>
<p>Domain: {{domain}}</p>
<p>URL: {{url}}</p>
<p>Hash: {{hash}}</p>
<p>C2: {{c2}}</p>

<canvas id="chart"></canvas>
<div id="map" style="height:400px;"></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.socket.io/4.0.1/socket.io.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<script>
// 📊 Chart
fetch('/api/chart').then(r=>r.json()).then(d=>{
 new Chart(document.getElementById('chart'),{
  type:'bar',
  data:{
    labels:d.map(x=>x._id),
    datasets:[{
      label: "Threat Types",
      data:d.map(x=>x.count),
      backgroundColor:"red"
    }]
  }
 });
});

// 🌍 Map
const map = L.map('map').setView([20,0],2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

fetch('/api/geo').then(r=>r.json()).then(d=>{
 d.forEach(x=>{
  L.marker([x.lat,x.lon]).addTo(map).bindPopup(x.ip);
 });
});

// 🔔 Alerts
const socket = io();
socket.on("alert", (d)=>{
 alert("🚨 Blocked: " + d.ip);
});
</script>
"""

# ---------------- RUN ----------------
if __name__ == "__main__":
    socketio.run(app, debug=True)