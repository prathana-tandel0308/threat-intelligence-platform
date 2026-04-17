## Project Architecture
```text
threat-intelligence-platform/
│
├── 📁 src/                     # 🔥 MAIN SOURCE CODE
│   ├── collectors/
│   ├── database/
│   ├── processors/
│   └── services/
│
├── 📁 assets/                  # 📸 Screenshots (VERY IMPORTANT)
│   ├── week-1.png
│   ├── week-2-dashboard.png
│   ├── week-3-firewall.png
│   ├── week-4-dashboard.png
│
├── 📁 logs/ 
│   ├── dynamic_firewall.log
│   ├── blocked_ips.log
│
├── 📁 week wise redme file/    # 📄 Weekly documentation
│   ├── week-1.md
│   ├── week-2.md
│   ├── week-3.md
│   ├── week-4.md
│
├── firewall_engine.py          # 🔥 Core firewall logic
├── firewall.py
├── mongo_to_elastic.py
├── run_collectors.py
├── rollback.py
├── monitor.py
├── config.py
├── utils.py
│
├── requirements.txt            # dependencies
├── README.md                   # MAIN PROJECT FILE 🔥
├── .env
└── .gitignore
```