import csv

# ====== CONFIG ======
PHISHTANK_FILE = "online-valid.csv"
OPENPHISH_FILE = "feed.txt"
OUTPUT_FILE = "data/blacklist.txt"
LIMIT = 2000  # ambil maksimal 2000 URL dulu


urls = set()

# ---- Load PhishTank CSV ----
try:
    with open(PHISHTANK_FILE, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if "url" in row:
                urls.add(row["url"].strip())
            if len(urls) >= LIMIT:
                break
except FileNotFoundError:
    print("PhishTank file tidak ditemukan")

# ---- Load OpenPhish TXT ----
try:
    with open(OPENPHISH_FILE, encoding="utf-8") as f:
        for line in f:
            urls.add(line.strip())
            if len(urls) >= LIMIT:
                break
except FileNotFoundError:
    print("OpenPhish file tidak ditemukan")

# ---- Save to blacklist.txt ----
with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    for url in urls:
        out.write(url + "\n")

print(f"Saved {len(urls)} URLs to blacklist.txt")