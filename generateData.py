import pandas as pd
import random
import os
from datetime import datetime, timedelta

random.seed(42)

# Generamos 1200 IPs únicas (la tarea pide 1000+)
def generar_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

NORMAL_IPS   = [generar_ip() for _ in range(1150)]
ATTACKER_IPS = [generar_ip() for _ in range(50)]
TODAS_IPS    = NORMAL_IPS + ATTACKER_IPS

def classify_ip(ip):
    last = int(ip.split(".")[-1])
    if last <= 51:  return "client"
    if last <= 102: return "server"
    if last <= 153: return "gateway"
    if last <= 204: return "external"
    return "honeypot"

def generar_evento(i, base_time):
    es_ataque = random.random() < 0.05  # 5% ataques

    if es_ataque:
        src_ip   = random.choice(ATTACKER_IPS)
        severity = random.randint(4, 5)
        port     = random.choice([22, 21, 3389])
    else:
        src_ip   = random.choice(NORMAL_IPS)
        severity = random.randint(1, 3)
        port     = random.choice([80, 443])

    dst_ip = random.choice(TODAS_IPS)

    return {
        "event_id"       : f"evt_{i}",
        "timestamp"      : (base_time + timedelta(seconds=i/1000)).isoformat(),
        "src_ip"         : src_ip,
        "dst_ip"         : dst_ip,
        "port"           : port,
        "severity"       : severity,
        "protocol"       : random.choice(["TCP", "UDP", "ICMP"]),
        "bytes"          : random.randint(64, 1500),
        "indicator"      : es_ataque,
        "source_category": classify_ip(src_ip),
        "dst_category"   : classify_ip(dst_ip),
        "event_count"    : 1
    }

# Generamos 60,000 eventos divididos en 5 fragmentos (tarea pide 5+)
os.makedirs("data", exist_ok=True)
base_time   = datetime.now()
TOTAL       = 60000
FRAGMENTOS  = 5
por_frag    = TOTAL // FRAGMENTOS

for f in range(FRAGMENTOS):
    inicio = f * por_frag
    fin    = inicio + por_frag
    eventos = [generar_evento(i, base_time) for i in range(inicio, fin)]
    df = pd.DataFrame(eventos)
    df.to_csv(f"data/fragment_{f+1}.csv", index=False)
    print(f"Fragmento {f+1} guardado — {len(df)} eventos")

print(f"\nTotal: {TOTAL} eventos en {FRAGMENTOS} archivos CSV")
print(f"IPs únicas aprox: {len(TODAS_IPS)}")