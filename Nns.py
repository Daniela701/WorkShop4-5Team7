import pandas as pd
import numpy as np
import glob
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

# ── Umbrales para marcar un IP como sospechoso ────────────────────────────────
UMBRAL_SEVERIDAD  = 3.5   # severidad promedio alta
UMBRAL_OTROS      = 0.50  # >50% protocolo raro

def es_sospechoso(row):
    return row["severidad_avg"] >= UMBRAL_SEVERIDAD or row["fraccion_otros"] >= UMBRAL_OTROS

# ── 1. Construir features ─────────────────────────────────────────────────────
def construir_features(ruta="data/*.csv"):
    archivos = glob.glob(ruta)
    df = pd.concat([pd.read_csv(f) for f in archivos], ignore_index=True)

    filas, ips = [], []
    for ip, g in df.groupby("src_ip"):
        total     = len(g)
        severidad = g["severity"].mean()
        frac_tcp  = (g["protocol"] == "TCP").sum() / total
        frac_udp  = (g["protocol"] == "UDP").sum() / total
        frac_otros = 1.0 - frac_tcp - frac_udp
        filas.append([total, severidad, frac_tcp, frac_udp, frac_otros])
        ips.append(ip)

    df_features = pd.DataFrame(
        filas, index=ips,
        columns=["total_eventos", "severidad_avg", "fraccion_TCP", "fraccion_UDP", "fraccion_otros"]
    )
    df_features.index.name = "src_ip"

    # StandardScaler: cada feature queda en la misma escala → distancias reales
    scaler = StandardScaler()
    matriz = scaler.fit_transform(df_features.values).astype(np.float32)

    return ips, matriz, df_features

# ── 2. Construir índice ───────────────────────────────────────────────────────
def construir_indice(matriz):
    indice = NearestNeighbors(
        n_neighbors=6,
        metric="euclidean",   # distancia real entre comportamientos
        algorithm="ball_tree",
        n_jobs=-1
    )
    indice.fit(matriz)
    return indice

# ── 3. Buscar vecinos ─────────────────────────────────────────────────────────
def buscar_vecinos(ip, lista_ips, matriz, indice, df_features, k=5):
    if ip not in lista_ips:
        raise ValueError(f"El IP '{ip}' no existe en los datos.")

    idx    = lista_ips.index(ip)
    vector = matriz[idx].reshape(1, -1)
    distancias, indices = indice.kneighbors(vector)

    resultados = []
    for dist, i in zip(distancias[0], indices[0]):
        vecino = lista_ips[i]
        if vecino == ip:
            continue
        row = df_features.iloc[i]
        resultados.append({
            "IP Vecino":       vecino,
            "Distancia":       round(float(dist), 3),
            "Severidad Prom":  round(float(row["severidad_avg"]), 2),
            "Fracción Otros":  f'{round(float(row["fraccion_otros"])*100)}%',
            "⚠ Sospechoso":   "🔴 SÍ" if es_sospechoso(row) else "🟢 NO",
        })
        if len(resultados) == k:
            break

    return pd.DataFrame(resultados)

# ── Entrada única para el Dashboard ──────────────────────────────────────────
def cargar_nns(ruta="data/*.csv"):
    lista_ips, matriz, df_features = construir_features(ruta)
    indice = construir_indice(matriz)
    return lista_ips, matriz, indice, df_features