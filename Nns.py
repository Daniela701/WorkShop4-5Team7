import pandas as pd
import numpy as np
import glob
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import normalize

# 1 — Leer los datos y resumir cada IP en 5 números

def construir_features(ruta="data/*.csv"):
    """
    Cada IP queda resumida en 5 números (su "firma de comportamiento"):
    """
    archivos = glob.glob(ruta)
    df = pd.concat([pd.read_csv(f) for f in archivos], ignore_index=True)

    filas = []
    ips   = []

    for ip, grupo in df.groupby("src_ip"):
        total      = len(grupo)
        severidad  = grupo["severity"].mean()
        frac_tcp   = (grupo["protocol"] == "TCP").sum()  / total
        frac_udp   = (grupo["protocol"] == "UDP").sum()  / total
        frac_otros = 1.0 - frac_tcp - frac_udp

        filas.append([total, severidad, frac_tcp, frac_udp, frac_otros])
        ips.append(ip)

    # DataFrame con los features originales (útil para Panel 3)
    df_features = pd.DataFrame(
        filas, index=ips,
        columns=["total_eventos", "severidad_avg",
                 "fraccion_TCP", "fraccion_UDP", "fraccion_otros"]
    )
    df_features.index.name = "src_ip"

    # Normalizamos los vectores para que la comparación sea por "forma"
    # y no se vea afectada por IPs que simplemente generan más tráfico
    matriz = normalize(df_features.values, norm="l2")

    return ips, matriz, df_features

# 2 — Construir el índice de búsqueda

def construir_indice(matriz):
    """
    Prepara la estructura que permite buscar vecinos rápido.

    El índice k-NN organiza los vectores para que solo revise
    un subconjunto pequeño → mucho más rápido.
    similitud coseno: mide el ángulo entre dos vectores.
    """
    indice = NearestNeighbors(
        n_neighbors=6,     # pedimos 6 porque el #0 siempre es el IP mismo
        metric="cosine",
        algorithm="brute",
        n_jobs=-1          # usa todos los núcleos del procesador
    )
    indice.fit(matriz)
    return indice



# 3 — Consultar vecinos de un IP

def buscar_vecinos(ip, lista_ips, matriz, indice, k=5):
    """
    Dado un IP, devuelve sus k IPs más parecidas con su score.
    """
    if ip not in lista_ips:
        raise ValueError(f"El IP '{ip}' no existe en los datos.")

    idx    = lista_ips.index(ip)
    vector = matriz[idx].reshape(1, -1)

    distancias, indices = indice.kneighbors(vector)

    resultados = []
    for dist, i in zip(distancias[0], indices[0]):
        vecino = lista_ips[i]
        if vecino == ip:                    # saltamos el IP consultado
            continue
        similitud = round(1 - dist, 4)     # distancia coseno → similitud
        resultados.append({"IP Vecino": vecino, "Similitud Coseno": similitud})
        if len(resultados) == k:
            break

    return pd.DataFrame(resultados)

# la llama el Dashboard


def cargar_nns(ruta="data/*.csv"):
    """
    Carga todo de una sola vez. En Dashboard.py se usa así:

        from NNS import cargar_nns, buscar_vecinos
        lista_ips, matriz, indice, df_features = cargar_nns()
        resultado = buscar_vecinos("1.2.3.4", lista_ips, matriz, indice)
    """
    lista_ips, matriz, df_features = construir_features(ruta)
    indice = construir_indice(matriz)
    return lista_ips, matriz, indice, df_features
