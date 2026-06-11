import streamlit as st
import pandas as pd
from MapReduce import run_mapreduce
from Nns import cargar_nns, buscar_vecinos

st.set_page_config(
    page_title="Cybersecurity Dashboard",
    layout="wide"
)

st.title("🛡️ Cybersecurity Threat Detection")

@st.cache_data
def load_data():
    return run_mapreduce()

@st.cache_resource
def load_nns():
    return cargar_nns()

if st.button("🔄 Ejecutar MapReduce"):
    st.cache_data.clear()
    st.rerun()

ranking, total_fragmentos = load_data()

st.info(
    f"MapReduce ejecutado sobre {total_fragmentos} fragmentos usando procesamiento paralelo."
)

df = pd.DataFrame(
    ranking,
    columns=["IP Category", "Total Outbound Events"]
)

st.sidebar.header("🔎 Filtros")

selected_categories = st.sidebar.multiselect(
    "Selecciona categorías",
    options=df["IP Category"].tolist(),
    default=df["IP Category"].tolist()
)

filtered_df = df[df["IP Category"].isin(selected_categories)]

# Panel 1
st.subheader("📊 Panel 1 — MapReduce Profiling")
st.metric(
    label="📊 Total categorías",
    value=len(filtered_df)
)

st.metric(
    label="🚨 Total eventos outbound",
    value=int(filtered_df["Total Outbound Events"].sum())
)

st.subheader("📋 Ranking de categorías")
st.dataframe(
    filtered_df,
    use_container_width=True
)

st.subheader("📈 Volumen outbound por categoría")
st.bar_chart(
    filtered_df.set_index("IP Category")
)

st.divider()

# Panel 2
st.subheader("🔍 Panel 2 — IPs con comportamiento similar")
lista_ips, matriz, indice, df_features = load_nns()

ip_elegida = st.selectbox(
    "Selecciona un IP:",
    options=lista_ips
)

if ip_elegida:
    perfil = df_features.loc[ip_elegida]
    st.markdown(f"**Perfil de `{ip_elegida}`:**")

    # Badge sospechoso
    sospechosa = perfil["severidad_avg"] >= 3.5 or perfil["fraccion_otros"] >= 0.50
    st.markdown(
        f"{'🔴 **SOSPECHOSA**' if sospechosa else '🟢 **NORMAL**'}"
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Eventos",    int(perfil["total_eventos"]))
    c2.metric("Severidad Prom",   round(perfil["severidad_avg"], 2))
    c3.metric("Fracción TCP",     f"{round(perfil['fraccion_TCP']*100)}%")
    c4.metric("Fracción UDP",     f"{round(perfil['fraccion_UDP']*100)}%")
    c5.metric("Otros Protocolos", f"{round(perfil['fraccion_otros']*100)}%")

    # Ahora recibe df_features como parámetro adicional
    vecinos = buscar_vecinos(ip_elegida, lista_ips, matriz, indice, df_features, k=5)
    st.dataframe(vecinos, use_container_width=True)
    st.bar_chart(vecinos.set_index("IP Vecino")["Distancia"])
    
    st.divider()
 
# ── Panel 3 — Threat Neighborhood Analysis ──────────────────────────────────
st.subheader("🧠 Panel 3 — Threat Neighborhood Analysis")
st.markdown(
    """
    **Pregunta creativa:** Cuando se consulta un IP de alta severidad,
    ¿sus 5 vecinos más cercanos también presentan `avg_severity` elevada?
    ¿Existe un *"vecindario de amenaza"* compacto en el espacio conductual,
    o los IPs peligrosos se dispersan entre el resto del tráfico?
    """
)
 
UMBRAL_SEVERIDAD = st.slider(
    "Umbral de alta severidad (avg_severity ≥)",
    min_value=1.0, max_value=5.0, value=3.5, step=0.1
)
 
# ── 1. Identificar IPs de alta severidad ────────────────────────────────────
lista_ips_p3, matriz_p3, indice_p3, df_features_p3 = load_nns()
 
ips_alta_sev = [
    ip for ip in lista_ips_p3
    if df_features_p3.loc[ip, "severidad_avg"] >= UMBRAL_SEVERIDAD
]
 
st.info(
    f"Se encontraron **{len(ips_alta_sev)}** IPs con `avg_severity` ≥ {UMBRAL_SEVERIDAD} "
    f"de un total de **{len(lista_ips_p3)}** IPs únicos."
)
 
if len(ips_alta_sev) == 0:
    st.warning("No hay IPs que superen el umbral definido. Reduce el valor del slider.")
else:
    # ── 2. Para cada IP amenazante → buscar 5 vecinos y medir su severidad ──
    registros = []
    for ip_amenaza in ips_alta_sev:
        sev_query = df_features_p3.loc[ip_amenaza, "severidad_avg"]
        try:
            vecinos_df = buscar_vecinos(ip_amenaza, lista_ips_p3, matriz_p3, indice_p3, df_features_p3, k=5)
        except ValueError:
            continue
 
        sevs_vecinos = [
            df_features_p3.loc[v, "severidad_avg"]
            for v in vecinos_df["IP Vecino"]
            if v in df_features_p3.index
        ]
        if not sevs_vecinos:
            continue
 
        avg_sev_vecinos = sum(sevs_vecinos) / len(sevs_vecinos)
        vecinos_alta_sev = sum(1 for s in sevs_vecinos if s >= UMBRAL_SEVERIDAD)
 
        registros.append({
            "IP Amenaza"              : ip_amenaza,
            "Severidad (query)"       : round(sev_query, 3),
            "Severidad prom. vecinos" : round(avg_sev_vecinos, 3),
            "Vecinos alta severidad"  : vecinos_alta_sev,
            "Vecinos totales"         : len(sevs_vecinos),
            "% vecinos amenaza"       : round(100 * vecinos_alta_sev / len(sevs_vecinos), 1),
        })
 
    df_panel3 = pd.DataFrame(registros)
 
    # ── 3. Métricas globales ─────────────────────────────────────────────────
    avg_sev_vecindario   = df_panel3["Severidad prom. vecinos"].mean()
    pct_vecinos_amenaza  = df_panel3["% vecinos amenaza"].mean()
    ips_cluster          = (df_panel3["Vecinos alta severidad"] >= 3).sum()
 
    col1, col2, col3 = st.columns(3)
    col1.metric(
        "Severidad prom. del vecindario",
        f"{avg_sev_vecindario:.2f}",
        help="Promedio de avg_severity de los 5 vecinos de todos los IPs amenazantes"
    )
    col2.metric(
        "% de vecinos también amenazantes",
        f"{pct_vecinos_amenaza:.1f}%",
        help="Porcentaje medio de vecinos que también superan el umbral de severidad"
    )
    col3.metric(
        "IPs con cluster amenazante (≥3/5 vecinos)",
        int(ips_cluster),
        help="IPs cuyo vecindario es mayoritariamente de alta severidad"
    )
 
    # ── 4. Tabla detallada ───────────────────────────────────────────────────
    st.subheader("📋 Detalle por IP amenazante")
    st.dataframe(
        df_panel3.sort_values("Severidad prom. vecinos", ascending=False),
        use_container_width=True
    )
 
    # ── 5. Gráfico: distribución de severidad promedio del vecindario ────────
    st.subheader("📊 Distribución de severidad promedio del vecindario")
    hist_data = df_panel3["Severidad prom. vecinos"].value_counts(bins=10).sort_index()
    st.bar_chart(hist_data)
 
    # ── 6. Gráfico: % de vecinos amenazantes ────────────────────────────────
    st.subheader("📊 ¿Cuántos vecinos también son amenazantes?")
    conteo_vecinos = (
        df_panel3["Vecinos alta severidad"]
        .value_counts()
        .sort_index()
        .rename(index={0:"0/5", 1:"1/5", 2:"2/5", 3:"3/5", 4:"4/5", 5:"5/5"})
    )
    st.bar_chart(conteo_vecinos)
 
    # ── 7. Conclusión automática ─────────────────────────────────────────────
    st.subheader("🔎 Conclusión")
    if pct_vecinos_amenaza >= 50:
        st.success(
            f"✅ **Sí existe un vecindario de amenaza compacto.**  \n"
            f"En promedio, el **{pct_vecinos_amenaza:.1f}%** de los vecinos "
            f"de un IP peligroso también son de alta severidad. "
            f"Los IPs amenazantes tienden a agruparse en el espacio conductual, "
            f"lo que sugiere que el modelo k-NN es útil para detectar amenazas por proximidad."
        )
    else:
        st.warning(
            f"⚠️ **Los IPs peligrosos se dispersan en el espacio conductual.**  \n"
            f"Solo el **{pct_vecinos_amenaza:.1f}%** de sus vecinos son también amenazantes. "
            f"Esto indica que la severidad alta no se correlaciona fuertemente con el "
            f"patrón de tráfico (protocolos, volumen), y que el k-NN por sí solo puede "
            f"no ser suficiente para aislar amenazas — se requieren features adicionales."
        )