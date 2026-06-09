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

@st.cache_resource                    #nuevo           
def load_nns():                                   
    return cargar_nns()  

if st.button("🔄 Ejecutar MapReduce"):
    st.cache_data.clear()  # fuerza recarga
    st.rerun()

ranking = load_data()

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

st.metric(
    label="📊 Total categorías",
    value=len(filtered_df)
)

st.metric(
    label="🚨 Total eventos outbound",
    value=int(filtered_df["Total Outbound Events"].sum())
)

st.subheader("📋 Ranking de categorías")

st.dataframe(filtered_df, use_container_width=True)

st.subheader("📈 Visualización")

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
 
    c1, c2, c3, c4, c5 = st.columns(5)                       
    c1.metric("Total Eventos",    int(perfil["total_eventos"]))           
    c2.metric("Severidad Prom",   round(perfil["severidad_avg"], 2))      
    c3.metric("Fracción TCP",     f"{round(perfil['fraccion_TCP']*100)}%")
    c4.metric("Fracción UDP",     f"{round(perfil['fraccion_UDP']*100)}%")
    c5.metric("Otros Protocolos", f"{round(perfil['fraccion_otros']*100)}%") 
 
    vecinos = buscar_vecinos(ip_elegida, lista_ips, matriz, indice, k=5)  
    st.dataframe(vecinos, use_container_width=True)           
    st.bar_chart(vecinos.set_index("IP Vecino")["Similitud Coseno"])      
