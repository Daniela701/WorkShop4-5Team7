import streamlit as st
import pandas as pd
from MapReduce import run_mapreduce

st.set_page_config(
    page_title="Cybersecurity Dashboard",
    layout="wide"
)

st.title("🛡️ Cybersecurity Threat Detection")

@st.cache_data
def load_data():
    return run_mapreduce()

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