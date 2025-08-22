# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd

st.set_page_config(page_title="CyberLog Analyzer", page_icon="🔒")

st.title("🔒 CyberLog Analyzer")
st.markdown("### Analyse intelligente des logs de sécurité")

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("🚨 Alertes", "42", "12")
with col2:
    st.metric("📈 Events", "1,337", "156")  
with col3:
    st.metric("🌍 Pays", "23", "3")

st.markdown("## 📁 Upload de logs")
uploaded_file = st.file_uploader("Choisissez un fichier", type=['csv', 'txt'])

if uploaded_file:
    st.success("✅ Fichier uploadé!")
    st.balloons()