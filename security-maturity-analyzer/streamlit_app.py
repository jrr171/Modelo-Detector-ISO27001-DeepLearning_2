"""
Dossier 27001 — Evaluador de Madurez ISO/IEC 27001:2022
Diseño editorial «Dossier» acoplado al backend de Deep Learning.
"""

import sys, io, json, tempfile, os, math
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from analyzer.log_parser       import LogParser
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer  import MaturityScorer, compute_gap_analysis, GapAnalysis
from analyzer.report_generator import export_html, export_json
from rules.iso27001_controls   import MATURITY_LEVELS, ISO27001_DOMAINS

# ────────────────────────────────────────────────────────────────────────────
# Paleta Dossier (alineada con system.css del Proyecto Tesis)
# ────────────────────────────────────────────────────────────────────────────
C = {
    "signal":  "#ff4d00",
    "lvl": {
        0: "#b5321f", 1: "#d6541f", 2: "#e08a1e",
        3: "#c9a83a", 4: "#7fa84e", 5: "#4e8c4a",
    },
    "domains": ["#ff4d00","#c9a83a","#7fa84e","#e08a1e","#d6541f","#b5321f"],
    "risk":    "#d6451f",
    "safe":    "#7fa84e",
    "warn":    "#e0a01e",
}

def level_color(lvl): return C["lvl"].get(lvl, "#9a958a")
LEVEL_COLORS = C["lvl"]

def score_color(s):
    if s >= 81: return C["lvl"][5]
    if s >= 61: return C["lvl"][4]
    if s >= 41: return C["lvl"][3]
    if s >= 21: return C["lvl"][2]
    if s >  0:  return C["lvl"][1]
    return C["lvl"][0]

def hex_rgba(hex_color: str, alpha: float = 1.0) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"rgba({r},{g},{b},{alpha})"

PLOTLY_FONT = dict(family="'JetBrains Mono', 'Courier New', monospace", size=11, color="#1a1814")
PLOTLY_DARK = dict(
    paper_bgcolor="#f0ede4",
    plot_bgcolor="#e8e4d9",
    font=PLOTLY_FONT,
)
PLOTLY_AXIS_DARK = dict(
    gridcolor="#c8c4b8",
    tickfont=dict(color="#4a4640", size=10),
)

def apply_dossier_theme(fig, polar=False):
    fig.update_layout(
        paper_bgcolor="#f0ede4",
        plot_bgcolor="#e8e4d9",
        font=PLOTLY_FONT,
        legend=dict(font=dict(color="#4a4640", size=10), bgcolor="rgba(0,0,0,0)"),
    )
    if not polar:
        try:
            fig.update_xaxes(**PLOTLY_AXIS_DARK)
            fig.update_yaxes(**PLOTLY_AXIS_DARK)
        except Exception:
            pass
    return fig

# ────────────────────────────────────────────────────────────────────────────
# Page config
# ────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Dossier 27001 — Evaluador de Madurez ISO/IEC 27001:2022",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ────────────────────────────────────────────────────────────────────────────
# CSS — Diseño editorial «Dossier» (sistema completo del Proyecto Tesis)
# ────────────────────────────────────────────────────────────────────────────
DOSSIER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Bodoni+Moda:ital,opsz,wght@0,6..96,400;0,6..96,700;0,6..96,800;0,6..96,900;1,6..96,500;1,6..96,800&family=Archivo:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ============================================================
   DOSSIER 27001 — Sistema de diseño oficial (Dossier-27001.html)
   Editorial brutalista · lujo refinado · instrumento técnico
   ============================================================ */

:root {
  --ink:        #f0ede4;  --ink-panel:  #e8e4d9;
  --ink-raise:  #ddd9cc;  --ink-sink:   #f5f2eb;
  --bone:       #1a1814;  --bone-dim:   #4a4640;  --bone-faint: #7a7570;
  --line:       #c8c4b8;  --line-soft:  #d8d4c8;
  --signal:      #c43a00; --signal-deep: #9e2e00; --signal-glow: rgba(196,58,0,0.20);
  --lvl-0: #b5321f; --lvl-1: #d6541f; --lvl-2: #c8860a;
  --lvl-3: #a08820; --lvl-4: #4a7830; --lvl-5: #2e6028;
  --risk: #b5321f;  --safe: #4a7830;  --warn: #c8860a;
  --serif:  'Bodoni Moda', Georgia, serif;
  --grotesk:'Archivo', system-ui, sans-serif;
  --mono:   'JetBrains Mono', monospace;
}

/* === Reset Streamlit === */
html, body { margin:0; padding:0; background:var(--ink) !important; color:var(--bone) !important; font-family:var(--grotesk) !important; -webkit-font-smoothing:antialiased; }
.stApp,[data-testid="stAppViewContainer"],[data-testid="block-container"],.main,.main>div { background:var(--ink) !important; }
.block-container,[data-testid="block-container"] { padding:0 !important; max-width:100% !important; }
p,span,div,li { color:var(--bone); }
::selection { background:var(--signal); color:#fff; }

/* Sidebar */
[data-testid="stSidebar"],section[data-testid="stSidebar"] { background:var(--ink-sink) !important; border-right:1px solid var(--line) !important; }
[data-testid="stSidebar"] * { color:var(--bone-dim) !important; }
[data-testid="stSidebar"] b,[data-testid="stSidebar"] strong { color:var(--bone) !important; }

/* Botones */
.stButton>button {
  font-family:var(--grotesk) !important; font-weight:800 !important;
  text-transform:uppercase !important; letter-spacing:0.1em !important;
  font-size:0.8rem !important; padding:14px 24px !important;
  border:1px solid var(--line) !important; background:transparent !important;
  color:var(--bone) !important; border-radius:0 !important;
  transition:transform .25s cubic-bezier(.2,.8,.2,1),background .25s,border-color .25s !important;
}
.stButton>button:hover { transform:translateY(-2px); border-color:var(--bone) !important; }
.stButton>button[kind="primary"] { background:var(--signal) !important; border-color:var(--signal) !important; }
.stButton>button[kind="primary"]:hover { background:var(--signal-deep) !important; border-color:var(--signal-deep) !important; box-shadow:0 14px 40px -12px var(--signal-glow) !important; }

/* Download buttons */
[data-testid="stDownloadButton"]>button { font-family:var(--grotesk) !important; font-weight:800 !important; text-transform:uppercase !important; letter-spacing:0.1em !important; border-radius:0 !important; border:1px solid var(--line) !important; background:transparent !important; color:var(--bone) !important; }
[data-testid="stDownloadButton"]>button[kind="primary"] { background:var(--signal) !important; border-color:var(--signal) !important; }

/* Inputs */
.stTextArea textarea,.stTextInput input { background:var(--ink-sink) !important; border:1px solid var(--line) !important; color:var(--bone) !important; border-radius:0 !important; font-family:var(--mono) !important; }
.stTextArea textarea:focus,.stTextInput input:focus { border-color:var(--signal) !important; box-shadow:none !important; }
textarea::placeholder { color:var(--bone-faint) !important; }

/* File uploader */
[data-testid="stFileUploader"] { border:1px dashed var(--line) !important; background:var(--ink-sink) !important; border-radius:0 !important; }
[data-testid="stFileUploader"] * { color:var(--bone-dim) !important; }

/* Tabs */
[data-baseweb="tab-list"] { background:var(--ink) !important; border-bottom:1px solid var(--line) !important; }
[data-baseweb="tab"] { font-family:var(--mono) !important; font-size:0.72rem !important; letter-spacing:0.12em !important; text-transform:uppercase !important; color:var(--bone-faint) !important; background:transparent !important; border-radius:0 !important; padding:10px 18px !important; }
[data-baseweb="tab"]:hover { color:var(--bone-dim) !important; }
[data-baseweb="tab"][aria-selected="true"] { color:var(--bone) !important; }
[data-baseweb="tab-highlight"] { background-color:var(--signal) !important; height:2px !important; }
[data-baseweb="tab-border"] { background-color:var(--line) !important; }
[data-baseweb="tab-panel"] { background:var(--ink) !important; padding:24px 48px !important; }

/* Expanders */
[data-testid="stExpander"] { border:1px solid var(--line) !important; background:var(--ink-panel) !important; border-radius:0 !important; }
[data-testid="stExpander"] summary { font-family:var(--mono) !important; font-size:0.76rem !important; color:var(--bone-dim) !important; background:var(--ink-panel) !important; padding:12px 16px !important; }
[data-testid="stExpander"] summary:hover { color:var(--bone) !important; }
[data-testid="stExpander"] [data-testid="stExpanderDetails"] { background:var(--ink-panel) !important; border-top:1px solid var(--line) !important; }

/* Métricas */
[data-testid="stMetricValue"] { font-family:var(--serif) !important; font-weight:800 !important; color:var(--bone) !important; }
[data-testid="stMetricLabel"] { font-family:var(--mono) !important; font-size:0.68rem !important; color:var(--bone-faint) !important; letter-spacing:0.12em !important; text-transform:uppercase !important; }

/* Sliders */
[data-testid="stSlider"] label { color:var(--bone-dim) !important; font-family:var(--mono) !important; }
[data-testid="stSlider"] [data-baseweb="slider"] [role="slider"] { background:var(--signal) !important; border-color:var(--signal) !important; }

/* Progress */
[data-testid="stProgress"]>div>div { background:var(--line) !important; border-radius:0 !important; }
[data-testid="stProgress"]>div>div>div { background:var(--signal) !important; border-radius:0 !important; }
[data-testid="stProgress"] p { color:var(--bone-dim) !important; font-family:var(--mono) !important; font-size:0.72rem !important; }

/* Alerts */
[data-testid="stAlert"] { border-radius:0 !important; border-left-width:3px !important; }
.stSuccess { background:rgba(78,140,74,0.12) !important; border-color:var(--safe) !important; }
.stInfo { background:rgba(201,168,58,0.08) !important; border-color:var(--warn) !important; }
.stWarning { background:rgba(224,138,30,0.10) !important; border-color:var(--warn) !important; }
.stError { background:rgba(181,50,31,0.10) !important; border-color:var(--lvl-0) !important; }
[data-testid="stAlert"] p,[data-testid="stAlert"] div { color:var(--bone) !important; }

/* Dataframe */
[data-testid="stDataFrame"] { background:var(--ink-panel) !important; }
[data-testid="stDataFrame"] thead th { background:var(--ink-sink) !important; color:var(--bone-faint) !important; font-family:var(--mono) !important; font-size:0.7rem !important; }
[data-testid="stDataFrame"] tbody td { color:var(--bone-dim) !important; }

/* Caption / Markdown */
[data-testid="stCaptionContainer"] { color:var(--bone-faint) !important; font-family:var(--mono) !important; font-size:0.7rem !important; }
[data-testid="stMarkdownContainer"] h1,[data-testid="stMarkdownContainer"] h2,[data-testid="stMarkdownContainer"] h3 { color:var(--bone) !important; font-family:var(--serif) !important; }
[data-testid="stMarkdownContainer"] p { color:var(--bone-dim); }
[data-testid="stMarkdownContainer"] b,[data-testid="stMarkdownContainer"] strong { color:var(--bone) !important; }

/* Spinner */
[data-testid="stSpinner"] div { border-top-color:var(--signal) !important; }

/* Scrollbar */
::-webkit-scrollbar { width:10px; height:10px; }
::-webkit-scrollbar-track { background:var(--ink-sink); }
::-webkit-scrollbar-thumb { background:var(--line); border:2px solid var(--ink-sink); }
::-webkit-scrollbar-thumb:hover { background:var(--signal); }

/* ════════════ COMPONENTES DOSSIER ════════════ */

/* Efecto grano de película (del Dossier-27001.html original) */
.grain { position:fixed; inset:0; z-index:9000; pointer-events:none; opacity:0.18; mix-blend-mode:multiply; background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E"); }
.vignette { position:fixed; inset:0; z-index:8999; pointer-events:none; background:radial-gradient(130% 90% at 50% 0%, transparent 60%, rgba(180,170,150,0.25) 100%); }

/* Masthead editorial */
.dossier-masthead { border-bottom:2px solid var(--bone); background:rgba(240,237,228,0.97); backdrop-filter:blur(20px); }
.dossier-masthead-top { display:flex; align-items:stretch; justify-content:space-between; border-bottom:1px solid var(--line); font-family:var(--mono); font-size:0.65rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-dim); }
.dossier-masthead-top>div { padding:9px 48px; }
.dossier-masthead-top .mt-mid { flex:1; text-align:center; border-left:1px solid var(--line); border-right:1px solid var(--line); display:flex; align-items:center; justify-content:center; gap:14px; }
.dossier-masthead-main { display:flex; align-items:center; justify-content:space-between; padding:18px 48px; gap:24px; }
.dossier-title { font-family:var(--serif); font-weight:800; font-size:clamp(1.6rem,3vw,2.6rem); letter-spacing:-0.02em; margin:0; color:var(--bone); }
.dossier-title .iso { color:var(--signal); font-style:italic; }
.live-dot { width:7px; height:7px; border-radius:50%; background:var(--signal); display:inline-block; box-shadow:0 0 0 0 var(--signal-glow); animation:pulse 2.4s infinite; }
@keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(255,77,0,.3)} 70%{box-shadow:0 0 0 10px transparent} 100%{box-shadow:0 0 0 0 transparent} }

/* KPI Strip */
.kpi-strip { display:grid; grid-template-columns:repeat(6,1fr); border:1px solid var(--line); border-bottom:0; margin:0 48px; }
.kpi-cell { border-right:1px solid var(--line); border-bottom:1px solid var(--line); padding:22px 20px 24px; position:relative; overflow:hidden; transition:background .25s; }
.kpi-cell:last-child { border-right:0; }
.kpi-cell:hover { background:var(--ink-panel); }
.kpi-lbl { font-family:var(--mono); font-size:0.56rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-faint); }
.kpi-val { font-family:var(--serif); font-weight:800; font-size:clamp(1.6rem,2.5vw,2.4rem); line-height:1; margin-top:12px; letter-spacing:-0.02em; }
.kpi-val small { font-family:var(--mono); font-size:0.75rem; font-weight:400; color:var(--bone-faint); }
.kpi-foot { font-family:var(--mono); font-size:0.58rem; color:var(--bone-dim); margin-top:8px; }

/* Sección editorial */
.dossier-section { padding:clamp(36px,5vw,80px) 48px; }
.section-head { display:grid; grid-template-columns:auto 1fr; gap:22px; align-items:start; margin-bottom:40px; }
.section-num { font-family:var(--serif); font-weight:800; font-style:italic; font-size:clamp(2.4rem,4vw,4rem); line-height:0.85; color:var(--signal); }
.section-title { font-family:var(--serif); font-weight:700; letter-spacing:-0.02em; font-size:clamp(1.6rem,3vw,2.8rem); line-height:1.05; margin:0 0 10px; color:var(--bone); }
.section-kicker { max-width:62ch; color:var(--bone-dim); font-size:0.96rem; line-height:1.6; }
.section-kicker b { color:var(--bone); }

/* Panel */
.panel { border:1px solid var(--line); background:var(--ink-panel); }
.panel-head { display:flex; align-items:center; justify-content:space-between; padding:14px 20px; border-bottom:1px solid var(--line); }
.panel-head h4 { margin:0; font-family:var(--grotesk); font-weight:800; font-size:0.8rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--bone); }
.panel-head .ph-tag { font-family:var(--mono); font-size:0.58rem; letter-spacing:0.16em; color:var(--signal); text-transform:uppercase; }
.panel-body { padding:24px 20px; }

/* Gap banner */
.gap-banner { border:1px solid var(--signal); background:linear-gradient(180deg,rgba(255,77,0,0.07),transparent); padding:24px 28px; display:grid; grid-template-columns:auto 1fr auto; gap:24px; align-items:center; }
.gap-banner.ok { border-color:var(--safe); background:linear-gradient(180deg,rgba(127,168,78,0.07),transparent); }
.gap-icon { font-family:var(--serif); font-style:italic; font-weight:800; font-size:2.8rem; color:var(--signal); line-height:1; }
.gap-banner.ok .gap-icon { color:var(--safe); }
.gap-title { font-family:var(--grotesk); font-weight:800; text-transform:uppercase; letter-spacing:0.08em; font-size:0.9rem; }
.gap-text { color:var(--bone-dim); font-size:0.88rem; line-height:1.6; margin-top:8px; max-width:70ch; }
.gap-eff { text-align:right; border-left:1px solid var(--line); padding-left:24px; }
.gap-eff .ge-num { font-family:var(--serif); font-weight:800; font-size:2.4rem; line-height:1; color:var(--bone); }
.gap-eff .ge-lbl { font-family:var(--mono); font-size:0.58rem; letter-spacing:0.16em; text-transform:uppercase; color:var(--bone-faint); margin-top:5px; }

/* Dom cards */
.dom-card { border:1px solid var(--line); background:var(--ink-panel); padding:20px; position:relative; overflow:hidden; transition:transform .3s,border-color .3s; }
.dom-card:hover { transform:translateY(-3px); }
.dom-card .dc-bar-top { position:absolute; top:0; left:0; height:3px; right:0; }
.dom-card .dc-id { font-family:var(--serif); font-weight:800; font-style:italic; font-size:1.4rem; }
.dom-card .dc-name { font-weight:700; font-size:0.88rem; margin-top:4px; color:var(--bone); }
.dom-card .dc-score { font-family:var(--serif); font-weight:800; font-size:2.4rem; line-height:1; margin:14px 0 2px; letter-spacing:-0.02em; }
.dom-card .dc-score small { font-family:var(--mono); font-size:0.68rem; color:var(--bone-faint); font-weight:400; }
.dom-card .dc-lvl { font-family:var(--mono); font-size:0.62rem; letter-spacing:0.08em; text-transform:uppercase; }
.dc-track { height:5px; background:var(--ink-sink); margin:14px 0 12px; overflow:hidden; }
.dc-fill { height:100%; }
.dc-meta { display:flex; justify-content:space-between; font-family:var(--mono); font-size:0.6rem; color:var(--bone-dim); }
.dc-meta b { color:var(--bone); }

/* Hallazgos */
.find-item { display:grid; grid-template-columns:auto 1fr; gap:14px; padding:14px 0; border-bottom:1px solid var(--line-soft); align-items:start; }
.find-item:last-child { border-bottom:0; }
.find-idx { font-family:var(--mono); font-size:0.68rem; color:var(--risk); padding-top:2px; }
.rec-idx  { font-family:var(--mono); font-size:0.68rem; color:var(--safe); padding-top:2px; }
.find-txt { font-size:0.88rem; line-height:1.55; color:var(--bone-dim); }
.find-txt b { color:var(--bone); }

/* DL header */
.dl-band-header { background:var(--ink-sink); border-top:2px solid var(--bone); border-bottom:1px solid var(--line); padding:32px 48px; }

/* Reglas / utilidades */
.rule   { height:1px;  background:var(--line); border:0; }
.rule-2 { height:2px;  background:var(--bone); border:0; }
.eyebrow { font-family:var(--mono); font-size:0.64rem; letter-spacing:0.42em; text-transform:uppercase; color:var(--bone-dim); }

/* Footer */
.dossier-footer { border-top:2px solid var(--bone); padding:40px 48px 56px; margin-top:48px; }
.foot-mark { font-family:var(--serif); font-weight:800; font-size:1.8rem; color:var(--bone); }
.foot-mark .iso { color:var(--signal); font-style:italic; }
.foot-caption { font-family:var(--mono); font-size:0.68rem; color:var(--bone-faint); line-height:1.9; margin-top:10px; letter-spacing:0.04em; }

/* Animacion reveal del diseño original */
@keyframes revealIn { from { transform:translateY(24px); } to { transform:none; } }
.reveal { opacity:1; animation:revealIn .9s cubic-bezier(.2,.8,.2,1); }
</style>
"""

st.markdown(DOSSIER_CSS, unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# Sidebar compacta (referencia)
# ────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style='font-family:var(--serif);font-weight:800;font-size:1.4rem;color:#f0ede4;margin-bottom:16px'>
    Dossier <span style='color:#ff4d00;font-style:italic'>27001</span>
    </div>
    <div style='font-family:var(--mono);font-size:0.64rem;color:#67635b;letter-spacing:0.16em;text-transform:uppercase;margin-bottom:18px'>
    ISO/IEC 27001:2022 · COBIT 5
    </div>
    """, unsafe_allow_html=True)
    st.markdown("**Escala de Madurez COBIT**")
    for i in range(6):
        info = MATURITY_LEVELS[i]
        lo, hi = info["range"]
        lc = level_color(i)
        rng = f"{lo}–{hi}%" if i > 0 else "0%"
        st.markdown(
            f"<div style='padding:5px 8px;margin-bottom:4px;border-left:3px solid {lc};"
            f"background:{lc}11;font-family:var(--mono);font-size:0.76rem'>"
            f"<span style='color:{lc};font-weight:700'>Nv {i}</span> · {rng}<br>"
            f"<span style='font-size:0.68rem;color:#9a958a'>{info['name']}</span></div>",
            unsafe_allow_html=True,
        )
    st.markdown("---")
    st.caption("ISO/IEC 27001:2022 · COBIT 5 · Deep Learning")

# ────────────────────────────────────────────────────────────────────────────
# MASTHEAD editorial
# ────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="grain"></div>
<div class="vignette"></div>
<div class="dossier-masthead">
  <div class="dossier-masthead-top">
    <div>ISO/IEC 27001:2022</div>
    <div class="mt-mid"><span class="live-dot"></span><span>Instrumento de Auditoría · v2.2</span></div>
    <div>COBIT 5 · 93 Controles</div>
  </div>
  <div class="dossier-masthead-main">
    <h1 class="dossier-title">Dossier <span class="iso">27001</span></h1>
    <div style="font-family:var(--mono);font-size:0.62rem;color:var(--bone-faint);letter-spacing:0.14em;text-transform:uppercase">
      Evaluador de Madurez en Seguridad de la Información
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# DESCRIPCIÓN + KPI STRIP (entre masthead y fuente de datos)
# ────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:0 48px; border-bottom:1px solid var(--line);">
  <div style="display:grid; grid-template-columns:1fr auto; gap:40px; align-items:stretch; padding:32px 0;">

    <!-- Descripción izquierda -->
    <div style="display:flex; flex-direction:column; justify-content:center; max-width:58ch;">
      <p style="font-family:var(--grotesk); font-size:1.05rem; line-height:1.7; color:var(--bone-dim); margin:0;">
        Un instrumento de evaluación que clasifica eventos de log
        según los <b style="color:var(--bone)">4 temas del Anexo A</b> de ISO/IEC 27001:2022 y
        calcula el nivel de madurez COBIT con apoyo de <b style="color:var(--bone)">Deep Learning</b>.
      </p>
    </div>

    <!-- KPI cells derecha -->
    <div style="display:grid; grid-template-columns:repeat(4,1fr); border-left:1px solid var(--line);">

      <div style="border-right:1px solid var(--line); padding:24px 28px 20px;">
        <div style="font-family:var(--serif); font-weight:800; font-size:clamp(1.8rem,2.5vw,2.6rem); line-height:1; color:var(--bone); letter-spacing:-0.02em;">93</div>
        <div style="font-family:var(--mono); font-size:0.56rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-faint); margin-top:10px;">Controles</div>
      </div>

      <div style="border-right:1px solid var(--line); padding:24px 28px 20px;">
        <div style="font-family:var(--serif); font-weight:800; font-size:clamp(1.8rem,2.5vw,2.6rem); line-height:1; color:var(--bone); letter-spacing:-0.02em;">4</div>
        <div style="font-family:var(--mono); font-size:0.56rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-faint); margin-top:10px;">Temas Anexo A</div>
      </div>

      <div style="border-right:1px solid var(--line); padding:24px 28px 20px;">
        <div style="font-family:var(--serif); font-weight:800; font-size:clamp(1.8rem,2.5vw,2.6rem); line-height:1; color:var(--bone); letter-spacing:-0.02em;">0–5</div>
        <div style="font-family:var(--mono); font-size:0.56rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-faint); margin-top:10px;">Niveles COBIT</div>
      </div>

      <div style="padding:24px 28px 20px;">
        <div style="font-family:var(--serif); font-weight:800; font-size:clamp(1.8rem,2.5vw,2.6rem); line-height:1; color:var(--bone); letter-spacing:-0.02em;">3</div>
        <div style="font-family:var(--mono); font-size:0.56rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--bone-faint); margin-top:10px;">Modelos DL</div>
      </div>

    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# ENTRADA DE DATOS — tabs
# ────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding: 40px 48px 0">
  <div class="eyebrow" style="color:var(--signal);margin-bottom:20px">● Fuente de Datos</div>
</div>
""", unsafe_allow_html=True)

with st.container():
    tab_up, tab_demo, tab_paste, tab_compare = st.tabs([
        "01 · Subir archivos", "02 · Demo ISO 27001:2022",
        "03 · Pegar texto",    "04 · Comparar logs"
    ])

    entries, source_label = [], ""

    with tab_up:
        st.markdown("**Formatos soportados:** Apache/Nginx `.log`, Linux syslog/auth.log, Windows Event Log `.csv`, JSON `.json`, `.gz`")
        uploaded = st.file_uploader(
            "Arrastra tus archivos de log aquí",
            type=["log","txt","csv","json","gz"], accept_multiple_files=True
        )
        if uploaded:
            with tempfile.TemporaryDirectory() as d:
                for f in uploaded:
                    (Path(d) / f.name).write_bytes(f.read())
                parser = LogParser()
                entries = parser.parse_path(d)
                source_label = f"{len(uploaded)} archivo(s)"
                st.success(f"✅ {parser.stats['parsed_ok']:,} eventos leídos de {len(uploaded)} archivo(s)")

    with tab_demo:
        st.markdown("""
        <p style='color:var(--bone-dim);font-size:0.88rem;line-height:1.65;margin-bottom:18px'>
        Logs simulados de un <b style='color:var(--bone)'>operador aduanero</b>:
        declaraciones DUA, ERP aduanero, portal de importaciones, SIEM y Active Directory.
        </p>
        """, unsafe_allow_html=True)
        st.markdown("""
        <div style='border:1px solid var(--line);padding:14px 16px;margin-bottom:20px;background:var(--ink-sink)'>
          <div style='font-family:var(--mono);font-size:0.66rem;color:var(--bone-dim);line-height:1.9'>
            <div><span style='color:#7fa84e'>›</span> sample_auth.log <span style='color:#67635b'>············ 4.210 ev.</span></div>
            <div><span style='color:#7fa84e'>›</span> sample_apache.log <span style='color:#67635b'>·········· 3.880 ev.</span></div>
            <div><span style='color:#7fa84e'>›</span> sample_windows_events.csv <span style='color:#67635b'>···· 2.557 ev.</span></div>
            <div><span style='color:#7fa84e'>›</span> sample_syslog.log <span style='color:#67635b'>·········· 2.200 ev.</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Ejecutar análisis con logs demo →", type="primary", use_container_width=True):
            sdir = ROOT / "samples"
            sample_files = list(sdir.glob("sample_*.log")) + list(sdir.glob("sample_*.csv"))
            if not sample_files:
                import subprocess
                subprocess.run([sys.executable, str(sdir / "generate_samples.py")], check=True)
                sample_files = list(sdir.glob("sample_*.log")) + list(sdir.glob("sample_*.csv"))
            parser = LogParser()
            entries = parser.parse_path(str(sdir))
            source_label = "Logs Demo — ISO 27001:2022"
            st.success(f"✅ {parser.stats['parsed_ok']:,} eventos procesados")
            st.session_state.update({"entries": entries, "source": source_label})

    with tab_paste:
        pasted = st.text_area(
            "Pega el contenido de tu log:", height=160,
            placeholder="Jan  1 10:00:00 srv sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
        )
        if st.button("Analizar texto →", type="primary") and pasted.strip():
            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tf:
                tf.write(pasted); tf_path = tf.name
            parser = LogParser()
            entries = parser.parse_path(tf_path)
            os.unlink(tf_path)
            source_label = "Texto pegado"
            st.success(f"✅ {len(entries):,} eventos leídos")

    with tab_compare:
        st.markdown("**Compara hasta 5 archivos de log** y visualiza sus perfiles de madurez superpuestos en un radar.")
        compare_files = st.file_uploader(
            "Sube los archivos a comparar", type=["log","txt","csv","json","gz"],
            accept_multiple_files=True, key="compare_uploader"
        )
        if compare_files and len(compare_files) >= 2:
            compare_results = []
            for cf in compare_files[:5]:
                with tempfile.NamedTemporaryFile(suffix=os.path.splitext(cf.name)[1] or ".log", delete=False) as tf:
                    tf.write(cf.read()); tf_path = tf.name
                _p = LogParser(); _e = _p.parse_path(tf_path); os.unlink(tf_path)
                _cls = EventClassifier().classify(_e)
                _r = MaturityScorer().score(_cls)
                compare_results.append({"name": cf.name[:30], "result": _r, "entries": len(_e)})

            if compare_results:
                st.success(f"✅ {len(compare_results)} archivos analizados")
                DOMAIN_KEYS_C = list(ISO27001_DOMAINS.keys())
                _CLBL = {"A5_organizational":"A.5<br>Organizacional","A6_people":"A.6<br>Personas",
                         "A7_physical":"A.7<br>Físico","A8_technological":"A.8<br>Tecnológico"}
                labels_c = [_CLBL.get(k, k) for k in DOMAIN_KEYS_C]
                COMPARE_COLORS = ["#ff4d00","#c9a83a","#7fa84e","#e08a1e","#d6541f"]
                fig_compare = go.Figure()
                for i, cr in enumerate(compare_results):
                    scores_c = [cr["result"].domain_scores[k].raw_score for k in DOMAIN_KEYS_C]
                    col_c = COMPARE_COLORS[i % len(COMPARE_COLORS)]
                    fig_compare.add_trace(go.Scatterpolar(
                        r=scores_c+[scores_c[0]], theta=labels_c+[labels_c[0]],
                        fill="toself", fillcolor=hex_rgba(col_c, 0.10),
                        line=dict(color=col_c, width=2.5),
                        name=f"{cr['name']}  (Nv.{cr['result'].overall_level} · {cr['result'].overall_score:.1f} pts)",
                    ))
                fig_compare.add_trace(go.Scatterpolar(
                    r=[60]*5+[60], theta=labels_c+[labels_c[0]], mode="lines",
                    line=dict(color="#c9a83a", width=1.2, dash="dot"),
                    name="Ref. Nivel 3", hoverinfo="skip",
                ))
                fig_compare.update_layout(
                    polar=dict(
                        radialaxis=dict(visible=True, range=[0,100], tickfont=dict(color="#9a958a",size=9),
                                        gridcolor="#2a2823", tickvals=[20,40,60,80,100]),
                        angularaxis=dict(tickfont=dict(color="#f0ede4",size=11)),
                        bgcolor="#070605",
                    ),
                    showlegend=True,
                    legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center", font=dict(color="#9a958a",size=10)),
                    height=480, margin=dict(l=80,r=80,t=80,b=100),
                    paper_bgcolor="#0b0a08",
                )
                st.plotly_chart(fig_compare, use_container_width=True)
        elif compare_files and len(compare_files) < 2:
            st.info("Sube al menos 2 archivos para comparar.")

if not entries and "entries" in st.session_state:
    entries = st.session_state["entries"]
    source_label = st.session_state.get("source", "")

# ────────────────────────────────────────────────────────────────────────────
# PANTALLA DE BIENVENIDA — sin datos
# ────────────────────────────────────────────────────────────────────────────
if not entries:
    st.markdown("""
    <div class="dossier-section">
      <div class="section-head">
        <div class="section-num">?</div>
        <div>
          <h2 class="section-title">¿Cómo usar esta herramienta?</h2>
          <p class="section-kicker">
            Sube tus archivos de log o usa el modo <b>Demo</b> para un análisis inmediato.
            La herramienta clasifica eventos según los <b>4 temas del Anexo A</b> de ISO/IEC 27001:2022
            y calcula el nivel de madurez COBIT con apoyo de <b>Deep Learning</b>.
          </p>
        </div>
      </div>
    """, unsafe_allow_html=True)
    for i, (key, dom) in enumerate(ISO27001_DOMAINS.items()):
        with st.expander(f"{dom.id} — {dom.name}  (peso {dom.weight:.0%})"):
            st.caption(dom.description)
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# ────────────────────────────────────────────────────────────────────────────
# PIPELINE — clasificación y score
# ────────────────────────────────────────────────────────────────────────────
with st.spinner("Clasificando eventos y calculando madurez…"):
    _cls_result  = EventClassifier().classify(entries)
    domain_stats = _cls_result.domain_stats
    a8_sub_stats = _cls_result.a8_sub_stats
    result = MaturityScorer().score(_cls_result)
    gap    = compute_gap_analysis(result)
    st.session_state["_gap"] = gap

lvl      = result.overall_level
lvl_info = MATURITY_LEVELS[lvl]
lc       = level_color(lvl)
domains  = list(result.domain_scores.values())
dom_names = [d.domain_name for d in domains]

DOMAIN_SHORT = {
    "A5_organizational": "A.5 Organizacional",
    "A6_people":         "A.6 Personas",
    "A7_physical":       "A.7 Físico",
    "A8_technological":  "A.8 Tecnológico",
}
DOMAIN_BADGE = {
    "A5_organizational": "A.5 (37 controles)",
    "A6_people":         "A.6 (8 controles)",
    "A7_physical":       "A.7 (14 controles)",
    "A8_technological":  "A.8 (34 controles)",
}
RADAR_LBL = {
    "A5_organizational": "A.5<br>Organizacional",
    "A6_people":         "A.6<br>Personas",
    "A7_physical":       "A.7<br>Físico",
    "A8_technological":  "A.8<br>Tecnológico",
}
labels_radar = [RADAR_LBL.get(d.domain_key, d.domain_id) for d in domains]
scores_radar = [d.raw_score for d in domains]

# ────────────────────────────────────────────────────────────────────────────
# SEPARADOR — línea editorial
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# KPI STRIP
# ────────────────────────────────────────────────────────────────────────────
kpis_data = [
    (f"{result.overall_score:.1f}", "<small>/100</small>", "SCORE GLOBAL", f"Nivel {lvl}", lc),
    (f"Nivel {lvl}", "", lvl_info["name"][:18], "COBIT", lc),
    (f"{result.total_events:,}", "", "EVENTOS TOTALES", "log", "#9a958a"),
    (f"{result.total_risk_events:,}", "", "EVENTOS DE RIESGO", "alertas", C["risk"]),
    (f"{result.total_domains_active}/{len(result.domain_scores)}", "", "DOMINIOS ACTIVOS", "cobertura", C["safe"]),
    (f"{result.total_risk_events/max(result.total_events,1):.1%}", "", "TASA DE RIESGO", "exposición", C["warn"]),
]
kpi_html = '<div class="kpi-strip">'
for val, val_suf, lbl, foot, color in kpis_data:
    kpi_html += f"""
    <div class="kpi-cell">
      <div class="kpi-lbl">{lbl}</div>
      <div class="kpi-val" style="color:{color}">{val}{val_suf}</div>
      <div class="kpi-foot">{foot}</div>
    </div>"""
kpi_html += "</div>"
st.markdown(kpi_html, unsafe_allow_html=True)

st.markdown("<div style='padding:0 48px;margin-top:0'><hr class='rule'></div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 1 — RESULTADO GLOBAL
# ────────────────────────────────────────────────────────────────────────────
ok_class = "ok" if not gap.has_critical_gap else ""
gap_icon_t = "!" if gap.has_critical_gap else "✓"
gap_title_t = "Brecha de Madurez Detectada" if gap.has_critical_gap else "Coherencia de Madurez Aceptable"
gap_color = C["risk"] if gap.has_critical_gap else C["safe"]

st.markdown(f"""
<div class="dossier-section">
  <div class="section-head">
    <div class="section-num">01</div>
    <div>
      <h2 class="section-title">Resultado Global</h2>
      <p class="section-kicker">
        Score ponderado de <b>{result.overall_score:.1f}/100</b> · Nivel de madurez
        COBIT <b>{lvl} — {lvl_info['name']}</b> · Fuente: {source_label}
      </p>
    </div>
  </div>

  <div class="gap-banner {ok_class}" style="margin-bottom:28px">
    <div class="gap-icon">{gap_icon_t}</div>
    <div>
      <div class="gap-title" style="color:{gap_color}">{gap_title_t}</div>
      <div class="gap-text">{gap.audit_note}</div>
    </div>
    <div class="gap-eff">
      <div class="ge-num" style="color:{gap_color}">Nv. {gap.effective_level}</div>
      <div class="ge-lbl">Nivel efectivo<br>para auditoría</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Gauge + Radar compacto
col_gauge, col_radar = st.columns([1, 1.2])
with col_gauge:
    st.markdown("<div style='padding:0 48px'><div class='panel'><div class='panel-head'><h4>Medidor de Madurez</h4><span class='ph-tag'>COBIT 5</span></div><div class='panel-body'>", unsafe_allow_html=True)
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=result.overall_score,
        delta={"reference": 60, "valueformat": ".1f", "suffix": " pts"},
        title={"text": f"<b>Nivel {lvl} — {lvl_info['name']}</b>", "font": {"size": 13, "color": "#9a958a"}},
        number={"suffix": "/100", "font": {"size": 34, "color": lc}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#2a2823",
                     "tickvals": [0,20,40,60,80,100],
                     "ticktext": ["0","20","40","60","80","100"],
                     "tickfont": {"color": "#9a958a", "size": 9}},
            "bar":  {"color": lc, "thickness": 0.28},
            "bgcolor": "#070605",
            "borderwidth": 1, "bordercolor": "#2a2823",
            "steps": [
                {"range": [0, 20],  "color": "#1a0a08"},
                {"range": [20, 40], "color": "#1a110a"},
                {"range": [40, 60], "color": "#191610"},
                {"range": [60, 80], "color": "#111510"},
                {"range": [80, 100],"color": "#0e1510"},
            ],
            "threshold": {"line": {"color": lc, "width": 3}, "thickness": 0.75, "value": result.overall_score},
        }
    ))
    fig_gauge.update_layout(height=300, margin=dict(l=20,r=20,t=50,b=10), paper_bgcolor="#131210", font=dict(color="#f0ede4"))
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.markdown(f"<div style='font-family:var(--mono);font-size:0.74rem;color:var(--bone-dim);line-height:1.6;padding:10px 0'>{lvl_info['description']}</div>", unsafe_allow_html=True)
    st.markdown("</div></div></div>", unsafe_allow_html=True)

with col_radar:
    st.markdown("<div style='padding:0 48px 0 0'><div class='panel'><div class='panel-head'><h4>Radar Anexo A</h4><span class='ph-tag'>4 DOMINIOS</span></div><div class='panel-body'>", unsafe_allow_html=True)
    fig_radar = go.Figure()
    fig_radar.add_trace(go.Scatterpolar(
        r=scores_radar+[scores_radar[0]], theta=labels_radar+[labels_radar[0]],
        fill="toself", fillcolor=hex_rgba(lc, 0.15),
        line=dict(color=lc, width=2.5), name="Score actual",
        hovertemplate="<b>%{theta}</b><br>Score: %{r:.1f}/100<extra></extra>",
    ))
    fig_radar.add_trace(go.Scatterpolar(
        r=[60]*len(labels_radar)+[60], theta=labels_radar+[labels_radar[0]],
        mode="lines", line=dict(color=C["warn"], width=1.2, dash="dot"),
        name="Ref. Nivel 3", hoverinfo="skip",
    ))
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0,100], tickfont=dict(color="#9a958a",size=9),
                            gridcolor="#2a2823", tickvals=[20,40,60,80,100]),
            angularaxis=dict(tickfont=dict(color="#f0ede4",size=11)),
            bgcolor="#070605",
        ),
        showlegend=True,
        legend=dict(orientation="h", y=-0.12, x=0.5, xanchor="center", font=dict(color="#9a958a",size=10)),
        height=360, margin=dict(l=60,r=60,t=30,b=60), paper_bgcolor="#131210",
    )
    st.plotly_chart(fig_radar, use_container_width=True)
    if hasattr(gap, "weakest_domain_id"):
        _risk_col = C["risk"]
        st.markdown(f"<div style='font-family:var(--mono);font-size:0.68rem;color:var(--bone-dim)'>"
                    f"<span style='color:{_risk_col}'>⬤</span> Dominio más débil: <b style='color:var(--bone)'>{gap.weakest_domain_id}</b> — "
                    f"{gap.weakest_score:.1f}/100 · Nv. {gap.weakest_level}</div>", unsafe_allow_html=True)
    st.markdown("</div></div></div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 2 — DOMINIOS
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)
st.markdown("""
<div class="dossier-section">
  <div class="section-head">
    <div class="section-num">02</div>
    <div>
      <h2 class="section-title">Análisis por Dominio</h2>
      <p class="section-kicker">
        Los <b>4 temas del Anexo A</b> de ISO/IEC 27001:2022: organizacional, personas,
        físico y tecnológico. Cada uno ponderado según su cobertura de los 93 controles.
      </p>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Dom cards
col_doms = st.columns(4)
for i, (key, d) in enumerate(result.domain_scores.items()):
    ds = domain_stats[key]
    dlc = level_color(d.level)
    pct = int(d.raw_score)
    risk_pct = ds.risk_rate * 100
    with col_doms[i]:
        st.markdown(f"""
        <div class="dom-card" style="--lvlc:{dlc}">
          <div class="dc-bar-top" style="width:{pct}%"></div>
          <div class="dc-id">{d.domain_id}</div>
          <div class="dc-name">{d.domain_name}</div>
          <div class="dc-score" style="color:{dlc}">{d.raw_score:.1f}<small>/100</small></div>
          <div class="dc-lvl">Nivel {d.level} — {d.level_name}</div>
          <div class="dc-track"><div class="dc-fill" style="width:{pct}%;background:{dlc}"></div></div>
          <div class="dc-meta">
            <span>⚠ <b style="color:{'#d6451f' if risk_pct>20 else '#e0a01e' if risk_pct>10 else '#7fa84e'}">{risk_pct:.1f}%</b> riesgo</span>
            <span><b>{ds.total_events:,}</b> ev.</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

# Radar ampliado + gráficos comparativos
st.markdown("<div style='padding:0 48px'>", unsafe_allow_html=True)
col_rad2, col_bars = st.columns([1.1, 1])

with col_rad2:
    LEVEL_RINGS = [
        (20,"Nivel 1","#d6541f","dot"), (40,"Nivel 2","#e08a1e","dot"),
        (60,"Nivel 3","#c9a83a","dashdot"), (80,"Nivel 4","#7fa84e","dot"),
    ]
    fig_rad2 = go.Figure()
    for rv, rn, rc, rd in reversed(LEVEL_RINGS):
        fig_rad2.add_trace(go.Scatterpolar(
            r=[rv]*len(labels_radar)+[rv], theta=labels_radar+[labels_radar[0]],
            mode="lines", line=dict(color=rc, width=1.0, dash=rd),
            name=f"{rn} ({rv})", opacity=0.6,
        ))
    fig_rad2.add_trace(go.Scatterpolar(
        r=scores_radar+[scores_radar[0]], theta=labels_radar+[labels_radar[0]],
        fill="toself", fillcolor=hex_rgba(lc, 0.20),
        line=dict(color=lc, width=3), name=f"Nivel {lvl} ({result.overall_score:.1f} pts)",
        hovertemplate="<b>%{theta}</b><br>%{r:.1f}/100<extra></extra>",
    ))
    fig_rad2.add_trace(go.Scatterpolar(
        r=scores_radar, theta=labels_radar, mode="markers+text",
        marker=dict(color=[C["domains"][i] for i in range(len(scores_radar))], size=10, line=dict(color="#0b0a08",width=2)),
        text=[f"<b>{s:.0f}</b>" for s in scores_radar], textposition="top center",
        textfont=dict(size=11, color="#f0ede4"), showlegend=False,
    ))
    fig_rad2.update_layout(
        polar=dict(
            domain=dict(x=[0.06,0.94], y=[0.06,0.90]),
            radialaxis=dict(visible=True, range=[0,110], tickfont=dict(color="#9a958a",size=10),
                            gridcolor="#2a2823", tickvals=[20,40,60,80,100]),
            angularaxis=dict(tickfont=dict(color="#f0ede4",size=13, family="Bodoni Moda,Georgia,serif")),
            bgcolor="#070605",
        ),
        showlegend=True,
        legend=dict(orientation="h", y=-0.18, x=0.5, xanchor="center", font=dict(color="#9a958a",size=11)),
        height=540, margin=dict(l=90,r=90,t=100,b=120),
        paper_bgcolor="#0b0a08",
    )
    st.plotly_chart(fig_rad2, use_container_width=True)

with col_bars:
    dom_keys = list(domain_stats.keys())
    dom_names_short = [DOMAIN_SHORT.get(d.domain_key, d.domain_name[:20]) for d in domains]
    safe_counts = [domain_stats[k].safe_events for k in dom_keys]
    risk_counts = [domain_stats[k].risk_events  for k in dom_keys]

    fig_bar = go.Figure()
    fig_bar.add_trace(go.Bar(
        name="Eventos Seguros", x=dom_names_short, y=safe_counts,
        marker_color=hex_rgba(C["safe"], 0.75),
        hovertemplate="<b>%{x}</b><br>Seguros: %{y}<extra></extra>",
    ))
    fig_bar.add_trace(go.Bar(
        name="Eventos de Riesgo", x=dom_names_short, y=risk_counts,
        marker_color=hex_rgba(C["risk"], 0.75),
        hovertemplate="<b>%{x}</b><br>Riesgo: %{y}<extra></extra>",
    ))
    fig_bar.update_layout(
        barmode="group", height=240,
        margin=dict(l=10,r=10,t=10,b=80), **PLOTLY_DARK,
        legend=dict(orientation="h", y=-0.35, x=0.5, xanchor="center"),
        yaxis=dict(title="N° eventos", **PLOTLY_AXIS_DARK),
        xaxis=dict(tickangle=-20, **PLOTLY_AXIS_DARK),
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    # Score barras horizontales
    sorted_domains = sorted(domains, key=lambda d: d.raw_score)
    fig_h = go.Figure()
    fig_h.add_trace(go.Bar(
        y=[DOMAIN_SHORT.get(d.domain_key, d.domain_name[:18]) for d in sorted_domains],
        x=[d.raw_score for d in sorted_domains],
        orientation="h",
        marker_color=[level_color(d.level) for d in sorted_domains],
        text=[f"{d.raw_score:.1f}" for d in sorted_domains],
        textposition="outside", textfont=dict(color="#9a958a", size=10),
        hovertemplate="<b>%{y}</b><br>%{x:.1f}/100<extra></extra>",
    ))
    for thr, tname, tcol in [(20,"Nv1","#d6541f"),(40,"Nv2","#e08a1e"),(60,"Nv3","#c9a83a"),(80,"Nv4","#7fa84e")]:
        fig_h.add_vline(x=thr, line_dash="dot", line_color=tcol, line_width=1)
    fig_h.update_layout(
        height=240, margin=dict(l=10,r=60,t=10,b=10), **PLOTLY_DARK,
        xaxis=dict(range=[0,110], title="Score (0–100)", **PLOTLY_AXIS_DARK),
        yaxis=dict(**PLOTLY_AXIS_DARK),
        showlegend=False,
    )
    st.plotly_chart(fig_h, use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 3 — EVENTOS
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)
st.markdown("""
<div class="dossier-section">
  <div class="section-head">
    <div class="section-num">03</div>
    <div>
      <h2 class="section-title">Estructura de Eventos</h2>
      <p class="section-kicker">
        Distribución temporal, jerárquica y por severidad de los
        <b>{:,} eventos</b> procesados. Mapa de calor de riesgo por dominio.
      </p>
    </div>
  </div>
</div>
""".format(result.total_events), unsafe_allow_html=True)

col_pie, col_sun, col_heat = st.columns(3)

with col_pie:
    pie_vals  = [domain_stats[d.domain_key].total_events for d in domains]
    pie_names = [DOMAIN_SHORT.get(d.domain_key, d.domain_name[:18]) for d in domains]
    fig_pie = go.Figure(go.Pie(
        labels=pie_names, values=pie_vals,
        marker=dict(colors=C["domains"], line=dict(color="#0b0a08",width=2)),
        hole=0.45, textinfo="percent+label", textfont=dict(size=9, color="#f0ede4"),
        hovertemplate="<b>%{label}</b><br>Eventos: %{value:,}<br>%{percent}<extra></extra>",
        pull=[0.06 if domain_stats[d.domain_key].risk_events/max(domain_stats[d.domain_key].total_events,1) > 0.3 else 0 for d in domains],
    ))
    fig_pie.update_layout(
        height=300, margin=dict(l=10,r=10,t=30,b=10), paper_bgcolor="#0b0a08",
        annotations=[dict(text=f"<b style='color:#f0ede4'>{result.total_events:,}</b>", x=0.5, y=0.5,
                          font=dict(size=11,color="#f0ede4"), showarrow=False)],
        showlegend=False,
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with col_sun:
    sun_ids, sun_labels, sun_parents, sun_vals, sun_colors = [], [], [], [], []
    sun_ids.append("root"); sun_labels.append("Total"); sun_parents.append(""); sun_vals.append(result.total_events); sun_colors.append(C["signal"])
    for i, (key, d) in enumerate(zip(list(domain_stats.keys()), domains)):
        ds = domain_stats[key]
        if ds.total_events == 0: continue
        did = f"dom_{key}"
        sun_ids.append(did); sun_labels.append(DOMAIN_SHORT.get(d.domain_key, d.domain_name[:16]))
        sun_parents.append("root"); sun_vals.append(ds.total_events); sun_colors.append(C["domains"][i % len(C["domains"])])
        if ds.safe_events > 0:
            sun_ids.append(f"{did}_ok"); sun_labels.append("Seguros")
            sun_parents.append(did); sun_vals.append(ds.safe_events); sun_colors.append(C["safe"])
        if ds.risk_events > 0:
            sun_ids.append(f"{did}_risk"); sun_labels.append("Riesgo")
            sun_parents.append(did); sun_vals.append(ds.risk_events); sun_colors.append(C["risk"])
    fig_sun = go.Figure(go.Sunburst(
        ids=sun_ids, labels=sun_labels, parents=sun_parents, values=sun_vals,
        marker=dict(colors=sun_colors, line=dict(width=1.5, color="#0b0a08")),
        branchvalues="total",
        hovertemplate="<b>%{label}</b><br>%{value:,} eventos<br>%{percentParent:.1%}<extra></extra>",
        textfont=dict(size=9, color="#f0ede4"),
        insidetextorientation="radial",
    ))
    fig_sun.update_layout(
        height=300, margin=dict(l=0,r=0,t=30,b=10), paper_bgcolor="#0b0a08",
    )
    st.plotly_chart(fig_sun, use_container_width=True)

with col_heat:
    categories = ["Riesgo %","Score inv.","Ev. Críticos","Cob. IPs"]
    dom_short = [DOMAIN_SHORT.get(d.domain_key, d.domain_name[:16]) for d in domains]
    heat_data = []
    for d in domains:
        ds = domain_stats[d.domain_key]
        rrate  = round(ds.risk_rate * 100, 1)
        inv_sc = round(100 - d.raw_score, 1)
        _crit_kws = ["CRITICAL","ransomware","breach","exfiltrat","zero.day","exploit","ddos","lateral_movement"]
        _n_crit = sum(1 for m in ds.raw_messages if any(k.lower() in m.lower() for k in _crit_kws))
        crit   = min(100, _n_crit * 10 + ds.risk_events * 2)
        cov_ips= min(100, len(ds.unique_ips) * 5)
        heat_data.append([rrate, inv_sc, crit, cov_ips])
    df_heat = pd.DataFrame(heat_data, index=dom_short, columns=categories)
    fig_heat = go.Figure(go.Heatmap(
        z=df_heat.values.tolist(), x=categories, y=dom_short,
        colorscale=[[0.0,"#0e1510"],[0.25,"#191610"],[0.5,"#1a110a"],[0.75,"#1a0e08"],[1.0,"#b5321f"]],
        text=[[f"{v:.0f}" for v in row] for row in df_heat.values.tolist()],
        texttemplate="%{text}", textfont=dict(size=10, color="#f0ede4"),
        hovertemplate="<b>%{y}</b><br>%{x}: %{z:.1f}<extra></extra>",
        showscale=True,
        colorbar=dict(title="Riesgo", tickfont=dict(size=8,color="#9a958a")),
    ))
    fig_heat.update_layout(
        height=300, margin=dict(l=10,r=10,t=30,b=10), **PLOTLY_DARK,
        xaxis=dict(tickangle=-15, tickfont=dict(color="#9a958a",size=9)),
        yaxis=dict(tickfont=dict(color="#9a958a",size=9)),
    )
    st.plotly_chart(fig_heat, use_container_width=True)

# Timeline
events_with_ts = [e for e in entries if e.timestamp is not None]
if events_with_ts:
    st.markdown("<div style='padding:0 48px;margin-top:8px'>", unsafe_allow_html=True)
    st.markdown("<div class='eyebrow' style='margin-bottom:14px'>Línea de Tiempo de Eventos</div>", unsafe_allow_html=True)
    lvl_colors_tl = {"DEBUG":"#67635b","INFO":"#9a958a","WARNING":C["warn"],"ERROR":C["risk"],"CRITICAL":"#b5321f"}
    lvl_size_tl   = {"DEBUG":4,"INFO":4,"WARNING":6,"ERROR":8,"CRITICAL":11}
    df_tl = pd.DataFrame([{
        "ts": e.timestamp, "nivel": e.level, "msg": (e.message or "")[:80],
        "color": lvl_colors_tl.get(e.level, "#9a958a"), "size": lvl_size_tl.get(e.level, 4),
        "y": {"DEBUG":0,"INFO":1,"WARNING":2,"ERROR":3,"CRITICAL":4}.get(e.level,1),
    } for e in events_with_ts]).sort_values("ts")
    fig_tl = go.Figure()
    for nivel, grp in df_tl.groupby("nivel"):
        fig_tl.add_trace(go.Scatter(
            x=grp["ts"], y=grp["y"], mode="markers", name=nivel,
            marker=dict(color=lvl_colors_tl.get(nivel,"#9a958a"), size=grp["size"].tolist(), opacity=0.8,
                        line=dict(color="#0b0a08", width=0.5)),
            hovertemplate="<b>%{x|%d/%m %H:%M}</b><br>" + nivel + "<br>%{customdata}<extra></extra>",
            customdata=grp["msg"].tolist(),
        ))
    fig_tl.update_layout(
        height=240, **PLOTLY_DARK,
        yaxis=dict(tickvals=[0,1,2,3,4], ticktext=["DEBUG","INFO","WARNING","ERROR","CRITICAL"],
                   **PLOTLY_AXIS_DARK, title="Severidad"),
        xaxis=dict(title="Fecha / Hora", **PLOTLY_AXIS_DARK),
        legend=dict(orientation="h", y=-0.3, x=0.5, xanchor="center", font=dict(color="#9a958a",size=9)),
        margin=dict(l=10,r=10,t=10,b=60), showlegend=True,
    )
    st.plotly_chart(fig_tl, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 4 — HALLAZGOS
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)
st.markdown("""
<div class="dossier-section">
  <div class="section-head">
    <div class="section-num">04</div>
    <div>
      <h2 class="section-title">Hallazgos y Recomendaciones</h2>
      <p class="section-kicker">
        Puntos críticos detectados y acciones sugeridas para
        <b>elevar el nivel de madurez</b> en cada dominio.
      </p>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

col_find, col_rec = st.columns(2)
with col_find:
    st.markdown("<div style='padding:0 0 0 48px'>", unsafe_allow_html=True)
    st.markdown("<div class='panel'><div class='panel-head'><h4>Hallazgos Críticos</h4><span class='ph-tag'>RIESGO</span></div><div class='panel-body'>", unsafe_allow_html=True)
    if result.critical_findings:
        html_f = ""
        for i, f in enumerate(result.critical_findings, 1):
            html_f += f"<div class='find-item'><div class='find-idx'>#{i:02d}</div><div class='find-txt'>{f}</div></div>"
        st.markdown(html_f, unsafe_allow_html=True)
    else:
        st.markdown("<div style='color:var(--safe);font-family:var(--mono);font-size:0.78rem'>✓ Sin hallazgos críticos detectados.</div>", unsafe_allow_html=True)
    st.markdown("</div></div></div>", unsafe_allow_html=True)

with col_rec:
    st.markdown("<div style='padding:0 48px 0 0'>", unsafe_allow_html=True)
    st.markdown("<div class='panel'><div class='panel-head'><h4>Recomendaciones</h4><span class='ph-tag'>ACCIÓN</span></div><div class='panel-body'>", unsafe_allow_html=True)
    html_r = ""
    for i, rec in enumerate(result.recommendations, 1):
        html_r += f"<div class='find-item'><div class='rec-idx'>#{i:02d}</div><div class='find-txt'>{rec}</div></div>"
    st.markdown(html_r, unsafe_allow_html=True)
    st.markdown("</div></div></div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 5 — PLAN DE ACCIÓN
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)
st.markdown("""
<div class="dossier-section">
  <div class="section-head">
    <div class="section-num">05</div>
    <div>
      <h2 class="section-title">Plan de Acción</h2>
      <p class="section-kicker">
        Acciones ordenadas por urgencia — el dominio más débil primero — con
        <b>nivel de esfuerzo</b> estimado y tiempo de implementación.
      </p>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

from analyzer.action_plan import generate_action_plan
action_plan = generate_action_plan(result)

if not action_plan:
    st.markdown("<div style='padding:0 48px;font-family:var(--mono);font-size:0.78rem;color:var(--safe)'>✓ Todos los dominios están en niveles óptimos.</div>", unsafe_allow_html=True)
else:
    st.markdown("<div style='padding:0 48px'>", unsafe_allow_html=True)
    # Barras de brecha
    bar_html = ""
    for item in action_plan:
        lc3 = level_color(item["level"])
        pct = int(item["score"])
        bar_html += f"""
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
          <span style="min-width:170px;font-family:var(--mono);font-size:0.7rem;color:var(--bone-dim)">{item['domain_name'][:26]}</span>
          <div style="flex:1;background:var(--ink-sink);height:4px">
            <div style="width:{pct}%;background:{lc3};height:4px"></div>
          </div>
          <span style="min-width:60px;font-family:var(--serif);font-weight:800;font-size:1rem;color:{lc3}">{item['score']:.1f}</span>
          <span style="font-family:var(--mono);font-size:0.6rem;color:var(--bone-faint)">▲ {item['gap_to_next']:.0f} pts</span>
        </div>"""
    st.markdown(bar_html, unsafe_allow_html=True)
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    for item in action_plan:
        effort_color = {"Bajo": C["safe"], "Medio": C["warn"], "Alto": C["risk"]}.get(item["effort"], "#9a958a")
        lvl_c = level_color(item["level"])
        with st.expander(
            f"#{item.get('priority',1)} — {item['domain_name']} · Score {item['score']:.1f}/100 · Nv. {item['level']} · {item['effort']} esfuerzo",
            expanded=item.get("priority", 1) <= 2,
        ):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Score actual", f"{item['score']:.1f}/100")
            with c2:
                st.metric("Esfuerzo", item["effort"])
            with c3:
                st.metric("Tiempo estimado", item["tiempo"])
            for action in item["actions"]:
                st.markdown(
                    f'<div style="border-left:2px solid {lvl_c};padding:6px 12px;margin-bottom:5px;'
                    f'font-size:0.87rem;color:var(--bone-dim);background:var(--ink-panel)">{action}</div>',
                    unsafe_allow_html=True
                )
    st.markdown("</div>", unsafe_allow_html=True)

# Tabla resumen
st.markdown("<div style='padding:0 48px'><hr class='rule'></div>", unsafe_allow_html=True)
st.markdown("<div style='padding:24px 48px'>", unsafe_allow_html=True)
st.markdown("<div class='eyebrow' style='margin-bottom:16px'>Tabla Resumen por Dominio</div>", unsafe_allow_html=True)
table_data = []
for key, d in result.domain_scores.items():
    ds = domain_stats[key]
    table_data.append({
        "Dominio": d.domain_name,
        "Cláusula": DOMAIN_BADGE.get(d.domain_key, d.annex_ref.split('–')[0].strip()),
        "Peso": f"{d.weight:.0%}",
        "Score": f"{d.raw_score:.1f}",
        "Nivel": f"{d.level} — {d.level_name}",
        "Total Ev.": ds.total_events,
        "Riesgo Ev.": ds.risk_events,
        "Tasa %": f"{ds.risk_rate:.1%}",
        "IPs": len(ds.unique_ips),
        "Usuarios": len(ds.unique_users),
    })
df_table = pd.DataFrame(table_data).sort_values("Score", ascending=False)
st.dataframe(df_table, use_container_width=True, hide_index=True)
st.markdown("</div>", unsafe_allow_html=True)

# Descargas
st.markdown("<div style='padding:0 48px'>", unsafe_allow_html=True)
st.markdown("<div class='eyebrow' style='margin-bottom:16px'>Exportar Resultados</div>", unsafe_allow_html=True)
dl1, dl2, dl3 = st.columns(3)
with dl1:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        export_html(result, source_label, tf.name)
        html_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("⬇ Reporte HTML completo", data=html_bytes,
        file_name="reporte_madurez_iso27001.html", mime="text/html", use_container_width=True, type="primary")
with dl2:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        export_json(result, tf.name)
        json_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("⬇ Datos JSON", data=json_bytes,
        file_name="resultado_iso27001.json", mime="application/json", use_container_width=True)
with dl3:
    if st.button("⬇ Generar Reporte PDF", use_container_width=True):
        with st.spinner("Generando PDF…"):
            try:
                from analyzer.pdf_report  import generate_pdf
                from analyzer.action_plan import generate_action_plan as _gap2
                pdf_bytes = generate_pdf(result, domain_stats, source_label, _gap2(result))
                st.download_button("📄 Descargar PDF", data=pdf_bytes,
                    file_name="reporte_iso27001.pdf", mime="application/pdf",
                    use_container_width=True, key="pdf_dl")
            except Exception as _e:
                st.error(f"Error generando PDF: {_e}")
st.markdown("</div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# § 6 — DEEP LEARNING
# ────────────────────────────────────────────────────────────────────────────
st.markdown("<div style='padding:0 48px'><hr class='rule-2'></div>", unsafe_allow_html=True)
st.markdown("""
<div class="dl-band-header">
  <div class="section-head" style="margin-bottom:0">
    <div class="section-num">06</div>
    <div>
      <h2 class="section-title">Deep Learning</h2>
      <p class="section-kicker">
        Tres modelos neurales entrenados en tiempo real:
        <b>Autoencoder</b> (detección de anomalías),
        <b>LSTM Bidireccional</b> (patrones temporales de amenaza) y
        <b>MLP Clasificador</b> (nivel de madurez por redes neuronales).
      </p>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

with st.expander("Ver arquitectura de los modelos"):
    arch_cols = st.columns(3)
    arch_info = [
        ("Autoencoder","63 → 32 → 16 → 8 → 16 → 32 → 63",
         "Reconstruye eventos normales. Alta pérdida = ANOMALÍA.",
         ["Entrada (63)","Dense 32","Dense 16","Bottleneck 8","Dense 16","Dense 32","Salida (63)"],"#ff4d00"),
        ("LSTM Bidireccional","(20×13) → BiLSTM(32) → LSTM(16) → Dense(8) → sigmoid",
         "Analiza secuencias de 20 eventos. Detecta patrones de ataque.",
         ["Seq (20,13)","BiLSTM 32","LSTM 16","Dense 8","Prob amenaza"],"#c9a83a"),
        ("MLP Clasificador","24 → 64 → 32 → 16 → softmax(6)",
         "Clasifica el nivel de madurez ISO 27001 (0–5) directamente.",
         ["Features (24)","Dense 64","Dense 32","Dense 16","Softmax (6)"],"#7fa84e"),
    ]
    for col, (title, arch, desc, layers_list, color) in zip(arch_cols, arch_info):
        with col:
            st.markdown(f"<b style='color:{color}'>{title}</b>", unsafe_allow_html=True)
            st.caption(desc)
            for i, lyr in enumerate(layers_list):
                is_key = any(k in lyr for k in ["8","sigmoid","Softmax"])
                bg = color if is_key else color+"22"
                fc = "#0b0a08" if is_key else color
                st.markdown(f'<div style="background:{bg};color:{fc};border:1px solid {color};border-radius:0;padding:4px 8px;text-align:center;margin-bottom:3px;font-family:var(--mono);font-size:0.72rem;font-weight:600">{lyr}</div>', unsafe_allow_html=True)
                if i < len(layers_list)-1:
                    st.markdown(f'<div style="text-align:center;color:{color};font-size:0.7rem">▼</div>', unsafe_allow_html=True)

st.markdown("<div style='padding:16px 48px 0'>", unsafe_allow_html=True)
dl_c1, dl_c2, dl_c3, dl_c4 = st.columns([1,1,1,1])
with dl_c1: ae_epochs   = st.slider("Épocas Autoencoder",        5, 50, 25, 5)
with dl_c2: lstm_epochs = st.slider("Épocas LSTM",               5, 40, 20, 5)
with dl_c3: mlp_epochs  = st.slider("Épocas MLP Clasificador",  10, 60, 35, 5)
with dl_c4:
    st.markdown("<br>", unsafe_allow_html=True)
    run_dl = st.button("Entrenar y Analizar con DL →", type="primary", use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

if run_dl or "dl_result" in st.session_state:
    if run_dl:
        from ml.dl_pipeline import DLPipeline, _separate_normal_attack, _augment_attack_entries
        from rules.iso27001_controls import MATURITY_LEVELS as ML

        prog_bar = st.progress(0, text="Inicializando modelos…")

        @st.cache_resource(show_spinner=False)
        def get_pipeline():
            return DLPipeline()

        pipeline = get_pipeline()
        pipeline._trained = False

        prog_bar.progress(10, text="Entrenando Autoencoder…")
        pipeline.autoencoder = __import__('ml.autoencoder_model', fromlist=['LogAutoencoder']).LogAutoencoder()
        pipeline.autoencoder.fit(entries, epochs=ae_epochs, verbose=0)

        prog_bar.progress(40, text="Entrenando LSTM Bidireccional…")
        from ml.lstm_model import LSTMThreatDetector
        pipeline.lstm = LSTMThreatDetector()
        pipeline.lstm.extractor = pipeline.autoencoder.extractor
        pipeline.lstm.extractor._fitted = True
        normal_e, attack_e = _separate_normal_attack(entries)
        if len(attack_e) < 30:
            attack_e = _augment_attack_entries(attack_e, normal_e)
        pipeline.lstm.fit(normal_e, attack_e, epochs=lstm_epochs, verbose=0)

        prog_bar.progress(70, text="Entrenando MLP Clasificador…")
        from ml.maturity_classifier import MaturityClassifier
        pipeline.classifier = MaturityClassifier()
        pipeline.classifier.fit(epochs=mlp_epochs, verbose=0)
        pipeline._trained = True

        prog_bar.progress(90, text="Calculando predicciones…")
        dl_res = pipeline.run(entries, domain_stats, result)
        st.session_state["dl_result"]  = dl_res
        st.session_state["dl_pipeline"] = pipeline
        prog_bar.progress(100, text="✅ Listo")
        prog_bar.empty()
    else:
        dl_res = st.session_state["dl_result"]

    from rules.iso27001_controls import MATURITY_LEVELS as ML

    # KPIs DL
    dl_kpis = [
        (f"{dl_res.anomaly_rate:.1f}%", "TASA DE ANOMALÍAS", "Autoencoder", "#ff4d00"),
        (f"{dl_res.threat_level['mean_threat_prob']:.1%}", "PROB. AMENAZA MEDIA", "LSTM", "#c9a83a"),
        (f"Nv. {dl_res.dl_predicted_level}", "NIVEL PREDICHO", "MLP", level_color(dl_res.dl_predicted_level)),
        (f"{dl_res.dl_confidence:.1f}%", "CONFIANZA MLP", "softmax", "#7fa84e"),
        ("✓ Acuerdo" if dl_res.agreement else "⚠ Difieren", "REGLAS vs DL", "coherencia",
         C["safe"] if dl_res.agreement else C["risk"]),
    ]
    kpi_dl_html = '<div class="kpi-strip" style="margin:16px 48px;grid-template-columns:repeat(5,1fr)">'
    for val, lbl, foot, color in dl_kpis:
        kpi_dl_html += f'<div class="kpi-cell"><div class="kpi-lbl">{lbl}</div><div class="kpi-val" style="color:{color}">{val}</div><div class="kpi-foot">{foot}</div></div>'
    kpi_dl_html += "</div>"
    st.markdown(kpi_dl_html, unsafe_allow_html=True)

    # Curvas de entrenamiento
    st.markdown("<div style='padding:16px 48px 0'><div class='eyebrow' style='margin-bottom:16px'>Curvas de Entrenamiento</div></div>", unsafe_allow_html=True)

    def plot_loss_dossier(train_loss, val_loss, train_acc, val_acc, title, color):
        if not train_loss:
            fig = go.Figure()
            fig.add_annotation(text="Modelo no entrenado",
                               xref="paper", yref="paper", x=0.5, y=0.5,
                               showarrow=False, font=dict(size=12, color="#9a958a"))
            fig.update_layout(height=220, **PLOTLY_DARK)
            return fig
        eps = list(range(1, len(train_loss)+1))
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=eps, y=train_loss, name="Train Loss",
            line=dict(color=color, width=2), mode="lines"))
        if val_loss:
            fig.add_trace(go.Scatter(x=eps, y=val_loss[:len(eps)], name="Val Loss",
                line=dict(color=color, width=1.5, dash="dot"), mode="lines", opacity=0.7))
        if train_acc:
            fig.add_trace(go.Scatter(x=eps, y=[a*100 for a in train_acc[:len(eps)]],
                name="Train Acc %", line=dict(color=C["warn"], width=1.2, dash="dash"),
                mode="lines", yaxis="y2"))
        y_min = min(train_loss)*0.9; y_max = max(train_loss)*1.1
        layout = dict(height=220, margin=dict(l=40,r=40,t=40,b=30), **PLOTLY_DARK,
            legend=dict(orientation="h", y=-0.3, font=dict(size=8)),
            xaxis=dict(title="Época", **PLOTLY_AXIS_DARK),
            yaxis=dict(title="Pérdida", **PLOTLY_AXIS_DARK, range=[y_min,y_max], tickformat=".4f"),
        )
        if train_acc:
            layout["yaxis2"] = dict(title="Acc %", overlaying="y", side="right", range=[0,105], showgrid=False, tickfont=dict(color="#9a958a"))
        fig.update_layout(**layout)
        return fig

    tc1, tc2, tc3 = st.columns(3)
    with tc1:
        fig = plot_loss_dossier(dl_res.ae_train_loss, dl_res.ae_val_loss, [], [], "Autoencoder (MSE)", "#ff4d00")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.ae_summary
        st.caption(f"Params: {sm['parameters']:,} · Épocas: {sm['epochs_trained']} · Loss: {sm['final_train_loss']}")
    with tc2:
        fig = plot_loss_dossier(dl_res.lstm_train_loss, dl_res.lstm_val_loss,
                                dl_res.lstm_train_acc, dl_res.lstm_val_acc, "LSTM (Binary CE)", "#c9a83a")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.lstm_summary
        acc = f"{sm['final_val_acc']:.1%}" if sm.get('final_val_acc') else "N/A"
        st.caption(f"Params: {sm['parameters']:,} · Épocas: {sm['epochs_trained']} · Acc val: {acc}")
    with tc3:
        fig = plot_loss_dossier(dl_res.mlp_train_loss, dl_res.mlp_val_loss,
                                dl_res.mlp_train_acc, dl_res.mlp_val_acc, "MLP (Categorical CE)", "#7fa84e")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.mlp_summary
        acc = f"{sm['final_val_acc']:.1%}" if sm.get('final_val_acc') else "N/A"
        st.caption(f"Params: {sm['parameters']:,} · Épocas: {sm['epochs_trained']} · Acc val: {acc}")

    # Autoencoder — anomalías
    st.markdown("<div style='padding:0 48px'><div class='eyebrow' style='margin:16px 0'>Autoencoder — Detección de Anomalías</div></div>", unsafe_allow_html=True)
    ae1, ae2 = st.columns(2)
    import numpy as _np
    _raw = _np.array(dl_res.anomaly_scores, dtype=float)
    _thr = float(dl_res.autoencoder_threshold) if dl_res.autoencoder_threshold > 0 else float(_raw.max() or 0.1)
    scores_norm = _np.clip(_raw / _thr * 50, 0, 200)
    _mask = _np.array(dl_res.is_anomaly, dtype=bool)
    normal_sc = scores_norm[~_mask]; anom_sc = scores_norm[_mask]

    with ae1:
        fig_hist_ae = go.Figure()
        if len(normal_sc):
            fig_hist_ae.add_trace(go.Histogram(x=normal_sc.tolist(), name="Normales",
                marker_color=hex_rgba(C["safe"], 0.7), nbinsx=40))
        if len(anom_sc):
            fig_hist_ae.add_trace(go.Histogram(x=anom_sc.tolist(), name="Anomalías",
                marker_color=hex_rgba(C["risk"], 0.7), nbinsx=40))
        fig_hist_ae.add_vline(x=50, line_dash="dash", line_color=C["warn"], line_width=2)
        fig_hist_ae.update_layout(
            barmode="overlay", height=250, margin=dict(l=10,r=10,t=10,b=30), **PLOTLY_DARK,
            legend=dict(orientation="h", y=-0.25, font=dict(size=9)),
            xaxis=dict(title="Score Anomalía (0–100)", **PLOTLY_AXIS_DARK),
            yaxis=dict(title="N° eventos", **PLOTLY_AXIS_DARK),
        )
        st.plotly_chart(fig_hist_ae, use_container_width=True)

    with ae2:
        step = max(1, len(scores_norm)//300)
        idx_pl = list(range(0, len(scores_norm), step))
        sc_pl  = scores_norm[idx_pl]
        col_pl = [C["risk"] if float(s)>=50 else C["safe"] for s in sc_pl.tolist()]
        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(x=idx_pl, y=sc_pl.tolist(), mode="markers",
            marker=dict(color=col_pl, size=4, opacity=0.7),
            hovertemplate="Evento #%{x}<br>Score: %{y:.1f}<extra></extra>"))
        fig_time.add_hline(y=50, line_dash="dash", line_color=C["warn"])
        fig_time.update_layout(
            height=250, margin=dict(l=10,r=10,t=10,b=30), **PLOTLY_DARK,
            xaxis=dict(title="N° evento", **PLOTLY_AXIS_DARK),
            yaxis=dict(title="Score anomalía", range=[0,105], **PLOTLY_AXIS_DARK),
        )
        st.plotly_chart(fig_time, use_container_width=True)

    st.info(f"Autoencoder: {dl_res.anomaly_rate:.1f}% anomalías ({int(dl_res.is_anomaly.sum()):,} de {len(dl_res.is_anomaly):,}) · Umbral P95: {dl_res.autoencoder_threshold:.6f}")

    # LSTM
    st.markdown("<div style='padding:0 48px'><div class='eyebrow' style='margin:16px 0'>LSTM — Detección Temporal de Amenazas</div></div>", unsafe_allow_html=True)
    ls1, ls2 = st.columns(2)
    tp = dl_res.threat_probs
    with ls1:
        step2 = max(1, len(tp)//150); tp_plot = tp[::step2]
        col_tp = [C["risk"] if p>=0.75 else C["warn"] if p>=0.5 else C["safe"] for p in tp_plot]
        fig_lstm = go.Figure()
        fig_lstm.add_trace(go.Bar(x=list(range(len(tp_plot))), y=tp_plot.tolist(),
            marker_color=col_tp, hovertemplate="Ventana %{x}<br>Prob: %{y:.3f}<extra></extra>"))
        fig_lstm.add_hline(y=0.75, line_dash="dash", line_color=C["risk"])
        fig_lstm.add_hline(y=0.50, line_dash="dot", line_color=C["warn"])
        fig_lstm.update_layout(height=250, margin=dict(l=10,r=10,t=10,b=30), **PLOTLY_DARK,
            xaxis=dict(title="Ventana temporal", **PLOTLY_AXIS_DARK),
            yaxis=dict(title="Probabilidad", range=[0,1.05], **PLOTLY_AXIS_DARK))
        st.plotly_chart(fig_lstm, use_container_width=True)

    with ls2:
        tl = dl_res.threat_level
        _low  = max(0.01, tl.get("pct_low_threat", 100.0 - tl.get("pct_high_threat",0) - tl.get("pct_medium_threat",0)))
        _med  = max(0.01, tl.get("pct_medium_threat", 0.0))
        _high = max(0.01, tl.get("pct_high_threat", 0.0))
        _tot  = _low+_med+_high
        vals_t = [_low/_tot*100, _med/_tot*100, _high/_tot*100]
        labels_t = ["Bajo (<50%)", "Medio (50–75%)", "Alto (>75%)"]
        fig_donut = go.Figure(go.Pie(
            labels=labels_t, values=vals_t,
            marker=dict(colors=[C["safe"],C["warn"],C["risk"]], line=dict(color="#0b0a08",width=2)),
            hole=0.5, hovertemplate="%{label}<br>%{value:.1f}%<extra></extra>",
            textfont=dict(size=10,color="#f0ede4"),
        ))
        fig_donut.update_layout(
            height=250, margin=dict(l=10,r=10,t=10,b=30), paper_bgcolor="#0b0a08", showlegend=True,
            legend=dict(font=dict(color="#9a958a",size=9)),
            annotations=[dict(text=f"{tl.get('mean_threat_prob',0.0):.1%}", x=0.5, y=0.5,
                              font=dict(size=13,color="#f0ede4",family="Bodoni Moda,serif"), showarrow=False)],
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    st.info(f"LSTM: Prob. máxima: {tl.get('max_threat_prob',0.0):.1%} · Alto riesgo: {tl.get('pct_high_threat',0.0):.1f}% ventanas")

    # MLP
    st.markdown("<div style='padding:0 48px'><div class='eyebrow' style='margin:16px 0'>MLP — Clasificación de Nivel de Madurez</div></div>", unsafe_allow_html=True)
    ml1, ml2 = st.columns(2)
    probs_dict = dl_res.dl_probabilities or {}
    with ml1:
        niveles_lbl = [f"Nivel {i}\n{ML[i]['name'][:12]}" for i in range(6)]
        probs_vals  = [round(probs_dict.get(i, 0.0)*100, 1) for i in range(6)]
        if sum(probs_vals) < 0.1: probs_vals = [round(100/6,1)]*6
        fig_mlp = go.Figure(go.Bar(
            x=niveles_lbl, y=probs_vals,
            marker_color=[level_color(i) for i in range(6)],
            text=[f"{v:.1f}%" for v in probs_vals], textposition="outside",
            textfont=dict(color="#9a958a",size=9),
            hovertemplate="<b>%{x}</b><br>Prob: %{y:.1f}%<extra></extra>",
        ))
        pred_lvl = dl_res.dl_predicted_level
        fig_mlp.add_vline(x=pred_lvl, line_color=level_color(pred_lvl), line_width=2, line_dash="dash")
        fig_mlp.update_layout(height=280, margin=dict(l=10,r=10,t=20,b=70), **PLOTLY_DARK,
            yaxis=dict(title="Probabilidad (%)", range=[0,115], **PLOTLY_AXIS_DARK),
            xaxis=dict(tickfont=dict(color="#9a958a",size=8), tickangle=-25),
            showlegend=False)
        st.plotly_chart(fig_mlp, use_container_width=True)

    with ml2:
        rule_lvl = dl_res.rule_based_level; dl_lvl = dl_res.dl_predicted_level
        methods = ["Sistema de Reglas\n(ISO 27001)", "MLP Deep Learning\n(Clasificador)", f"Score Ajustado DL\n(penalización AE)"]
        scores_m = [dl_res.rule_based_score, round(dl_res.dl_confidence*100,1), dl_res.dl_adjusted_score]
        colors_m = [level_color(rule_lvl), level_color(dl_lvl), level_color(int(dl_res.dl_adjusted_score/20))]
        fig_comp = go.Figure(go.Bar(
            x=methods, y=scores_m, marker_color=colors_m,
            text=[f"Nv.{l} · {s:.1f}" for l,s in zip([rule_lvl,dl_lvl,int(dl_res.dl_adjusted_score/20)],scores_m)],
            textposition="outside", textfont=dict(color="#9a958a",size=9),
            hovertemplate="<b>%{x}</b><br>%{text}<extra></extra>",
        ))
        acuerdo_txt = "✓ Ambos métodos coinciden" if dl_res.agreement else "⚠ Métodos difieren — revisar"
        acuerdo_color = C["safe"] if dl_res.agreement else C["risk"]
        fig_comp.update_layout(height=280, margin=dict(l=10,r=10,t=20,b=60), **PLOTLY_DARK,
            yaxis=dict(title="Score / Confianza (%)", range=[0,115], **PLOTLY_AXIS_DARK),
            xaxis=dict(tickfont=dict(color="#9a958a",size=9)),
            showlegend=False,
            annotations=[dict(text=f"<span style='color:{acuerdo_color}'>{acuerdo_txt}</span>",
                              x=0.5, y=-0.22, xref="paper", yref="paper",
                              font=dict(color=acuerdo_color,size=11), showarrow=False)],
        )
        st.plotly_chart(fig_comp, use_container_width=True)

    # Tabla modelos DL
    sm_ae = dl_res.ae_summary; sm_lstm = dl_res.lstm_summary; sm_mlp = dl_res.mlp_summary
    df_models = pd.DataFrame([
        {"Modelo":"Autoencoder","Arquitectura":sm_ae.get("architecture",""),
         "Parámetros":f"{sm_ae.get('parameters',0):,}","Épocas":sm_ae.get("epochs_trained",""),
         "Loss train":sm_ae.get("final_train_loss",""),"Loss val":sm_ae.get("final_val_loss",""),
         "Métrica":f"Anomalías: {dl_res.anomaly_rate:.1f}%"},
        {"Modelo":"LSTM Bidireccional","Arquitectura":sm_lstm.get("architecture",""),
         "Parámetros":f"{sm_lstm.get('parameters',0):,}","Épocas":sm_lstm.get("epochs_trained",""),
         "Loss train":sm_lstm.get("final_train_loss",""),"Loss val":sm_lstm.get("final_val_loss",""),
         "Métrica":f"Prob. amenaza: {tl.get('mean_threat_prob',0.0):.1%}"},
        {"Modelo":"MLP Clasificador","Arquitectura":sm_mlp.get("architecture",""),
         "Parámetros":f"{sm_mlp.get('parameters',0):,}","Épocas":sm_mlp.get("epochs_trained",""),
         "Loss train":sm_mlp.get("final_train_loss",""),"Loss val":sm_mlp.get("final_val_loss",""),
         "Métrica":f"Nivel {dl_res.dl_predicted_level} ({dl_res.dl_confidence:.1f}%)"},
    ])
    st.dataframe(df_models, use_container_width=True, hide_index=True)
    st.success(
        f"Análisis Deep Learning completado · "
        f"Total parámetros: {sm_ae.get('parameters',0)+sm_lstm.get('parameters',0)+sm_mlp.get('parameters',0):,} · "
        f"Score ajustado DL: {dl_res.dl_adjusted_score:.1f}/100"
    )
else:
    st.markdown("<div style='padding:16px 48px;font-family:var(--mono);font-size:0.78rem;color:var(--bone-faint)'>↑ Configura las épocas y presiona Entrenar para activar el análisis neuronal.</div>", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# FOOTER
# ────────────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="dossier-footer">
  <div style="display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:40px;align-items:start">
    <div>
      <div class="foot-mark">Dossier <span class="iso">27001</span></div>
      <div class="foot-caption">
        Evaluador de Madurez en Seguridad de la Información<br>
        ISO/IEC 27001:2022 · COBIT 5 · Deep Learning<br>
        Fuente analizada: {source_label}
      </div>
    </div>
    <div>
      <div style="font-family:var(--mono);font-size:0.58rem;letter-spacing:0.2em;text-transform:uppercase;color:var(--bone-faint);margin-bottom:12px">Estándar</div>
      <div style="font-family:var(--mono);font-size:0.72rem;color:var(--bone-dim);line-height:1.9">
        ISO/IEC 27001:2022<br>
        93 Controles · 4 Temas<br>
        Anexo A: A.5 · A.6 · A.7 · A.8
      </div>
    </div>
    <div>
      <div style="font-family:var(--mono);font-size:0.58rem;letter-spacing:0.2em;text-transform:uppercase;color:var(--bone-faint);margin-bottom:12px">Eventos procesados</div>
      <div style="font-family:var(--serif);font-weight:800;font-size:2rem;color:var(--signal);line-height:1">{result.total_events:,}</div>
      <div style="font-family:var(--mono);font-size:0.66rem;color:var(--bone-faint);margin-top:4px">Nivel global: {lvl} — {lvl_info['name']}</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)
