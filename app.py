import math
import hashlib
import hmac
import secrets
from datetime import date

import pandas as pd
import plotly.express as px
import psycopg2
from psycopg2.extras import RealDictCursor
import streamlit as st

APP_NAME = "SI-PRO IKM"
APP_SUBTITLE = "Sistem Pendukung Keputusan Produksi"



# =========================================================
# KONFIGURASI HALAMAN
# =========================================================
st.set_page_config(
    page_title=APP_NAME,
    page_icon="🌿",
    layout="wide",
    initial_sidebar_state="expanded",
)


try:
    DATABASE_URL = st.secrets["DATABASE_URL"]
except Exception:
    DATABASE_URL = ""

if not DATABASE_URL:
    st.error(
        "DATABASE_URL belum dikonfigurasi. Tambahkan connection string "
        "Supabase pada Settings > Secrets di Streamlit Community Cloud."
    )
    st.stop()


# =========================================================
# DATABASE POSTGRESQL (SUPABASE)
# =========================================================
class DatabaseConnection:
    """Wrapper koneksi PostgreSQL dengan cursor berbentuk dictionary."""

    def __init__(self):
        self.connection = psycopg2.connect(
            DATABASE_URL,
            sslmode="require",
            connect_timeout=15,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()

    def execute(self, query, params=None):
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params or ())
        return cursor

    def commit(self):
        self.connection.commit()


def get_connection():
    return DatabaseConnection()


def table_exists(conn, table_name):
    result = conn.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (table_name,),
    ).fetchone()
    return result is not None


def init_db():
    """Membuat tabel PostgreSQL untuk akun dan data harian."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                business_name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
            ON users (LOWER(username))
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS data_harian (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tanggal DATE NOT NULL,
                produksi INTEGER NOT NULL,
                penjualan INTEGER NOT NULL,
                sisa_ayam INTEGER NOT NULL,
                harga_jual DOUBLE PRECISION NOT NULL,
                biaya_produksi DOUBLE PRECISION NOT NULL,
                dibuat_pada TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, tanggal)
            )
        """)


# =========================================================
# KEAMANAN AKUN
# =========================================================
def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
    ).hex()
    return f"{salt}${digest}"


def verify_password(password, stored_hash):
    try:
        salt, expected_digest = stored_hash.split("$", 1)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
        ).hex()
        return hmac.compare_digest(actual_digest, expected_digest)
    except (ValueError, AttributeError):
        return False


def create_user(username, password, owner_name, business_name):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, owner_name, business_name)
            VALUES (%s, %s, %s, %s)
            """,
            (
                username.strip(),
                hash_password(password),
                owner_name.strip(),
                business_name.strip(),
            ),
        )
        conn.commit()


def authenticate_user(username, password):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = LOWER(%s)",
            (username.strip(),),
        ).fetchone()

    if user and verify_password(password, user["password_hash"]):
        return dict(user)
    return None


def get_user(user_id):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id, username, owner_name, business_name FROM users WHERE id=%s",
            (user_id,),
        ).fetchone()
    return dict(user) if user else None


def update_user_profile(user_id, owner_name, business_name):
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET owner_name=%s, business_name=%s WHERE id=%s",
            (owner_name.strip(), business_name.strip(), user_id),
        )
        conn.commit()


# =========================================================
# DATA HARIAN - SEMUA QUERY WAJIB MEMAKAI user_id
# =========================================================
def load_data(user_id):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM data_harian
            WHERE user_id = %s
            ORDER BY tanggal ASC
            """,
            (user_id,),
        ).fetchall()

    df = pd.DataFrame([dict(row) for row in rows])
    if not df.empty:
        df["tanggal"] = pd.to_datetime(df["tanggal"]).dt.date
        df["pendapatan"] = df["penjualan"] * df["harga_jual"]
        df["total_biaya"] = df["produksi"] * df["biaya_produksi"]
        df["keuntungan"] = df["pendapatan"] - df["total_biaya"]
    return df

def save_data(
    user_id, tanggal, produksi, penjualan, sisa_ayam,
    harga_jual, biaya_produksi, edit_id=None
):
    with get_connection() as conn:
        if edit_id is None:
            conn.execute(
                """
                INSERT INTO data_harian
                (user_id, tanggal, produksi, penjualan, sisa_ayam,
                 harga_jual, biaya_produksi)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id, str(tanggal), produksi, penjualan, sisa_ayam,
                    harga_jual, biaya_produksi,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE data_harian
                SET tanggal=%s, produksi=%s, penjualan=%s, sisa_ayam=%s,
                    harga_jual=%s, biaya_produksi=%s
                WHERE id=%s AND user_id=%s
                """,
                (
                    str(tanggal), produksi, penjualan, sisa_ayam,
                    harga_jual, biaya_produksi, edit_id, user_id,
                ),
            )
        conn.commit()


def delete_data(user_id, row_id):
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM data_harian WHERE id=%s AND user_id=%s",
            (int(row_id), user_id),
        )
        conn.commit()


# =========================================================
# DATA LAMA
# =========================================================
# Database SQLite lama tidak otomatis tersedia di Supabase.
# Pemindahan data lama dilakukan terpisah setelah aplikasi online aktif.


# =========================================================
# PERAMALAN
# =========================================================
def get_forecast(dataframe):
    """Moving Average 7 catatan penjualan terbaru."""
    if dataframe.empty:
        return None, 0, 0

    recent = dataframe.sort_values("tanggal").tail(7)
    forecast = float(recent["penjualan"].mean())
    latest_leftover = int(
        dataframe.sort_values("tanggal").iloc[-1]["sisa_ayam"]
    )
    recommendation = max(0, math.ceil(forecast - latest_leftover))
    return forecast, latest_leftover, recommendation


def rupiah(value):
    return "Rp" + f"{float(value):,.0f}".replace(",", ".")


# =========================================================
# INISIALISASI
# =========================================================
init_db()

if "user_id" not in st.session_state:
    st.session_state.user_id = None

if "auth_page" not in st.session_state:
    st.session_state.auth_page = "Masuk"


# =========================================================
# CSS / TAMPILAN
# =========================================================
st.markdown("""
<style>
    .stApp {
        background-color: #fbfaf2;
        color: #203b2b;
    }
    .stApp p, .stApp label, .stApp span, .stApp li,
    .stApp [data-testid="stMarkdownContainer"] {
        color: #203b2b;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #285d35 !important;
        font-weight: 700;
    }
    [data-testid="stSidebar"] {
        background-color: #eaf2dc;
    }
    [data-testid="stSidebar"] * {
        color: #244d2d !important;
    }
    .stTextInput input, .stNumberInput input,
    .stDateInput input, [data-baseweb="select"] * {
        color: #203b2b !important;
        background-color: #fffefa !important;
    }
    input::placeholder {
        color: #788477 !important;
        opacity: 1;
    }
    div.stButton > button[kind="primary"],
    div.stFormSubmitButton > button[kind="primary"] {
        background: #34763d;
        color: #ffffff !important;
        border-radius: 12px;
        border: 0;
        min-height: 42px;
        font-weight: 600;
    }
    div.stButton > button, div.stFormSubmitButton > button {
        border-radius: 12px;
        color: #285d35 !important;
        border-color: #8baa7c;
    }
    [data-testid="stMetric"] {
        background: #edf4e3;
        padding: 14px;
        border-radius: 14px;
        border: 1px solid #dce9ce;
    }
    [data-testid="stMetric"] label,
    [data-testid="stMetric"] [data-testid="stMetricValue"],
    [data-testid="stMetric"] [data-testid="stMetricDelta"] {
        color: #244d2d !important;
    }
    .intro {
        background: #e8f1d9;
        padding: 18px 22px;
        border-radius: 18px;
        color: #244d2d !important;
        margin-bottom: 14px;
    }
    .intro * { color: #244d2d !important; }
    .recommendation {
        background: #e4f0dc;
        padding: 22px;
        border-radius: 18px;
        border: 1px solid #c9dfbd;
        text-align: center;
        color: #244d2d !important;
    }
    .recommendation * { color: #244d2d !important; }
    [data-testid="stAlert"] * { color: #203b2b !important; }
</style>
""", unsafe_allow_html=True)


# =========================================================
# LOGIN & REGISTRASI
# =========================================================
if st.session_state.user_id is None:
    st.markdown(
        """
        <div style="text-align:center;padding:30px 10px 12px 10px;">
            <div style="font-size:52px;">🌿</div>
            <h1 style="color:#285d35;">SI-PRO IKM</h1>
            <p style="color:#526653;">
                Sistem Pendukung Keputusan Produksi
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, center, right = st.columns([1, 1.25, 1])
    with center:
        tab_login, tab_register = st.tabs(["Masuk", "Daftar Akun"])

        with tab_login:
            with st.form("login_form"):
                st.subheader("Selamat Datang")
                login_username = st.text_input("Username")
                login_password = st.text_input("Password", type="password")
                login_submit = st.form_submit_button(
                    "Masuk", type="primary", use_container_width=True
                )

            if login_submit:
                user = authenticate_user(login_username, login_password)
                if user:
                    st.session_state.user_id = user["id"]
                    st.rerun()
                else:
                    st.error("Username atau password salah.")

        with tab_register:
            with st.form("register_form"):
                st.subheader("Buat Akun Baru")
                reg_owner = st.text_input("Nama pemilik usaha")
                reg_business = st.text_input("Nama usaha")
                reg_username = st.text_input("Buat username")
                reg_password = st.text_input(
                    "Buat password", type="password"
                )
                reg_confirm = st.text_input(
                    "Konfirmasi password", type="password"
                )
                register_submit = st.form_submit_button(
                    "Daftar", type="primary", use_container_width=True
                )

            if register_submit:
                if not all([
                    reg_owner.strip(), reg_business.strip(),
                    reg_username.strip(), reg_password, reg_confirm,
                ]):
                    st.error("Semua kolom wajib diisi.")
                elif len(reg_username.strip()) < 4:
                    st.error("Username minimal 4 karakter.")
                elif len(reg_password) < 8:
                    st.error("Password minimal 8 karakter.")
                elif reg_password != reg_confirm:
                    st.error("Konfirmasi password tidak sama.")
                else:
                    try:
                        create_user(
                            reg_username, reg_password,
                            reg_owner, reg_business,
                        )
                        st.success(
                            "Akun berhasil dibuat. Silakan masuk menggunakan akun baru."
                        )
                    except psycopg2.IntegrityError:
                        st.error("Username sudah digunakan. Silakan pilih username lain.")

    st.stop()


# =========================================================
# DATA PENGGUNA AKTIF
# =========================================================
user = get_user(st.session_state.user_id)
if not user:
    st.session_state.user_id = None
    st.rerun()
    st.stop()

user_id = int(user["id"])
df = load_data(user_id)


# =========================================================
# SIDEBAR / NAVIGASI
# =========================================================
st.sidebar.markdown("# 🌿 SI-PRO IKM")
st.sidebar.caption(APP_SUBTITLE)
st.sidebar.markdown(f"**{user['business_name']}**")
st.sidebar.caption(f"Pemilik: {user['owner_name']}")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Menu utama",
    [
        "Dashboard",
        "Input Data",
        "Analisis",
        "Rekomendasi Produksi",
        "Riwayat",
        "Profil Usaha",
    ],
)

st.sidebar.markdown("---")
if st.sidebar.button("Keluar", use_container_width=True):
    st.session_state.user_id = None
    st.rerun()

st.sidebar.caption("© SI-PRO IKM")


# =========================================================
# DASHBOARD
# =========================================================
if menu == "Dashboard":
    st.title("🌿 Dashboard")
    st.markdown(
        f'<div class="intro"><b>Selamat datang, {user["owner_name"]}!</b><br>'
        f'Pantau produksi, penjualan, dan rekomendasi produksi '
        f'{user["business_name"]} dalam satu halaman.</div>',
        unsafe_allow_html=True,
    )

    if df.empty:
        st.info("Belum ada data operasional. Silakan masukkan data melalui menu Input Data.")
    else:
        latest = df.sort_values("tanggal").iloc[-1]
        forecast, leftover, recommendation = get_forecast(df)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Produksi terakhir", f'{int(latest["produksi"])} porsi')
        c2.metric("Penjualan terakhir", f'{int(latest["penjualan"])} porsi')
        c3.metric("Sisa produk terakhir", f'{int(latest["sisa_ayam"])} porsi')
        c4.metric("Pendapatan terakhir", rupiah(latest["pendapatan"]))

        st.subheader("Rekomendasi Produksi Berikutnya")
        st.markdown(
            f'<div class="recommendation">'
            f'<div>Estimasi permintaan: <b>{forecast:.1f} porsi</b></div>'
            f'<h1 style="font-size:48px;margin:8px 0;">{recommendation} Porsi</h1>'
            f'<div>Sisa produk tercatat: <b>{leftover} porsi</b></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        chart_df = df.sort_values("tanggal").tail(14)
        st.subheader("Tren Penjualan")
        fig = px.line(
            chart_df, x="tanggal", y="penjualan", markers=True,
            title="Penjualan maksimal 14 catatan terakhir",
            labels={"tanggal": "Tanggal", "penjualan": "Penjualan (porsi)"},
        )
        fig.update_traces(line_color="#6F9F72")
        fig.update_layout(
            paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
            font_color="#244d2d",
        )
        st.plotly_chart(fig, use_container_width=True)

        compare = chart_df.melt(
            id_vars="tanggal",
            value_vars=["produksi", "penjualan"],
            var_name="Jenis", value_name="Jumlah (porsi)",
        )
        fig2 = px.bar(
            compare, x="tanggal", y="Jumlah (porsi)", color="Jenis",
            barmode="group", title="Perbandingan produksi dan penjualan",
            color_discrete_map={
                "produksi": "#91B9CF", "penjualan": "#D99A7C"
            },
        )
        fig2.update_layout(
            paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
            font_color="#244d2d",
        )
        st.plotly_chart(fig2, use_container_width=True)


# =========================================================
# INPUT DATA
# =========================================================
elif menu == "Input Data":
    st.title("📝 Input Data Harian")
    st.markdown(
        '<div class="intro">Masukkan data produksi dan penjualan '
        'untuk memperbarui data historis usaha.</div>',
        unsafe_allow_html=True,
    )

    with st.form("form_input", clear_on_submit=True):
        tanggal = st.date_input("Tanggal produksi", value=date.today())
        col1, col2 = st.columns(2)
        with col1:
            produksi = st.number_input("Jumlah produksi (porsi)", min_value=0, step=1)
            penjualan = st.number_input("Jumlah penjualan (porsi)", min_value=0, step=1)
            sisa_ayam = st.number_input("Sisa produk layak jual (porsi)", min_value=0, step=1)
        with col2:
            harga_jual = st.number_input("Harga jual per porsi (Rp)", min_value=0, step=500)
            biaya_produksi = st.number_input("Biaya produksi per porsi (Rp)", min_value=0, step=500)

        submitted = st.form_submit_button(
            "💾 Simpan Data", type="primary", use_container_width=True
        )

        if submitted:
            if penjualan > produksi + sisa_ayam:
                st.error("Jumlah penjualan tidak boleh melebihi produksi ditambah sisa yang tersedia.")
            else:
                try:
                    save_data(
                        user_id, tanggal, int(produksi), int(penjualan),
                        int(sisa_ayam), float(harga_jual), float(biaya_produksi),
                    )
                    st.success("Data berhasil disimpan!")
                    st.rerun()
                except psycopg2.IntegrityError:
                    st.error("Data untuk tanggal tersebut sudah ada. Buka menu Riwayat untuk mengedit data.")

    st.caption("Satu tanggal hanya dapat memiliki satu catatan untuk setiap akun.")


# =========================================================
# ANALISIS
# =========================================================
elif menu == "Analisis":
    st.title("📊 Analisis Penjualan")
    if df.empty:
        st.info("Belum ada data untuk dianalisis. Masukkan data harian terlebih dahulu.")
    else:
        min_date = min(df["tanggal"])
        max_date = max(df["tanggal"])
        period = st.date_input(
            "Pilih rentang tanggal",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date,
        )

        if isinstance(period, tuple) and len(period) == 2:
            start_date, end_date = period
            view = df[
                (df["tanggal"] >= start_date) &
                (df["tanggal"] <= end_date)
            ]
        else:
            view = df.copy()

        if view.empty:
            st.warning("Tidak ada data pada rentang tanggal yang dipilih.")
        else:
            avg_sales = view["penjualan"].mean()
            total_sales = view["penjualan"].sum()
            total_production = view["produksi"].sum()
            highest = view["penjualan"].max()
            lowest = view["penjualan"].min()
            avg_leftover = view["sisa_ayam"].mean()
            available = view["produksi"] + view["sisa_ayam"]
            sold_ratio = (
                view["penjualan"].sum() / available.sum() * 100
                if available.sum() else 0
            )

            a, b, c = st.columns(3)
            a.metric("Rata-rata penjualan", f"{avg_sales:.1f} porsi/hari")
            b.metric("Penjualan tertinggi", f"{int(highest)} porsi")
            c.metric("Penjualan terendah", f"{int(lowest)} porsi")

            d, e, f = st.columns(3)
            d.metric("Total produksi", f"{int(total_production)} porsi")
            e.metric("Total penjualan", f"{int(total_sales)} porsi")
            f.metric("Rata-rata sisa produk", f"{avg_leftover:.1f} porsi")
            st.metric("Persentase terjual dari produksi + sisa yang dicatat", f"{sold_ratio:.1f}%")

            fig = px.line(
                view, x="tanggal", y="penjualan", markers=True,
                title="Tren penjualan harian",
                labels={"tanggal": "Tanggal", "penjualan": "Penjualan (porsi)"},
            )
            fig.update_traces(line_color="#6F9F72")
            fig.update_layout(
                paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
                font_color="#244d2d",
            )
            st.plotly_chart(fig, use_container_width=True)

            compare = view.melt(
                id_vars="tanggal",
                value_vars=["produksi", "penjualan"],
                var_name="Jenis", value_name="Jumlah (porsi)",
            )
            fig2 = px.bar(
                compare, x="tanggal", y="Jumlah (porsi)", color="Jenis",
                barmode="group", title="Produksi dibandingkan penjualan",
                color_discrete_map={
                    "produksi": "#91B9CF", "penjualan": "#D99A7C"
                },
            )
            fig2.update_layout(
                paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
                font_color="#244d2d",
            )
            st.plotly_chart(fig2, use_container_width=True)

            fig3 = px.bar(
                view, x="tanggal", y="sisa_ayam",
                title="Sisa produk layak jual",
                labels={"tanggal": "Tanggal", "sisa_ayam": "Sisa (porsi)"},
                color_discrete_sequence=["#E8C875"],
            )
            fig3.update_layout(
                paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
                font_color="#244d2d",
            )
            st.plotly_chart(fig3, use_container_width=True)


# =========================================================
# REKOMENDASI PRODUKSI
# =========================================================
elif menu == "Rekomendasi Produksi":
    st.title("💡 Rekomendasi Produksi")
    st.markdown(
        '<div class="intro">Estimasi permintaan dihitung dari maksimal '
        'tujuh catatan penjualan terbaru.</div>',
        unsafe_allow_html=True,
    )

    if df.empty:
        st.warning("Belum ada data historis. Masukkan data penjualan terlebih dahulu.")
    else:
        forecast, leftover, recommendation = get_forecast(df)
        recent = df.sort_values("tanggal").tail(7)

        st.subheader("Hasil Rekomendasi")
        st.markdown(
            f'<div class="recommendation">'
            f'<p>Rekomendasi produksi untuk hari berikutnya</p>'
            f'<h1 style="font-size:54px;margin:8px 0;">{recommendation} Porsi</h1>'
            f'<p>Estimasi permintaan: <b>{forecast:.1f} porsi</b> '
            f'| Sisa produk layak jual: <b>{leftover} porsi</b></p></div>',
            unsafe_allow_html=True,
        )

        st.subheader("Data Penjualan yang Digunakan")
        st.dataframe(
            recent[["tanggal", "penjualan"]].rename(
                columns={
                    "tanggal": "Tanggal",
                    "penjualan": "Penjualan (porsi)",
                }
            ),
            use_container_width=True,
            hide_index=True,
        )

        if len(recent) < 7:
            st.info(
                f"Data baru tersedia {len(recent)} hari. "
                "Sistem menggunakan seluruh data yang tersedia."
            )

        if recommendation == 0:
            st.warning("Sisa produk yang tercatat sudah mencukupi atau melebihi estimasi permintaan.")


# =========================================================
# RIWAYAT
# =========================================================
elif menu == "Riwayat":
    st.title("🗂️ Riwayat Data Harian")
    if df.empty:
        st.info("Belum ada data yang tersimpan.")
    else:
        history = df.sort_values("tanggal", ascending=False).copy()
        filter_by_date = st.checkbox("Filter berdasarkan tanggal tertentu")
        if filter_by_date:
            search_date = st.date_input(
                "Pilih tanggal", value=date.today(), key="search_date"
            )
            history = history[history["tanggal"] == search_date]

        display = history.rename(columns={
            "tanggal": "Tanggal",
            "produksi": "Produksi (porsi)",
            "penjualan": "Penjualan (porsi)",
            "sisa_ayam": "Sisa produk (porsi)",
            "harga_jual": "Harga jual/porsi",
            "biaya_produksi": "Biaya produksi/porsi",
            "pendapatan": "Pendapatan",
            "total_biaya": "Total biaya produksi",
            "keuntungan": "Estimasi keuntungan",
        })
        cols = [
            "Tanggal", "Produksi (porsi)", "Penjualan (porsi)",
            "Sisa produk (porsi)", "Harga jual/porsi",
            "Biaya produksi/porsi", "Pendapatan",
            "Total biaya produksi", "Estimasi keuntungan",
        ]
        st.dataframe(
            display[cols], use_container_width=True, hide_index=True
        )

        csv = history.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "⬇️ Download riwayat (CSV)",
            data=csv,
            file_name="riwayat_data_usaha.csv",
            mime="text/csv",
        )

        st.markdown("---")
        st.subheader("Edit atau Hapus Data")
        options = {
            f"{row['tanggal']} — {int(row['penjualan'])} porsi terjual": int(row["id"])
            for _, row in history.iterrows()
        }

        if options:
            selected_label = st.selectbox("Pilih data", list(options.keys()))
            selected_id = options[selected_label]
            selected = df[df["id"] == selected_id].iloc[0]

            with st.expander("Edit data terpilih"):
                with st.form("edit_form"):
                    edit_tanggal = st.date_input(
                        "Tanggal", value=selected["tanggal"], key="edit_tanggal"
                    )
                    e1, e2 = st.columns(2)
                    with e1:
                        edit_produksi = st.number_input(
                            "Produksi (porsi)", min_value=0,
                            value=int(selected["produksi"]), step=1
                        )
                        edit_penjualan = st.number_input(
                            "Penjualan (porsi)", min_value=0,
                            value=int(selected["penjualan"]), step=1
                        )
                        edit_sisa = st.number_input(
                            "Sisa produk layak jual (porsi)", min_value=0,
                            value=int(selected["sisa_ayam"]), step=1
                        )
                    with e2:
                        edit_harga = st.number_input(
                            "Harga jual/porsi (Rp)", min_value=0,
                            value=int(selected["harga_jual"]), step=500
                        )
                        edit_biaya = st.number_input(
                            "Biaya produksi/porsi (Rp)", min_value=0,
                            value=int(selected["biaya_produksi"]), step=500
                        )

                    update = st.form_submit_button(
                        "Simpan perubahan", type="primary"
                    )
                    if update:
                        if edit_penjualan > edit_produksi + edit_sisa:
                            st.error("Penjualan tidak boleh melebihi produksi ditambah sisa.")
                        else:
                            try:
                                save_data(
                                    user_id, edit_tanggal, int(edit_produksi),
                                    int(edit_penjualan), int(edit_sisa),
                                    float(edit_harga), float(edit_biaya),
                                    edit_id=selected_id,
                                )
                                st.success("Data berhasil diperbarui.")
                                st.rerun()
                            except psycopg2.IntegrityError:
                                st.error("Tanggal tersebut sudah memiliki data lain.")

            with st.expander("Hapus data terpilih"):
                st.warning("Data yang dihapus tidak dapat dikembalikan.")
                confirm = st.checkbox(
                    "Saya yakin ingin menghapus data ini.",
                    key=f"confirm_delete_{selected_id}",
                )
                if st.button(
                    "Hapus data", disabled=not confirm,
                    key=f"delete_{selected_id}",
                ):
                    delete_data(user_id, selected_id)
                    st.success("Data berhasil dihapus.")
                    st.rerun()


# =========================================================
# PROFIL USAHA
# =========================================================
elif menu == "Profil Usaha":
    st.title("🏪 Profil Usaha")
    st.write("Perbarui identitas pemilik dan nama usaha yang ditampilkan di aplikasi.")

    with st.form("profile_form"):
        owner_name = st.text_input(
            "Nama pemilik usaha", value=user["owner_name"]
        )
        business_name = st.text_input(
            "Nama usaha", value=user["business_name"]
        )
        profile_submit = st.form_submit_button(
            "Simpan Profil", type="primary"
        )

    if profile_submit:
        if not owner_name.strip() or not business_name.strip():
            st.error("Nama pemilik dan nama usaha tidak boleh kosong.")
        else:
            update_user_profile(user_id, owner_name, business_name)
            st.success("Profil usaha berhasil diperbarui.")
            st.rerun()

    st.markdown("---")
    st.info(
        "Database aplikasi ini sudah menggunakan PostgreSQL online. "
        "Data dari database SQLite versi lokal tidak otomatis ikut berpindah. "
        "Simpan file database lama sebagai cadangan; pemindahan data lama "
        "akan dilakukan melalui proses migrasi terpisah."
    )

    st.markdown("---")
    st.caption("SI-PRO IKM · Sistem Pendukung Keputusan Produksi")
