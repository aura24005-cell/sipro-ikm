import math
import hashlib
import hmac
import secrets
from datetime import date

import pandas as pd
import plotly.express as px
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
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


def get_connection():
    return DatabaseConnection()


def init_db():
    """
    Membuat tabel dan memigrasikan skema satu-menu versi lama ke multi-menu.
    Data lama dipertahankan dan dimasukkan ke menu 'Menu Utama (data lama)'.
    Proses ini idempotent sehingga aman dijalankan setiap aplikasi dimulai.
    """
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
            CREATE TABLE IF NOT EXISTS menus (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                nama_menu TEXT NOT NULL,
                harga_jual_default DOUBLE PRECISION NOT NULL DEFAULT 0,
                biaya_produksi_default DOUBLE PRECISION NOT NULL DEFAULT 0,
                aktif BOOLEAN NOT NULL DEFAULT TRUE,
                dibuat_pada TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS menus_user_name_lower_idx
            ON menus (user_id, LOWER(nama_menu))
        """)

        # Tabel lama tetap digunakan agar riwayat lama tidak hilang.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS data_harian (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tanggal DATE NOT NULL,
                produksi INTEGER NOT NULL DEFAULT 0,
                penjualan INTEGER NOT NULL DEFAULT 0,
                sisa_ayam INTEGER NOT NULL DEFAULT 0,
                harga_jual DOUBLE PRECISION NOT NULL DEFAULT 0,
                biaya_produksi DOUBLE PRECISION NOT NULL DEFAULT 0,
                dibuat_pada TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tambahkan relasi menu ke tabel data lama.
        conn.execute("""
            ALTER TABLE data_harian
            ADD COLUMN IF NOT EXISTS menu_id BIGINT
        """)

        # Hapus batasan lama: satu catatan per akun per tanggal.
        conn.execute("""
            ALTER TABLE data_harian
            DROP CONSTRAINT IF EXISTS data_harian_user_id_tanggal_key
        """)

        # Backfill data lama ke menu khusus per akun.
        conn.execute("""
            INSERT INTO menus (user_id, nama_menu, harga_jual_default,
                               biaya_produksi_default, aktif)
            SELECT DISTINCT d.user_id, 'Menu Utama (data lama)', 0, 0, TRUE
            FROM data_harian d
            WHERE d.menu_id IS NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM menus m
                  WHERE m.user_id = d.user_id
                    AND LOWER(m.nama_menu) = LOWER('Menu Utama (data lama)')
              )
        """)
        conn.execute("""
            UPDATE data_harian d
            SET menu_id = m.id
            FROM menus m
            WHERE d.menu_id IS NULL
              AND m.user_id = d.user_id
              AND LOWER(m.nama_menu) = LOWER('Menu Utama (data lama)')
        """)

        # Pastikan setiap baris baru harus terkait ke sebuah menu.
        conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'data_harian_menu_id_fkey'
                ) THEN
                    ALTER TABLE data_harian
                    ADD CONSTRAINT data_harian_menu_id_fkey
                    FOREIGN KEY (menu_id) REFERENCES menus(id) ON DELETE RESTRICT;
                END IF;
            END $$;
        """)
        conn.execute("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM data_harian WHERE menu_id IS NULL
                ) THEN
                    RAISE EXCEPTION 'Migrasi menu gagal: masih ada data tanpa menu_id.';
                END IF;
            END $$;
        """)
        conn.execute("""
            ALTER TABLE data_harian
            ALTER COLUMN menu_id SET NOT NULL
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS data_harian_user_menu_tanggal_idx
            ON data_harian (user_id, menu_id, tanggal)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS data_harian_user_tanggal_idx
            ON data_harian (user_id, tanggal)
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


# =========================================================
# MANAJEMEN MENU
# =========================================================
def load_menus(user_id, active_only=False):
    query = """
        SELECT * FROM menus
        WHERE user_id = %s
    """
    if active_only:
        query += " AND aktif = TRUE"
    query += " ORDER BY aktif DESC, nama_menu ASC"

    with get_connection() as conn:
        rows = conn.execute(query, (user_id,)).fetchall()
    return pd.DataFrame([dict(row) for row in rows])


def add_menu(user_id, nama_menu, harga_jual, biaya_produksi):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO menus
                (user_id, nama_menu, harga_jual_default, biaya_produksi_default)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, nama_menu.strip(), float(harga_jual), float(biaya_produksi)),
        )


def update_menu(user_id, menu_id, nama_menu, harga_jual, biaya_produksi):
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE menus
            SET nama_menu=%s, harga_jual_default=%s, biaya_produksi_default=%s
            WHERE id=%s AND user_id=%s
            """,
            (nama_menu.strip(), float(harga_jual), float(biaya_produksi),
             int(menu_id), user_id),
        )


def set_menu_active(user_id, menu_id, active):
    with get_connection() as conn:
        conn.execute(
            "UPDATE menus SET aktif=%s WHERE id=%s AND user_id=%s",
            (bool(active), int(menu_id), user_id),
        )


# =========================================================
# DATA HARIAN
# =========================================================
def load_data(user_id, menu_id=None, include_archived=True):
    query = """
        SELECT
            d.*,
            m.nama_menu,
            (d.penjualan * d.harga_jual) AS pendapatan,
            (d.produksi * d.biaya_produksi) AS total_biaya,
            ((d.penjualan * d.harga_jual) -
             (d.produksi * d.biaya_produksi)) AS keuntungan
        FROM data_harian d
        INNER JOIN menus m ON m.id = d.menu_id
        WHERE d.user_id = %s
    """
    params = [user_id]
    if menu_id is not None:
        query += " AND d.menu_id = %s"
        params.append(int(menu_id))
    if not include_archived:
        query += " AND m.aktif = TRUE"
    query += " ORDER BY d.tanggal ASC, m.nama_menu ASC"

    with get_connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()

    df = pd.DataFrame([dict(row) for row in rows])
    if not df.empty:
        df["tanggal"] = pd.to_datetime(df["tanggal"]).dt.date
    return df


def save_data(user_id, menu_id, tanggal, produksi, penjualan, sisa_produk,
              harga_jual, biaya_produksi, edit_id=None):
    with get_connection() as conn:
        if edit_id is None:
            conn.execute(
                """
                INSERT INTO data_harian
                    (user_id, menu_id, tanggal, produksi, penjualan, sisa_ayam,
                     harga_jual, biaya_produksi)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (user_id, int(menu_id), str(tanggal), int(produksi),
                 int(penjualan), int(sisa_produk), float(harga_jual),
                 float(biaya_produksi)),
            )
        else:
            conn.execute(
                """
                UPDATE data_harian
                SET menu_id=%s, tanggal=%s, produksi=%s, penjualan=%s,
                    sisa_ayam=%s, harga_jual=%s, biaya_produksi=%s
                WHERE id=%s AND user_id=%s
                """,
                (int(menu_id), str(tanggal), int(produksi), int(penjualan),
                 int(sisa_produk), float(harga_jual), float(biaya_produksi),
                 int(edit_id), user_id),
            )


def save_many_daily_rows(user_id, tanggal, rows):
    """Simpan semua menu pada satu tanggal dalam satu transaksi."""
    with get_connection() as conn:
        for row in rows:
            conn.execute(
                """
                INSERT INTO data_harian
                    (user_id, menu_id, tanggal, produksi, penjualan, sisa_ayam,
                     harga_jual, biaya_produksi)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, menu_id, tanggal)
                DO UPDATE SET
                    produksi = EXCLUDED.produksi,
                    penjualan = EXCLUDED.penjualan,
                    sisa_ayam = EXCLUDED.sisa_ayam,
                    harga_jual = EXCLUDED.harga_jual,
                    biaya_produksi = EXCLUDED.biaya_produksi
                """,
                (user_id, int(row["menu_id"]), str(tanggal),
                 int(row["produksi"]), int(row["penjualan"]),
                 int(row["sisa_produk"]), float(row["harga_jual"]),
                 float(row["biaya_produksi"])),
            )


def delete_data(user_id, row_id):
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM data_harian WHERE id=%s AND user_id=%s",
            (int(row_id), user_id),
        )


# =========================================================
# PERAMALAN DAN FORMAT
# =========================================================
def get_forecast(dataframe):
    """
    Moving Average 7 catatan penjualan terakhir untuk satu menu.
    Menggunakan catatan yang tersedia, bukan mengisi tanggal kosong menjadi nol.
    """
    if dataframe.empty:
        return None, 0, 0

    ordered = dataframe.sort_values("tanggal")
    recent = ordered.tail(7)
    forecast = float(recent["penjualan"].mean())
    latest_leftover = int(ordered.iloc[-1]["sisa_ayam"])
    recommendation = max(0, math.ceil(forecast - latest_leftover))
    return forecast, latest_leftover, recommendation


def rupiah(value):
    return "Rp" + f"{float(value):,.0f}".replace(",", ".")


def safe_int(value):
    return int(value) if pd.notna(value) else 0


# =========================================================
# INISIALISASI
# =========================================================
try:
    init_db()
except Exception as exc:
    st.error("Database belum siap atau proses migrasi mengalami kendala.")
    st.code(str(exc))
    st.info(
        "Jangan menghapus tabel Supabase. Periksa koneksi database dan pastikan "
        "akun database memiliki izin untuk membuat/mengubah tabel."
    )
    st.stop()

if "user_id" not in st.session_state:
    st.session_state.user_id = None


# =========================================================
# CSS / TAMPILAN
# =========================================================
st.markdown("""
<style>
    .stApp { background-color: #fbfaf2; color: #203b2b; }
    .stApp p, .stApp label, .stApp span, .stApp li,
    .stApp [data-testid="stMarkdownContainer"] { color: #203b2b; }
    h1, h2, h3, h4, h5, h6 {
        color: #285d35 !important; font-weight: 700;
    }
    [data-testid="stSidebar"] { background-color: #eaf2dc; }
    [data-testid="stSidebar"] * { color: #244d2d !important; }
    .stTextInput input, .stNumberInput input,
    .stDateInput input, [data-baseweb="select"] * {
        color: #203b2b !important; background-color: #fffefa !important;
    }
    input::placeholder { color: #788477 !important; opacity: 1; }
    div.stButton > button[kind="primary"],
    div.stFormSubmitButton > button[kind="primary"] {
        background: #34763d; color: #ffffff !important;
        border-radius: 12px; border: 0; min-height: 42px; font-weight: 600;
    }
    div.stButton > button, div.stFormSubmitButton > button {
        border-radius: 12px; color: #285d35 !important; border-color: #8baa7c;
    }
    [data-testid="stMetric"] {
        background: #edf4e3; padding: 14px; border-radius: 14px;
        border: 1px solid #dce9ce;
    }
    [data-testid="stMetric"] label,
    [data-testid="stMetric"] [data-testid="stMetricValue"],
    [data-testid="stMetric"] [data-testid="stMetricDelta"] {
        color: #244d2d !important;
    }
    .intro {
        background: #e8f1d9; padding: 18px 22px; border-radius: 18px;
        color: #244d2d !important; margin-bottom: 14px;
    }
    .intro * { color: #244d2d !important; }
    .recommendation {
        background: #e4f0dc; padding: 18px; border-radius: 18px;
        border: 1px solid #c9dfbd; color: #244d2d !important;
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
            <p style="color:#526653;">Sistem Pendukung Keputusan Produksi</p>
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
                reg_password = st.text_input("Buat password", type="password")
                reg_confirm = st.text_input("Konfirmasi password", type="password")
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
                            reg_username, reg_password, reg_owner, reg_business
                        )
                        st.success(
                            "Akun berhasil dibuat. Silakan masuk menggunakan akun baru."
                        )
                    except IntegrityError:
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
menus_df = load_menus(user_id)
active_menus = menus_df[menus_df["aktif"] == True].copy() if not menus_df.empty else menus_df
df = load_data(user_id)


# =========================================================
# SIDEBAR / NAVIGASI
# =========================================================
st.sidebar.markdown("# 🌿 SI-PRO IKM")
st.sidebar.caption(APP_SUBTITLE)
st.sidebar.markdown(f"**{user['business_name']}**")
st.sidebar.caption(f"Pemilik: {user['owner_name']}")
st.sidebar.markdown("---")

menu_page = st.sidebar.radio(
    "Menu utama",
    [
        "Dashboard",
        "Manajemen Menu",
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
if menu_page == "Dashboard":
    st.title("🌿 Dashboard")
    st.markdown(
        f'<div class="intro"><b>Selamat datang, {user["owner_name"]}!</b><br>'
        f'Pantau produksi, penjualan, dan rekomendasi setiap menu '
        f'{user["business_name"]} dalam satu halaman.</div>',
        unsafe_allow_html=True,
    )

    if menus_df.empty or active_menus.empty:
        st.info("Belum ada menu aktif. Tambahkan menu terlebih dahulu melalui Manajemen Menu.")
    else:
        active_ids = active_menus["id"].astype(int).tolist()
        active_data = df[df["menu_id"].isin(active_ids)].copy() if not df.empty else pd.DataFrame()

        if active_data.empty:
            st.metric("Menu aktif", len(active_menus))
            st.info("Menu sudah dibuat. Masukkan data harian untuk melihat ringkasan dan rekomendasi.")
        else:
            latest_date = active_data["tanggal"].max()
            latest = active_data[active_data["tanggal"] == latest_date]
            total_production = int(latest["produksi"].sum())
            total_sales = int(latest["penjualan"].sum())
            total_leftover = int(latest["sisa_ayam"].sum())
            total_revenue = float(latest["pendapatan"].sum())

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Menu aktif", len(active_menus))
            c2.metric("Produksi pada data terakhir", f"{total_production} porsi")
            c3.metric("Penjualan pada data terakhir", f"{total_sales} porsi")
            c4.metric("Pendapatan pada data terakhir", rupiah(total_revenue))

            st.caption(f"Ringkasan data terakhir: {latest_date:%d %B %Y}")
            st.subheader("Rekomendasi Produksi per Menu")
            recommendation_rows = []
            for _, menu_row in active_menus.iterrows():
                menu_data = active_data[active_data["menu_id"] == int(menu_row["id"])]
                forecast, leftover, recommendation = get_forecast(menu_data)
                if forecast is not None:
                    recommendation_rows.append({
                        "Menu": menu_row["nama_menu"],
                        "Rata-rata permintaan": round(forecast, 1),
                        "Sisa layak jual terakhir": leftover,
                        "Rekomendasi produksi": recommendation,
                    })
            if recommendation_rows:
                st.dataframe(
                    pd.DataFrame(recommendation_rows),
                    use_container_width=True,
                    hide_index=True,
                )

            chart_df = active_data.sort_values("tanggal").tail(30)
            st.subheader("Tren Penjualan per Menu")
            fig = px.line(
                chart_df, x="tanggal", y="penjualan", color="nama_menu",
                markers=True,
                labels={
                    "tanggal": "Tanggal", "penjualan": "Penjualan (porsi)",
                    "nama_menu": "Menu",
                },
            )
            fig.update_layout(
                paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
                font_color="#244d2d",
            )
            st.plotly_chart(fig, use_container_width=True)


# =========================================================
# MANAJEMEN MENU
# =========================================================
elif menu_page == "Manajemen Menu":
    st.title("🍽️ Manajemen Menu")
    st.markdown(
        '<div class="intro">Tambahkan semua produk atau menu yang dijual oleh usaha. '
        'Setiap menu memiliki riwayat penjualan dan peramalan masing-masing.</div>',
        unsafe_allow_html=True,
    )

    with st.expander("➕ Tambah Menu Baru", expanded=menus_df.empty):
        with st.form("add_menu_form", clear_on_submit=True):
            nama_menu = st.text_input("Nama menu", placeholder="Contoh: Ayam Geprek")
            m1, m2 = st.columns(2)
            with m1:
                harga_default = st.number_input(
                    "Harga jual default per porsi (Rp)", min_value=0,
                    value=0, step=500,
                )
            with m2:
                biaya_default = st.number_input(
                    "Biaya produksi default per porsi (Rp)", min_value=0,
                    value=0, step=500,
                )
            add_submit = st.form_submit_button(
                "Simpan Menu", type="primary", use_container_width=True
            )
        if add_submit:
            if not nama_menu.strip():
                st.error("Nama menu wajib diisi.")
            else:
                try:
                    add_menu(user_id, nama_menu, harga_default, biaya_default)
                    st.success(f"Menu '{nama_menu.strip()}' berhasil ditambahkan.")
                    st.rerun()
                except IntegrityError:
                    st.error("Nama menu tersebut sudah terdaftar pada usaha ini.")

    st.subheader("Daftar Menu")
    if menus_df.empty:
        st.info("Belum ada menu. Tambahkan menu pertama usaha kamu.")
    else:
        display_menus = menus_df.copy()
        display_menus["Status"] = display_menus["aktif"].map(
            {True: "Aktif", False: "Diarsipkan"}
        )
        display_menus["Harga jual default"] = display_menus[
            "harga_jual_default"
        ].apply(rupiah)
        display_menus["Biaya produksi default"] = display_menus[
            "biaya_produksi_default"
        ].apply(rupiah)
        st.dataframe(
            display_menus[[
                "nama_menu", "Harga jual default",
                "Biaya produksi default", "Status",
            ]].rename(columns={"nama_menu": "Nama menu"}),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")
        st.subheader("Edit atau Arsipkan Menu")
        menu_options = {
            f"{row['nama_menu']} — {'Aktif' if row['aktif'] else 'Diarsipkan'}":
                int(row["id"])
            for _, row in menus_df.iterrows()
        }
        selected_menu_label = st.selectbox(
            "Pilih menu", list(menu_options.keys()), key="manage_menu_select"
        )
        selected_menu_id = menu_options[selected_menu_label]
        selected_menu = menus_df[
            menus_df["id"] == selected_menu_id
        ].iloc[0]

        with st.expander("✏️ Edit informasi menu"):
            with st.form(f"edit_menu_{selected_menu_id}"):
                edit_menu_name = st.text_input(
                    "Nama menu", value=selected_menu["nama_menu"]
                )
                em1, em2 = st.columns(2)
                with em1:
                    edit_menu_price = st.number_input(
                        "Harga jual default (Rp)", min_value=0,
                        value=int(selected_menu["harga_jual_default"]),
                        step=500,
                    )
                with em2:
                    edit_menu_cost = st.number_input(
                        "Biaya produksi default (Rp)", min_value=0,
                        value=int(selected_menu["biaya_produksi_default"]),
                        step=500,
                    )
                edit_menu_submit = st.form_submit_button(
                    "Simpan Perubahan", type="primary"
                )
            if edit_menu_submit:
                if not edit_menu_name.strip():
                    st.error("Nama menu tidak boleh kosong.")
                else:
                    try:
                        update_menu(
                            user_id, selected_menu_id, edit_menu_name,
                            edit_menu_price, edit_menu_cost,
                        )
                        st.success("Informasi menu berhasil diperbarui.")
                        st.rerun()
                    except IntegrityError:
                        st.error("Nama menu tersebut sudah digunakan.")

        if selected_menu["aktif"]:
            st.warning(
                "Jika menu tidak lagi dijual, arsipkan menu agar riwayat lama "
                "tetap tersimpan dan menu tidak muncul pada input harian."
            )
            if st.button("Arsipkan Menu Ini", key=f"archive_{selected_menu_id}"):
                set_menu_active(user_id, selected_menu_id, False)
                st.success("Menu berhasil diarsipkan.")
                st.rerun()
        else:
            if st.button("Aktifkan Kembali Menu Ini", key=f"activate_{selected_menu_id}"):
                set_menu_active(user_id, selected_menu_id, True)
                st.success("Menu berhasil diaktifkan kembali.")
                st.rerun()


# =========================================================
# INPUT DATA
# =========================================================
elif menu_page == "Input Data":
    st.title("📝 Input Data Harian")
    st.markdown(
        '<div class="intro">Masukkan data semua menu pada tanggal yang sama. '
        'Data setiap menu disimpan dan dianalisis secara terpisah.</div>',
        unsafe_allow_html=True,
    )

    if active_menus.empty:
        st.warning("Belum ada menu aktif. Tambahkan menu terlebih dahulu di Manajemen Menu.")
    else:
        input_date = st.date_input("Tanggal pencatatan", value=date.today())
        st.caption(
            "Isi data untuk setiap menu. Jika suatu menu tidak terjual pada hari tersebut, "
            "masukkan penjualan 0 agar catatan hariannya tetap tercatat."
        )

        input_rows = []
        with st.form("multi_menu_input_form"):
            for _, menu_row in active_menus.iterrows():
                menu_id = int(menu_row["id"])
                st.markdown(f"### 🍽️ {menu_row['nama_menu']}")
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    production = st.number_input(
                        "Jumlah produksi (porsi)", min_value=0, step=1,
                        key=f"input_prod_{menu_id}",
                    )
                    sales = st.number_input(
                        "Jumlah terjual (porsi)", min_value=0, step=1,
                        key=f"input_sales_{menu_id}",
                    )
                with col_b:
                    leftover = st.number_input(
                        "Sisa layak jual akhir hari (porsi)", min_value=0, step=1,
                        key=f"input_left_{menu_id}",
                    )
                    price = st.number_input(
                        "Harga jual per porsi (Rp)", min_value=0, step=500,
                        value=int(menu_row["harga_jual_default"]),
                        key=f"input_price_{menu_id}",
                    )
                with col_c:
                    cost = st.number_input(
                        "Biaya produksi per porsi (Rp)", min_value=0, step=500,
                        value=int(menu_row["biaya_produksi_default"]),
                        key=f"input_cost_{menu_id}",
                    )
                input_rows.append({
                    "menu_id": menu_id,
                    "produksi": production,
                    "penjualan": sales,
                    "sisa_produk": leftover,
                    "harga_jual": price,
                    "biaya_produksi": cost,
                })
                st.markdown("---")

            input_submit = st.form_submit_button(
                "💾 Simpan Data Semua Menu", type="primary",
                use_container_width=True,
            )

        if input_submit:
            try:
                save_many_daily_rows(user_id, input_date, input_rows)
                st.success(
                    "Data semua menu berhasil disimpan. Jika tanggal dan menu "
                    "sudah pernah diinput, catatan tersebut diperbarui."
                )
                st.rerun()
            except Exception as exc:
                st.error("Data belum berhasil disimpan.")
                st.caption(str(exc))


# =========================================================
# ANALISIS
# =========================================================
elif menu_page == "Analisis":
    st.title("📊 Analisis Penjualan")
    if active_menus.empty:
        st.info("Tambahkan menu terlebih dahulu melalui Manajemen Menu.")
    else:
        selected_analysis_menu = st.selectbox(
            "Pilih menu yang akan dianalisis",
            active_menus["id"].tolist(),
            format_func=lambda x: active_menus.loc[
                active_menus["id"] == x, "nama_menu"
            ].iloc[0],
        )
        menu_data = load_data(user_id, menu_id=int(selected_analysis_menu))
        if menu_data.empty:
            st.info("Belum ada data untuk menu ini. Masukkan data harian terlebih dahulu.")
        else:
            min_date = min(menu_data["tanggal"])
            max_date = max(menu_data["tanggal"])
            period = st.date_input(
                "Pilih rentang tanggal",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date,
                key=f"analysis_period_{selected_analysis_menu}",
            )
            if isinstance(period, tuple) and len(period) == 2:
                start_date, end_date = period
                view = menu_data[
                    (menu_data["tanggal"] >= start_date)
                    & (menu_data["tanggal"] <= end_date)
                ]
            else:
                view = menu_data.copy()

            if view.empty:
                st.warning("Tidak ada data pada rentang tanggal yang dipilih.")
            else:
                avg_sales = view["penjualan"].mean()
                total_sales = view["penjualan"].sum()
                total_production = view["produksi"].sum()
                highest = view["penjualan"].max()
                lowest = view["penjualan"].min()
                avg_leftover = view["sisa_ayam"].mean()
                total_revenue = view["pendapatan"].sum()
                total_profit = view["keuntungan"].sum()

                a, b, c = st.columns(3)
                a.metric("Rata-rata penjualan", f"{avg_sales:.1f} porsi/hari")
                b.metric("Penjualan tertinggi", f"{int(highest)} porsi")
                c.metric("Penjualan terendah", f"{int(lowest)} porsi")
                d, e, f = st.columns(3)
                d.metric("Total produksi", f"{int(total_production)} porsi")
                e.metric("Total penjualan", f"{int(total_sales)} porsi")
                f.metric("Rata-rata sisa produk", f"{avg_leftover:.1f} porsi")
                g, h = st.columns(2)
                g.metric("Total pendapatan", rupiah(total_revenue))
                h.metric("Estimasi keuntungan", rupiah(total_profit))

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
                        "produksi": "#91B9CF", "penjualan": "#D99A7C",
                    },
                )
                fig2.update_layout(
                    paper_bgcolor="#fbfaf2", plot_bgcolor="#fffefa",
                    font_color="#244d2d",
                )
                st.plotly_chart(fig2, use_container_width=True)


# =========================================================
# REKOMENDASI PRODUKSI
# =========================================================
elif menu_page == "Rekomendasi Produksi":
    st.title("💡 Rekomendasi Produksi")
    st.markdown(
        '<div class="intro">Sistem menghitung Moving Average dari maksimal '
        'tujuh catatan penjualan terbaru untuk setiap menu. Rekomendasi produksi '
        'mengurangi estimasi permintaan dengan sisa produk layak jual terakhir.</div>',
        unsafe_allow_html=True,
    )

    if active_menus.empty:
        st.warning("Tambahkan menu terlebih dahulu melalui Manajemen Menu.")
    else:
        recommendation_rows = []
        detail_by_menu = {}
        for _, menu_row in active_menus.iterrows():
            menu_id = int(menu_row["id"])
            menu_data = load_data(user_id, menu_id=menu_id)
            forecast, leftover, recommendation = get_forecast(menu_data)
            if forecast is None:
                recommendation_rows.append({
                    "Menu": menu_row["nama_menu"],
                    "Data tersedia": 0,
                    "Estimasi permintaan (porsi)": "-",
                    "Sisa layak jual (porsi)": "-",
                    "Rekomendasi produksi (porsi)": "Belum ada data",
                })
            else:
                recommendation_rows.append({
                    "Menu": menu_row["nama_menu"],
                    "Data tersedia": len(menu_data),
                    "Estimasi permintaan (porsi)": round(forecast, 1),
                    "Sisa layak jual (porsi)": leftover,
                    "Rekomendasi produksi (porsi)": recommendation,
                })
                detail_by_menu[menu_id] = menu_data

        result_df = pd.DataFrame(recommendation_rows)
        st.subheader("Tabel Rekomendasi per Menu")
        st.dataframe(result_df, use_container_width=True, hide_index=True)

        numeric_recommendations = [
            row["Rekomendasi produksi (porsi)"]
            for row in recommendation_rows
            if isinstance(row["Rekomendasi produksi (porsi)"], int)
        ]
        if numeric_recommendations:
            st.markdown("---")
            st.subheader("Total Rencana Produksi")
            st.metric(
                "Total seluruh menu",
                f"{sum(numeric_recommendations)} porsi",
            )
            st.caption(
                "Total merupakan penjumlahan rekomendasi menu yang sudah memiliki "
                "data historis. Menu tanpa data belum dapat dihitung."
            )

        with st.expander("Lihat dasar perhitungan setiap menu"):
            for _, menu_row in active_menus.iterrows():
                menu_id = int(menu_row["id"])
                if menu_id not in detail_by_menu:
                    st.write(f"**{menu_row['nama_menu']}**: belum memiliki data historis.")
                    continue
                menu_data = detail_by_menu[menu_id].sort_values("tanggal").tail(7)
                st.markdown(f"**{menu_row['nama_menu']}**")
                st.dataframe(
                    menu_data[["tanggal", "penjualan", "sisa_ayam"]].rename(
                        columns={
                            "tanggal": "Tanggal",
                            "penjualan": "Penjualan (porsi)",
                            "sisa_ayam": "Sisa layak jual (porsi)",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
                if len(menu_data) < 7:
                    st.caption(
                        f"Perhitungan menggunakan {len(menu_data)} catatan yang tersedia."
                    )


# =========================================================
# RIWAYAT
# =========================================================
elif menu_page == "Riwayat":
    st.title("🗂️ Riwayat Data Harian")
    if df.empty:
        st.info("Belum ada data yang tersimpan.")
    else:
        history = df.sort_values("tanggal", ascending=False).copy()
        menu_filter_options = ["Semua menu"] + sorted(history["nama_menu"].unique().tolist())
        selected_history_menu = st.selectbox(
            "Filter menu", menu_filter_options
        )
        if selected_history_menu != "Semua menu":
            history = history[history["nama_menu"] == selected_history_menu]

        filter_by_date = st.checkbox("Filter berdasarkan tanggal tertentu")
        if filter_by_date:
            selected_date = st.date_input("Pilih tanggal", value=date.today())
            history = history[history["tanggal"] == selected_date]

        display = history.rename(columns={
            "nama_menu": "Menu",
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
            "Tanggal", "Menu", "Produksi (porsi)", "Penjualan (porsi)",
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
        if not history.empty:
            options = {
                f"{row['tanggal']} — {row['nama_menu']} — "
                f"{int(row['penjualan'])} porsi terjual": int(row["id"])
                for _, row in history.iterrows()
            }
            selected_label = st.selectbox("Pilih catatan", list(options.keys()))
            selected_id = options[selected_label]
            selected = df[df["id"] == selected_id].iloc[0]

            all_menu_options = {
                int(row["id"]): row["nama_menu"]
                for _, row in menus_df.iterrows()
            }
            with st.expander("✏️ Edit catatan terpilih"):
                with st.form(f"edit_data_form_{selected_id}"):
                    edit_menu_id = st.selectbox(
                        "Menu",
                        list(all_menu_options.keys()),
                        index=list(all_menu_options.keys()).index(int(selected["menu_id"])),
                        format_func=lambda x: all_menu_options[x],
                    )
                    edit_tanggal = st.date_input(
                        "Tanggal", value=selected["tanggal"],
                        key=f"edit_date_{selected_id}",
                    )
                    e1, e2 = st.columns(2)
                    with e1:
                        edit_produksi = st.number_input(
                            "Produksi (porsi)", min_value=0,
                            value=int(selected["produksi"]), step=1,
                        )
                        edit_penjualan = st.number_input(
                            "Penjualan (porsi)", min_value=0,
                            value=int(selected["penjualan"]), step=1,
                        )
                        edit_sisa = st.number_input(
                            "Sisa layak jual akhir hari (porsi)", min_value=0,
                            value=int(selected["sisa_ayam"]), step=1,
                        )
                    with e2:
                        edit_harga = st.number_input(
                            "Harga jual/porsi (Rp)", min_value=0,
                            value=int(selected["harga_jual"]), step=500,
                        )
                        edit_biaya = st.number_input(
                            "Biaya produksi/porsi (Rp)", min_value=0,
                            value=int(selected["biaya_produksi"]), step=500,
                        )
                    update = st.form_submit_button(
                        "Simpan Perubahan", type="primary"
                    )
                    if update:
                        try:
                            save_data(
                                user_id, edit_menu_id, edit_tanggal,
                                int(edit_produksi), int(edit_penjualan),
                                int(edit_sisa), float(edit_harga),
                                float(edit_biaya), edit_id=selected_id,
                            )
                            st.success("Data berhasil diperbarui.")
                            st.rerun()
                        except IntegrityError:
                            st.error(
                                "Menu tersebut sudah memiliki catatan pada tanggal ini."
                            )

            with st.expander("🗑️ Hapus catatan terpilih"):
                st.warning("Data yang dihapus tidak dapat dikembalikan.")
                confirm = st.checkbox(
                    "Saya yakin ingin menghapus data ini.",
                    key=f"confirm_delete_{selected_id}",
                )
                if st.button(
                    "Hapus Data", disabled=not confirm,
                    key=f"delete_{selected_id}",
                ):
                    delete_data(user_id, selected_id)
                    st.success("Data berhasil dihapus.")
                    st.rerun()
        else:
            st.info("Tidak ada catatan pada filter yang dipilih.")


# =========================================================
# PROFIL USAHA
# =========================================================
elif menu_page == "Profil Usaha":
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
        "SI-PRO IKM kini mendukung banyak menu dalam satu akun. Riwayat dari "
        "versi satu-menu dipertahankan dan dipindahkan ke menu 'Menu Utama (data lama)'. "
        "Kamu dapat mengganti nama menu tersebut melalui Manajemen Menu."
    )
    st.caption("SI-PRO IKM · Sistem Pendukung Keputusan Produksi")
