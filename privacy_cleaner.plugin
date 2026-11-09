__id__ = "privacy_cleaner"
__name__ = "Privacy Cleaner"
__description__ = (
    "Чистит метаданные у фото и видео, трекинг-параметры в ссылках, проверяет ссылки "
    "на фишинг, показывает информацию о чате и устройство, с которого записан кружок. "
    "Всё работает на устройстве, без сети."
)
__author__ = "@m0lex (Sato.py)"
__version__ = "0.3.0"
__min_version__ = "11.12.1"

# Проверка ссылок основана на Link Guard (@Robobloxi), определение устройства записи
# кружка — на Round Client Detector (@netconfiger). Использовано с разрешения авторов.

import collections
from datetime import datetime
import os
import re
import threading
import time
import uuid
import shutil
import unicodedata
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, unquote_plus

from base_plugin import BasePlugin, HookResult, HookStrategy, MethodHook, MenuItemData, MenuItemType
from hook_utils import find_class
from java import jclass

try:
    from ui.settings import Header, Switch, Divider, Text, Input
    HAS_SETTINGS = True
except Exception:
    Header = Switch = Divider = Text = Input = None
    HAS_SETTINGS = False

try:
    from ui.alert import AlertDialogBuilder
except Exception:
    AlertDialogBuilder = None

try:
    from ui.bulletin import BulletinHelper
except Exception:
    BulletinHelper = None

try:
    from client_utils import get_last_fragment
except Exception:
    def get_last_fragment():
        return None

try:
    from client_utils import get_messages_controller
except Exception:
    get_messages_controller = None

try:
    from android_utils import log
except Exception:
    def log(*args):
        print("PrivacyCleaner:", *args)

try:
    from android_utils import run_on_ui_thread
except Exception:
    def run_on_ui_thread(func, delay=0):
        func()

try:
    from android_utils import copy_to_clipboard
except Exception:
    copy_to_clipboard = None

try:
    from hook_utils import get_private_field, set_private_field
except Exception:
    def get_private_field(obj, field):
        return getattr(obj, field, None)

    def set_private_field(obj, field, val):
        setattr(obj, field, val)

# --- Java ---------------------------------------------------------------
BitmapFactory = jclass("android.graphics.BitmapFactory")
Bitmap = jclass("android.graphics.Bitmap")
CompressFormat = jclass("android.graphics.Bitmap$CompressFormat")
Matrix = jclass("android.graphics.Matrix")
ExifInterface = jclass("android.media.ExifInterface")
FileOutputStream = jclass("java.io.FileOutputStream")
ApplicationLoader = jclass("org.telegram.messenger.ApplicationLoader")

JPEG_QUALITY = 95
MAX_VIDEO_MB = 200  # видео больше этого размера отправляются как есть

PHOTO_EXT = {".jpg", ".jpeg", ".png", ".heic", ".heif"}
VIDEO_EXT = {".mp4", ".m4v", ".mov", ".3gp"}

# ======================================================================
# Строки
# ======================================================================
S = {
    "hdr_media": "Медиа и файлы",
    "sw_photos": "Чистить фото",
    "sw_photos_sub": "Убирает EXIF (GPS, модель телефона, время съёмки) перед отправкой",
    "sw_videos": "Чистить видео и кружки",
    "sw_videos_sub": "Стирает метаданные mp4/mov (GPS, модель, даты)",
    "sw_names": "Случайные имена файлов",
    "sw_names_sub": "Вместо IMG_20261007_... отправляется случайное имя",
    "hdr_links": "Ссылки",
    "sw_clean_out": "Чистить ссылки в моих сообщениях",
    "sw_clean_out_sub": "Убирает utm_*, fbclid, gclid и прочие метки",
    "sw_check": "Проверять ссылки перед открытием",
    "sw_check_sub": "Разбор адреса на устройстве: фишинг, подмена символов, подозрительные домены",
    "sw_always": "Показывать разбор всегда",
    "sw_always_sub": "Иначе окно появляется только при подозрении",
    "sw_clean_open": "Чистить метки при переходе",
    "sw_clean_open_sub": "Убирает трекеры из ссылки, на которую вы нажали",
    "sw_aggr": "Агрессивная чистка",
    "sw_aggr_sub": "Дополнительно режет ref, si, spm, from — редкие ссылки могут перестать работать",
    "hdr_exc": "Исключения",
    "in_whitelist": "Доверенные домены",
    "in_whitelist_sub": "Через запятую, например: example.com, site.org",
    "note_title": "Что не делает плагин",
    "note_text": "Плагин не прячет IP-адрес и данные устройства от серверов Telegram. "
                 "Для этого нужны VPN или прокси. Сам плагин в сеть не выходит.",
    "menu_check": "Проверить ссылки",
    "menu_copy": "Копировать без трекеров",
    "menu_info": "Инфо о чате",
    "title_danger": "⛔ Опасная ссылка",
    "title_suspicious": "⚠️ Подозрительная ссылка",
    "title_info": "🔗 Разбор ссылки",
    "btn_open": "Открыть",
    "btn_cancel": "Отмена",
    "btn_trust": "Доверять",
    "btn_ok": "Понятно",
    "lbl_domain": "Домен: %s",
    "lbl_removed": "Убрано меток: %s (%s)",
    "checked_n": "Ссылок проверено: %s",
    "toast_no_links": "Ссылок в сообщении нет",
    "toast_no_dialog": "Разбор недоступен в этой сборке",
    "toast_trusted": "%s больше не проверяется",
    "toast_copied": "Не удалось открыть, ссылка скопирована",
    "toast_copied_ok": "Ссылки скопированы без трекеров",
    "toast_cleaned": "Убрано меток слежения: %s",
    "trust_title": "Больше не проверять домен?",
    "trust_body": "%s перестанет проверяться совсем. Убрать его можно в настройках плагина.",
    "btn_trust_yes": "Не проверять",
    "src_stranger": "Ссылка из чужого чата или канала",
    "src_trusted": "Ссылка от вашего контакта",
    "f_unparsable": "Адрес не разбирается — вероятно, специально исковеркан",
    "f_scheme": "Схема «%s» — это не переход на сайт, а выполнение кода или открытие файла",
    "f_nodomain": "В адресе нет домена",
    "f_userinfo": "Перед символом @ можно написать любой текст — настоящий домен здесь %s",
    "f_punycode": "Домен записан в punycode и выглядит как «%s»",
    "f_mixed": "В домене смешаны разные алфавиты (%s) — типичная маскировка",
    "f_lookalike": "Домен визуально копирует %s подменёнными символами",
    "f_typo": "Домен отличается от %s всего на %s %s",
    "f_subdomain": "«%s» стоит в поддомене, а сам сайт — %s",
    "f_anchor": "В сообщении ссылка подписана как %s, а ведёт на %s",
    "f_ip": "Вместо домена IP-адрес",
    "f_ip_local": "Адрес в локальной сети",
    "f_badport": "После двоеточия стоит не номер порта — адрес сломан или замаскирован",
    "f_port": "Нестандартный порт %s",
    "f_tld": "Доменная зона .%s часто используется для одноразовых мошеннических сайтов",
    "f_brand_extra": "В имени домена стоит «%s», но сайт этому сервису не принадлежит",
    "f_deep": "Очень длинная цепочка поддоменов",
    "f_long": "Неестественно длинный домен",
    "f_bait": "В адресе слова-приманки: %s",
    "f_exec": "Ссылка ведёт на файл %s — это установка программы, а не сайт",
    "f_short": "Сокращённая ссылка — настоящий адрес скрыт",
    "unit_char": "символ|символа|символов",
    "scripts_LATIN": "латиница",
    "scripts_CYRILLIC": "кириллица",
    "scripts_GREEK": "греческий",
    "scripts_ARMENIAN": "армянский",
    "scripts_HEBREW": "иврит",
}


def t(key, *args):
    text = S.get(key, key)
    return text % args if args else text


def plural_ru(forms, count):
    one, few, many = (str(forms).split("|") + ["", ""])[:3]
    tail = abs(int(count)) % 100
    if 11 <= tail <= 14:
        return many
    tail %= 10
    if tail == 1:
        return one
    if 2 <= tail <= 4:
        return few
    return many


def _as_str(obj):
    if isinstance(obj, str):
        return obj
    try:
        if obj is not None and obj.getClass().getName() == "java.lang.String":
            return str(obj)
    except Exception:
        pass
    return None


# ======================================================================
# Метаданные mp4
# ======================================================================
def _scrub_boxes(buf, start, end):
    """Заменяет udta/meta на free (размеры не меняются, смещения не ломаются)
    и обнуляет даты в mvhd/tkhd/mdhd."""
    pos = start
    while pos + 8 <= end:
        size = int.from_bytes(buf[pos:pos + 4], "big")
        typ = bytes(buf[pos + 4:pos + 8])
        hsz = 8
        if size == 1:
            if pos + 16 > end:
                break
            size = int.from_bytes(buf[pos + 8:pos + 16], "big")
            hsz = 16
        elif size == 0:
            size = end - pos
        if size < hsz or pos + size > end:
            break
        body = pos + hsz
        box_end = pos + size
        if typ in (b"udta", b"meta"):
            buf[pos + 4:pos + 8] = b"free"
            buf[body:box_end] = bytes(box_end - body)
        elif typ in (b"moov", b"trak", b"mdia"):
            _scrub_boxes(buf, body, box_end)
        elif typ in (b"mvhd", b"tkhd", b"mdhd"):
            n = 8 if buf[body] == 1 else 4
            off = body + 4
            buf[off:off + 2 * n] = bytes(2 * n)
        pos += size


def scrub_mp4_inplace(path):
    with open(path, "r+b") as f:
        f.seek(0, 2)
        end = f.tell()
        pos = 0
        while pos + 8 <= end:
            f.seek(pos)
            hdr = f.read(16)
            size = int.from_bytes(hdr[0:4], "big")
            typ = hdr[4:8]
            hsz = 8
            if size == 1:
                size = int.from_bytes(hdr[8:16], "big")
                hsz = 16
            elif size == 0:
                size = end - pos
            if size < hsz or pos + size > end:
                break
            if typ == b"moov":
                f.seek(pos + hsz)
                body = bytearray(f.read(size - hsz))
                _scrub_boxes(body, 0, len(body))
                f.seek(pos + hsz)
                f.write(body)
            elif typ in (b"udta", b"meta", b"uuid", b"XMP_"):
                f.seek(pos + 4)
                f.write(b"free")
                f.seek(pos + hsz)
                f.write(bytes(size - hsz))
            pos += size


# ======================================================================
# Ссылки: чистка трекеров (на основе Link Guard, @Robobloxi)
# ======================================================================
TRACKER_EXACT = {
    "fbclid", "gclid", "gbraid", "wbraid", "dclid", "msclkid", "twclid", "ttclid",
    "igshid", "igsh", "yclid", "ysclid", "_openstat", "mkt_tok", "vero_id", "vero_conv",
    "mc_cid", "mc_eid", "oly_anon_id", "oly_enc_id", "hsctatracking", "__hssc", "__hstc",
    "__hsfp", "_hsenc", "_hsmi", "wickedid", "rb_clickid", "s_cid", "epik", "otc", "cvid",
    "erid", "ymclid", "yadclid", "_ga", "_gl", "mc_tc", "sc_cid", "srsltid", "cjevent",
    "irclickid", "li_fat_id", "__s",
}
TRACKER_PREFIXES = ("utm_", "pk_", "mtm_", "piwik_", "hsa_", "at_custom", "stm_", "matomo_", "sc_")
TRACKER_AGGRESSIVE = {
    "ref", "referer", "referrer", "ref_src", "ref_url", "si", "spm", "scm", "from", "source",
    "share_source", "share_medium", "share_plat", "_branch_match_id", "feature", "trk",
    "trkcampaign",
}
# Параметры, которые безопасно резать всегда, но только на этих сайтах
DOMAIN_PARAMS = {
    "youtu.be": {"si", "feature"},
    "youtube.com": {"si", "feature"},
    "music.youtube.com": {"si", "feature"},
    "open.spotify.com": {"si"},
    "instagram.com": {"igsh", "igshid"},
}

URL_RE = re.compile(
    r"(?:(?:https?|ftp|tg)://|www\.)[^\s<>\"']*[^\s<>\"'.,;:!?)\]}»]",
    re.IGNORECASE,
)


def clean_url(url, aggressive=False):
    try:
        parts = urlsplit(url)
    except Exception:
        return url, []
    if not parts.query:
        return url, []
    host = (parts.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    extra = DOMAIN_PARAMS.get(host, set())

    kept, removed = [], []
    for segment in parts.query.split("&"):
        if not segment:
            continue
        key = unquote_plus(segment.split("=", 1)[0])
        low = key.lower()
        drop = (
            low in TRACKER_EXACT
            or low.startswith(TRACKER_PREFIXES)
            or low in extra
            or (aggressive and low in TRACKER_AGGRESSIVE)
        )
        if drop:
            removed.append(key)
        else:
            kept.append(segment)

    if not removed:
        return url, []
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(kept), parts.fragment)), removed


# ======================================================================
# Ссылки: разбор на фишинг (на основе Link Guard, без сети и без базы)
# ======================================================================
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "clck.ru", "vk.cc", "surl.li", "u.to", "qps.ru", "clc.to", "gg.gg", "tiny.cc",
    "shorte.st", "lnkd.in", "s.id", "rebrand.ly", "t.ly", "short.io", "l.ead.me", "dfl.to",
    "goo.su", "clck.su", "kurl.ru", "shrturi.com", "tlgg.ru",
}

BRANDS = {
    "telegram.org", "t.me", "telegram.me", "fragment.com", "walletbot.me", "google.com",
    "gmail.com", "youtube.com", "instagram.com", "facebook.com", "whatsapp.com", "discord.com",
    "steampowered.com", "steamcommunity.com", "github.com", "apple.com", "icloud.com",
    "microsoft.com", "office.com", "binance.com", "bybit.com", "metamask.io", "trustwallet.com",
    "vk.com", "ok.ru", "mail.ru", "yandex.ru", "dzen.ru", "avito.ru", "ozon.ru", "wildberries.ru",
    "sberbank.ru", "sbrf.ru", "tinkoff.ru", "tbank.ru", "alfabank.ru", "vtb.ru", "gosuslugi.ru",
    "nalog.gov.ru", "cdek.ru", "pochta.ru", "megafon.ru", "beeline.ru", "mts.ru", "aliexpress.ru",
    "citilink.ru", "dns-shop.ru", "mvideo.ru", "eldorado.ru", "lamoda.ru", "sportmaster.ru",
    "rzd.ru", "aeroflot.ru", "pochtabank.ru", "raiffeisen.ru", "psbank.ru", "gazprombank.ru",
    "sovcombank.ru", "yoomoney.ru", "sbermarket.ru", "samokat.ru", "vkusvill.ru", "rutube.ru",
    "twitch.tv", "epicgames.com", "roblox.com", "steamgifts.com",
}
BRAND_LIST = sorted(BRANDS)

GENERIC_LABELS = {"mail", "office", "post", "link", "click", "wallet"}

RISKY_TLD = {
    "zip", "mov", "top", "xyz", "icu", "cfd", "sbs", "cyou", "click", "link", "rest", "quest",
    "monster", "bar", "beauty", "makeup", "skin", "hair", "boats", "autos", "lol", "gdn", "tk",
    "ml", "ga", "cf", "gq", "buzz", "cricket", "download", "loan", "party", "review", "science",
    "stream", "trade", "webcam",
}

BAIT_WORDS = (
    "login", "signin", "verify", "confirm", "secure", "account", "update", "wallet", "seed",
    "recovery", "airdrop", "giveaway", "bonus", "promo", "gift", "premium-free", "nft-claim",
    "podarok", "vyigrysh", "bonus-ru", "oplata", "dostavka", "posylka", "shtraf", "vozvrat",
    "vyplata", "kompensaciya", "podtverdite", "razblokirovka", "verifikaciya",
)

DANGEROUS_EXT = (".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".jar", ".vbs", ".apks", ".xapk")
DANGEROUS_SCHEMES = {"javascript", "data", "file", "intent", "content", "jar"}

LOOKALIKE_LETTERS = {
    "а": "a", "б": "b", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ϲ": "c", "τ": "t",
    "υ": "u",
}

TWO_LEVEL_TLD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.br", "com.au", "com.tr", "com.ua",
    "com.cn", "co.kr", "co.in", "com.mx", "gov.ru", "org.ru", "net.ru", "com.ru", "edu.ru",
    "ac.ru", "pp.ua", "in.ua",
}

ANCHOR_RE = re.compile(
    r"^(?:https?://)?([a-z0-9\-._~Ѐ-ӿ]+\.[a-zЀ-ӿ]{2,})(?:[/?#:]|$)", re.IGNORECASE
)
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

HOST_MAX = 253
LABELS_MAX = 40
BRAND_CORE_MIN = 3
BRAND_GLUED_MIN = 6
ANCHOR_MAX = 300
CACHE_TTL = 300.0
CACHE_MAX = 200

LURE_WORDS = {
    "shop", "store", "market", "magazin", "pay", "payment", "bank", "banking", "online",
    "official", "support", "help", "service", "servis", "login", "signin", "secure", "security",
    "verify", "verification", "account", "cabinet", "kabinet", "wallet", "claim", "gift", "bonus",
    "promo", "prize", "win", "winner", "refund", "update", "confirm", "center", "centre", "centr",
    "auth", "access", "recovery", "restore", "unlock", "oplata", "dostavka", "vyplata", "viplata",
    "vozvrat", "podarok", "vhod", "lk", "id", "app", "apk", "download", "mobile", "invest", "bot",
    "premium", "vip", "free",
}

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
_RISK_ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}


class Verdict:
    def __init__(self, original):
        self.original = original
        self.cleaned = original
        self.flags = []
        self.removed_params = []
        self.is_shortener = False
        self.host = ""
        self.display_host = ""
        self.source = None

    def add(self, level, text):
        self.flags.append((level, text))

    def clone(self):
        c = Verdict(self.original)
        c.cleaned = self.cleaned
        c.flags = list(self.flags)
        c.removed_params = list(self.removed_params)
        c.is_shortener = self.is_shortener
        c.host = self.host
        c.display_host = self.display_host
        c.source = self.source
        return c

    @property
    def risk(self):
        if not self.flags:
            return INFO
        return max((lvl for lvl, _ in self.flags), key=lambda l: _RISK_ORDER[l])

    @property
    def suspicious(self):
        return _RISK_ORDER[self.risk] >= _RISK_ORDER[MEDIUM]


def levenshtein(left, right):
    if left == right:
        return 0
    if not left or not right:
        return max(len(left), len(right))
    before = None
    prev = list(range(len(right) + 1))
    for i, ca in enumerate(left, 1):
        cur = [i]
        for j, cb in enumerate(right, 1):
            step = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == right[j - 2] and left[i - 2] == cb:
                step = min(step, before[j - 2] + 1)
            cur.append(step)
        before, prev = prev, cur
    return prev[-1]


def letter_mask(text):
    mask = 0
    for ch in text:
        mask |= 1 << (ord(ch) & 63)
    return mask


BRAND_INDEX = [(b, len(b), letter_mask(b)) for b in BRAND_LIST]


def label_tokens(label):
    tokens = set()
    for part in re.split(r"[^a-z0-9]+", label):
        if not part:
            continue
        tokens.add(part)
        for piece in re.findall(r"[a-z]+", part):
            tokens.add(piece)
    return tokens


def glued_to_lure(label, core):
    rest = label.replace(core, "", 1).strip("-_.0123456789")
    return rest in LURE_WORDS


def brand_with_extra(reg):
    if reg in BRANDS:
        return None
    label = reg.split(".")[0]
    tokens = label_tokens(label)
    for brand in BRAND_LIST:
        core = brand.split(".")[0]
        if len(core) < BRAND_CORE_MIN or core in GENERIC_LABELS:
            continue
        if label == core:
            return None
        if core in tokens:
            return core
        if len(core) >= BRAND_GLUED_MIN and core in label and glued_to_lure(label, core):
            return core
    return None


def registrable(host):
    parts = host.split(".")
    if len(parts) < 2:
        return host
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def decode_idna(host):
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def scripts_of(text):
    found = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW"):
            if name.startswith(script):
                found.add(script)
                break
    return found


def to_latin_lookalike(host):
    return "".join(LOOKALIKE_LETTERS.get(ch, ch) for ch in host.lower())


def slice_utf16(text, offset, length):
    if not length:
        return ""
    try:
        units = text.encode("utf-16-le")
        return units[offset * 2:(offset + length) * 2].decode("utf-16-le", "ignore")
    except Exception:
        return text[offset:offset + length]


def anchor_domain(text):
    if not text:
        return ""
    candidate = text.strip().strip("<>()[]«»\"'").rstrip(".,;:!?")
    match = ANCHOR_RE.match(candidate)
    if not match:
        return ""
    host = decode_idna(match.group(1).lower().rstrip("."))
    if "." not in host:
        return ""
    return registrable(host)


def normalize_domain(text):
    value = str(text).strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if "@" in value:
        value = value.split("@")[-1]
    value = value.split(":")[0].strip().strip(".").lstrip("*.")
    if not value or " " in value:
        return ""
    if not re.fullmatch(r"[a-z0-9\-._~Ѐ-ӿ]+\.(?:[a-zЀ-ӿ]{2,}|xn--[a-z0-9\-]{2,})", value):
        return ""
    return decode_idna(value)


def is_private_ip(host):
    try:
        first, second = (int(p) for p in host.split(".")[:2])
    except (TypeError, ValueError):
        return False
    return (first in (10, 127) or (first == 192 and second == 168)
            or (first == 172 and 16 <= second <= 31) or (first == 169 and second == 254))


def analyze(url, aggressive=False, whitelist=(), anchor=None):
    verdict = Verdict(url)
    try:
        raw = urlsplit(url)
    except Exception:
        verdict.add(HIGH, t("f_unparsable"))
        return verdict

    scheme = (raw.scheme or "").lower()
    if scheme in DANGEROUS_SCHEMES:
        verdict.add(HIGH, t("f_scheme", scheme))
        return verdict
    if scheme not in ("", "http", "https", "ftp"):
        return verdict

    probe = url if "://" in url else "http://" + url
    try:
        parts = urlsplit(probe)
        host = (parts.hostname or "").lower()
    except Exception:
        verdict.add(HIGH, t("f_unparsable"))
        return verdict

    verdict.host = host
    verdict.display_host = decode_idna(host)

    if not host:
        verdict.add(MEDIUM, t("f_nodomain"))
        return verdict

    if len(host) > HOST_MAX or host.count(".") > LABELS_MAX:
        verdict.add(HIGH, t("f_unparsable"))
        verdict.cleaned, verdict.removed_params = clean_url(url, aggressive)
        return verdict

    reg = registrable(host)
    shown = verdict.display_host
    shown_reg = reg if shown == host else registrable(shown)
    if reg in whitelist or host in whitelist or shown_reg in whitelist or shown in whitelist:
        verdict.cleaned, verdict.removed_params = clean_url(url, aggressive)
        return verdict

    if parts.username or "@" in parts.netloc:
        verdict.add(HIGH, t("f_userinfo", host))

    if shown != host:
        verdict.add(LOW, t("f_punycode", shown))
    scripts = scripts_of(shown)
    if len(scripts) > 1:
        names = sorted(t("scripts_" + s) for s in scripts)
        verdict.add(HIGH, t("f_mixed", ", ".join(names)))

    defused = to_latin_lookalike(shown)
    defused_reg = registrable(defused)
    if defused_reg != reg and defused_reg in BRANDS:
        verdict.add(HIGH, t("f_lookalike", defused_reg))
    elif defused_reg not in BRANDS:
        own_length = len(defused_reg)
        own_mask = letter_mask(defused_reg)
        for brand, length, mask in BRAND_INDEX:
            if abs(own_length - length) > 2:
                continue
            limit = 1 if length < 10 else 2
            if bin(own_mask ^ mask).count("1") > limit:
                continue
            dist = levenshtein(defused_reg, brand)
            if 1 <= dist <= limit:
                verdict.add(HIGH, t("f_typo", brand, dist, plural_ru(t("unit_char"), dist)))
                break

    if reg not in BRANDS:
        labels = shown.split(".")
        for brand in BRAND_LIST:
            head = brand.split(".")[0]
            if len(head) < 5 or head in GENERIC_LABELS:
                continue
            if head in labels[:-2]:
                verdict.add(HIGH, t("f_subdomain", head, reg))
                break

    shown_as = anchor_domain(anchor)
    if shown_as and shown_as != reg and shown_as != registrable(shown):
        verdict.add(HIGH, t("f_anchor", shown_as, reg))

    if IP_RE.fullmatch(host):
        private = is_private_ip(host)
        verdict.add(LOW if private else MEDIUM, t("f_ip_local") if private else t("f_ip"))
    try:
        port = parts.port
    except ValueError:
        port = None
        verdict.add(MEDIUM, t("f_badport"))
    if port and port not in (80, 443):
        verdict.add(LOW, t("f_port", port))

    stolen = brand_with_extra(reg)
    if stolen:
        verdict.add(HIGH, t("f_brand_extra", stolen))

    if host.count(".") >= 4:
        verdict.add(LOW, t("f_deep"))
    if len(host) > 40:
        verdict.add(LOW, t("f_long"))

    lowered = (host + parts.path).lower()
    hits = [w for w in BAIT_WORDS if w in lowered]
    if hits and reg not in BRANDS:
        verdict.add(MEDIUM if verdict.flags else LOW, t("f_bait", ", ".join(hits[:3])))

    path_low = parts.path.lower()
    for ext in DANGEROUS_EXT:
        if path_low.endswith(ext):
            verdict.add(HIGH, t("f_exec", ext))
            break

    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLD:
        verdict.add(LOW, t("f_tld", tld))

    if reg in SHORTENERS or host in SHORTENERS:
        verdict.is_shortener = True
        verdict.add(INFO, t("f_short"))

    verdict.cleaned, verdict.removed_params = clean_url(url, aggressive)
    return verdict


# ======================================================================
# Хук открытия ссылок
# ======================================================================
class _OpenUrlHook(MethodHook):
    plugin = None

    def before_hooked_method(self, param):
        try:
            self.plugin.on_open_url(param)
        except Exception as e:
            log("PrivacyCleaner: open hook error: %s" % e)


class _MediaHook(MethodHook):
    plugin = None

    def before_hooked_method(self, param):
        try:
            self.plugin.sanitize_args(param.args)
        except Exception as e:
            self.plugin.log("media hook error: %s" % e)


# ======================================================================
# Устройство записи кружка (Round Client Detector 3.3.1, @netconfiger)
# ======================================================================
ROUND_NON_TARGET_TYPES = {0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}


class ThreadSafeLRUCache:
    def __init__(self, max_size: int = 1000):
        self._max_size = max_size
        self._cache: collections.OrderedDict = collections.OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def put(self, key: Any, value: Any):
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self):
        with self._lock:
            self._cache.clear()


def _safe_get(map_obj: Any, key: str, default: Any = None) -> Any:
    if map_obj is None:
        return default
    try:
        if isinstance(map_obj, dict):
            return map_obj.get(key, default)
        val = map_obj.get(key)
        return val if val is not None else default
    except Exception:
        return default


def analyze_round_video_data(
    file_name: Optional[str],
    file_path: Optional[str] = None,
    raw_bytes: Optional[bytes] = None,
) -> Dict[str, Any]:
    details = []
    platform = None
    reasons = []

    if file_name:
        details.append(f"Имя файла: '{file_name}'")
        fn_lower = file_name.lower().strip()
        if fn_lower == "video.mp4":
            platform = "iOS (Apple iPhone/iPad)"
            reasons.append("Имя 'video.mp4' стандартно для записи на iOS.")
        elif fn_lower.startswith("round_") and fn_lower.endswith(".mp4"):
            platform = "Telegram Desktop (Windows / Linux / macOS)"
            reasons.append("Шаблон имени 'round_YYYY-MM-DD_HH-MM-SS.mp4' создается Telegram Desktop.")
        elif "desktop" in fn_lower or fn_lower.startswith("round"):
            platform = "Telegram Desktop (ПК)"
            reasons.append("Префикс файла указывает на версию для компьютера.")
    else:
        details.append("Имя файла: отсутствует (стандартно для Android)")

    if not raw_bytes and file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(4096)
        except Exception:
            pass

    if raw_bytes and len(raw_bytes) >= 12:
        if raw_bytes[4:8] == b"ftyp":
            major_brand = raw_bytes[8:12].decode("latin1", errors="ignore")
            details.append(f"Метка контейнера MP4: '{major_brand}'")

            if (b"Core Media" in raw_bytes or b"Apple" in raw_bytes or b"com.apple" in raw_bytes
                    or major_brand in ("qt  ", "CAEP")):
                if not platform or "iOS" not in platform:
                    platform = "iOS (Apple iPhone/iPad)"
                reasons.append("Энкодер видео: Apple CoreMedia / QuickTime.")
            elif (b"libstagefright" in raw_bytes or b"c2.android" in raw_bytes
                  or b"OMX.google" in raw_bytes or b"Android" in raw_bytes):
                if not platform:
                    platform = "Android"
                reasons.append("Энкодер видео: Android MediaCodec / Stagefright.")
            elif b"Lavf" in raw_bytes or b"Lavc" in raw_bytes:
                if not platform:
                    platform = "Telegram Desktop (ПК)"
                reasons.append("Энкодер видео: FFmpeg (версия для компьютера).")

    if not platform:
        if file_name is None or file_name == "":
            platform = "Android"
            reasons.append("Отсутствие имени файла в метаданных Telegram.")
        else:
            platform = "Сторонний клиент / Бот"
            reasons.append("Нестандартный формат видеосообщения.")

    if "iOS" in platform:
        desc = "Кружок записан на iPhone или iPad."
    elif "Desktop" in platform or "ПК" in platform:
        desc = "Кружок записан на компьютере через Telegram Desktop."
    elif "Android" in platform:
        desc = "Кружок записан на телефоне или планшете с Android."
    else:
        desc = "Кружок отправлен через бота или неофициальный клиент."

    return {"success": True, "platform": platform, "description": desc,
            "reasons": reasons, "details": details}


class _RoundCellMeasureTimeHook(MethodHook):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def after_hooked_method(self, param: Any):
        try:
            if not self.plugin._rc_is_enabled():
                return

            cell = getattr(param, "thisObject", None)
            if not cell:
                return

            message = (param.args[0] if (param.args and len(param.args) > 0 and param.args[0] is not None)
                       else self.plugin._get_cell_message(cell))
            if not message:
                return

            # Быстрый выход для не-кружков
            msg_type = getattr(message, "type", None)
            if msg_type == 5:
                pass
            elif msg_type in ROUND_NON_TARGET_TYPES:
                return
            else:
                is_round_fn = getattr(message, "isRoundVideo", None)
                if callable(is_round_fn):
                    try:
                        if not is_round_fn():
                            return
                    except Exception:
                        return
                elif hasattr(message, "messageOwner") and hasattr(message.messageOwner, "media"):
                    doc = getattr(message.messageOwner.media, "document", None)
                    attrs = getattr(doc, "attributes", None)
                    found_round = False
                    if attrs and hasattr(attrs, "size"):
                        for i in range(attrs.size()):
                            if getattr(attrs.get(i), "round_message", False):
                                found_round = True
                                break
                    if not found_round:
                        return
                else:
                    return

            raw_id = getattr(message, "id", None)
            if isinstance(raw_id, int):
                msg_id = raw_id
            elif raw_id is None:
                try:
                    msg_id = int(message.getId())
                except Exception:
                    msg_id = 0
            elif callable(raw_id):
                msg_id = int(raw_id())
            else:
                msg_id = int(raw_id or 0)
            if not msg_id:
                return

            dialog_id = getattr(message, "dialog_id", 0)
            if not dialog_id:
                try:
                    dialog_id = message.getDialogId()
                except Exception:
                    dialog_id = 0

            owner = getattr(message, "messageOwner", message)
            edit_date = getattr(owner, "edit_date", 0) if owner else 0
            cache_key = (dialog_id, msg_id, edit_date)

            # Кешируем только сам тег. Ширину и layout всегда считаем заново от текущей
            # базовой ширины: Theme.chat_timePaint пересоздаётся при каждом входе в чат,
            # и закешированные пиксели обрезали бы метку.
            tag = self.plugin.get_round_tag_fast(message, cache_key)
            if not tag:
                return

            paint = self.plugin.get_time_paint()
            if not paint:
                return

            if owner:
                existing_author = getattr(owner, "post_author", None)
                if existing_author:
                    if tag not in existing_author:
                        owner.post_author = f"{existing_author} · {tag}"
                else:
                    owner.post_author = tag

            cur_time = self.plugin._get_cell_time_string(cell)
            if not cur_time:
                return

            cur_time_str = str(cur_time)
            if tag in cur_time_str:
                return

            new_time_str = f"{cur_time_str} · {tag}"
            old_w = int(paint.measureText(cur_time_str))
            new_w = int(paint.measureText(new_time_str))
            delta = new_w - old_w
            new_tw = self.plugin._get_cell_time_width(cell) + delta
            new_ttw = self.plugin._get_cell_time_text_width(cell) + delta

            StaticLayout = self.plugin.get_static_layout_class()
            Alignment = self.plugin.get_alignment_class()
            if StaticLayout and Alignment:
                align_norm = getattr(Alignment, "ALIGN_NORMAL", None)
                if align_norm:
                    layout = StaticLayout(new_time_str, paint, new_ttw + 100, align_norm, 1.0, 0.0, False)
                    self.plugin._set_cell_fields(cell, new_time_str, new_tw, new_ttw, layout)
        except Exception:
            pass


# ======================================================================
# Плагин
# ======================================================================
class PrivacyCleaner(BasePlugin):
    APPROVAL_WINDOW = 10.0
    UPDATE_NAMES = ("TL_updateNewMessage", "TL_updateNewChannelMessage",
                    "TL_updateShortMessage", "TL_updateShortChatMessage",
                    "TL_updates", "TL_updatesCombined")

    def on_plugin_load(self):
        self.cache_dir = None
        self._bypass = {}
        self._cache = {}
        self._anchors = {}
        self._sources = {}
        self._hooks = []
        self._menu_items = []
        self._browser_cls = None

        self._step("cache", self._init_cache)
        self._step("sendHook", self.add_on_send_message_hook)
        self._step("mediaHooks", self._install_media_hooks)
        self._step("openUrl", self._install_open_url_hook)
        self._step("updates", self._install_update_hook)
        self._step("roundBadge", self._install_round_hook)
        self._step("menu", self._register_menu)
        self.log("Privacy Cleaner %s loaded" % __version__)

    def on_plugin_unload(self):
        for h in self._hooks:
            try:
                self.unhook_method(h)
            except Exception:
                pass
        self._hooks = []
        for item in self._menu_items:
            try:
                self.remove_menu_item(item)
            except Exception:
                pass
        self._menu_items = []
        try:
            self._tag_cache.clear()
            self._field_cache.clear()
        except Exception:
            pass

    def _step(self, name, action):
        try:
            action()
            return True
        except Exception as e:
            self.log("load step %s failed: %s" % (name, e))
            return False

    # ---------------------------------------------------------- настройки
    def _on(self, key, default=True):
        return bool(self.get_setting(key, default))

    def create_settings(self):
        if not HAS_SETTINGS:
            return []
        return [
            Header(text=t("hdr_media")),
            Switch(key="clean_photos", text=t("sw_photos"), default=True, subtext=t("sw_photos_sub")),
            Switch(key="clean_videos", text=t("sw_videos"), default=True, subtext=t("sw_videos_sub")),
            Switch(key="randomize_names", text=t("sw_names"), default=True, subtext=t("sw_names_sub")),

            Header(text=t("hdr_links")),
            Switch(key="clean_urls_out", text=t("sw_clean_out"), default=True, subtext=t("sw_clean_out_sub")),
            Switch(key="check_enabled", text=t("sw_check"), default=True, subtext=t("sw_check_sub")),
            Switch(key="show_always", text=t("sw_always"), default=False, subtext=t("sw_always_sub")),
            Switch(key="clean_on_open", text=t("sw_clean_open"), default=True, subtext=t("sw_clean_open_sub")),
            Switch(key="aggressive", text=t("sw_aggr"), default=False, subtext=t("sw_aggr_sub")),

            Header(text=t("hdr_exc")),
            Input(key="whitelist", text=t("in_whitelist"),
                  default=self.get_setting("whitelist", "") or "",
                  subtext=t("in_whitelist_sub")),

            Header(text="Кружки"),
            Switch(key="time_badge_enabled", text="Показывать устройство у времени кружка", default=True,
                   subtext="Короткая метка (iOS, Android, Win) рядом со временем"),
            Switch(key="show_technical_details", text="Технические подробности в меню", default=True,
                   subtext="Имя файла и метаданные при проверке кружка через меню"),

            Divider(),
            Text(text=t("note_title"), subtext=t("note_text")),
        ]

    def _whitelist_list(self):
        raw = self.get_setting("whitelist", "") or ""
        seen = []
        for part in re.split(r"[,\s]+", str(raw)):
            item = part.strip().lower().lstrip("*.")
            if item and item not in seen:
                seen.append(item)
        return seen

    def _whitelist(self):
        return set(self._whitelist_list())

    def _aggressive(self):
        return self._on("aggressive", False)

    # ---------------------------------------------------------- кэш файлов
    def _init_cache(self):
        ctx = ApplicationLoader.applicationContext
        # Telegram отказывается отправлять файлы из внутренней папки приложения
        # ("файл не поддерживается"), поэтому копии кладём во внешний кэш.
        base = None
        try:
            ext_dir = ctx.getExternalCacheDir()
            if ext_dir is not None:
                base = str(ext_dir.getAbsolutePath())
        except Exception:
            base = None
        if not base:
            base = str(ctx.getCacheDir().getAbsolutePath())
        self.cache_dir = os.path.join(base, "privacy_clean")
        os.makedirs(self.cache_dir, exist_ok=True)
        now = time.time()
        for name in os.listdir(self.cache_dir):
            p = os.path.join(self.cache_dir, name)
            if now - os.path.getmtime(p) > 24 * 3600:
                shutil.rmtree(p, ignore_errors=True)

    def _out_path(self, src, ext):
        d = os.path.join(self.cache_dir, uuid.uuid4().hex)
        os.makedirs(d, exist_ok=True)
        if self._on("randomize_names", True):
            name = uuid.uuid4().hex[:12] + ext
        else:
            name = os.path.splitext(os.path.basename(src))[0] + ext
        return os.path.join(d, name)

    # ---------------------------------------------------------- исходящий текст
    def on_send_message_hook(self, account, params):
        if not self._on("clean_urls_out", True):
            return HookResult()
        text = _as_str(getattr(params, "message", None))
        if not text or ("://" not in text and "www." not in text.lower()):
            return HookResult()
        try:
            entities = getattr(params, "entities", None)
            if entities is not None and entities.size() > 0:
                return HookResult()  # форматирование: при замене сдвинулись бы offset'ы
        except Exception:
            pass

        aggressive = self._aggressive()
        removed_total = [0]

        def repl(match):
            cleaned, removed = clean_url(match.group(0), aggressive)
            removed_total[0] += len(removed)
            return cleaned

        new_text = URL_RE.sub(repl, text)
        if not removed_total[0]:
            return HookResult()
        params.message = new_text
        return HookResult(strategy=HookStrategy.MODIFY, params=params)

    # ---------------------------------------------------------- медиа
    def _install_media_hooks(self):
        helper = find_class("org.telegram.messenger.SendMessagesHelper")
        hook = _MediaHook()
        hook.plugin = self
        for name in (
            "prepareSendingMedia", "prepareSendingDocuments", "prepareSendingDocument",
            "prepareSendingDocumentInternal", "prepareSendingPhoto", "prepareSendingVideo",
        ):
            try:
                self.hook_all_methods(helper, name, hook)
                self.log("hooked %s" % name)
            except Exception as e:
                self.log("cannot hook %s: %s" % (name, e))

    def sanitize_args(self, args):
        for i in range(len(args)):
            a = args[i]
            s = _as_str(a)
            if s is not None:
                new = self._safe_process(s)
                if new:
                    args[i] = new
                continue
            if a is None:
                continue
            try:
                if hasattr(a, "size") and hasattr(a, "get") and hasattr(a, "set"):
                    self._sanitize_list(a)
                    continue
            except Exception:
                pass
            self._fix_video_info(a, None, None)

    def _sanitize_list(self, lst):
        for j in range(lst.size()):
            item = lst.get(j)
            s = _as_str(item)
            if s is not None:
                new = self._safe_process(s)
                if new:
                    lst.set(j, new)
                continue
            try:
                old = _as_str(item.path)
            except Exception:
                continue
            new = self._safe_process(old)
            if new:
                item.path = new
                try:
                    self._fix_video_info(item.videoEditedInfo, old, new)
                except Exception:
                    pass

    def _fix_video_info(self, vei, old, new):
        try:
            if vei is None:
                return
            cur = _as_str(vei.originalPath)
            if cur is None:
                return
            if old is not None and cur == old:
                vei.originalPath = new
            elif old is None:
                repl = self._safe_process(cur)
                if repl:
                    vei.originalPath = repl
        except Exception:
            pass

    def _safe_process(self, path):
        try:
            return self._process_path(path)
        except Exception as e:
            self.log("clean failed for %s: %s" % (path, e))
            self._toast("Privacy Cleaner: не удалось очистить файл, он отправлен как есть")
            return None

    def _process_path(self, path):
        if not path or not self.cache_dir or path.startswith(self.cache_dir):
            return None
        if not os.path.isfile(path):
            return None
        ext = os.path.splitext(path)[1].lower()
        out = None
        if self._on("clean_photos", True) and ext in PHOTO_EXT:
            out = self._clean_photo(path, ext)
        elif self._on("clean_videos", True) and ext in VIDEO_EXT:
            out = self._clean_video(path, ext)
        if out is None:
            return None
        if not os.path.isfile(out) or os.path.getsize(out) == 0:
            raise ValueError("empty output file")
        try:
            os.chmod(out, 0o644)
        except Exception:
            pass
        self.log("cleaned: %s -> %s" % (path, out))
        return out

    def _clean_photo(self, path, ext):
        bmp = BitmapFactory.decodeFile(path)
        if bmp is None:
            raise ValueError("decode failed")
        orient = 1
        if ext in (".jpg", ".jpeg"):
            try:
                orient = ExifInterface(path).getAttributeInt("Orientation", 1)
            except Exception:
                orient = 1
        m = Matrix()
        if orient == 2:
            m.setScale(-1.0, 1.0)
        elif orient == 3:
            m.setRotate(180.0)
        elif orient == 4:
            m.setRotate(180.0)
            m.postScale(-1.0, 1.0)
        elif orient == 5:
            m.setRotate(90.0)
            m.postScale(-1.0, 1.0)
        elif orient == 6:
            m.setRotate(90.0)
        elif orient == 7:
            m.setRotate(-90.0)
            m.postScale(-1.0, 1.0)
        elif orient == 8:
            m.setRotate(-90.0)
        if orient in (2, 3, 4, 5, 6, 7, 8):
            rotated = Bitmap.createBitmap(bmp, 0, 0, bmp.getWidth(), bmp.getHeight(), m, True)
            if rotated is not bmp:
                bmp.recycle()
            bmp = rotated
        is_png = ext == ".png"
        out = self._out_path(path, ".png" if is_png else ".jpg")
        fos = FileOutputStream(out)
        try:
            ok = bmp.compress(CompressFormat.PNG if is_png else CompressFormat.JPEG,
                              100 if is_png else JPEG_QUALITY, fos)
        finally:
            fos.close()
            bmp.recycle()
        if not ok:
            raise ValueError("compress failed")
        return out

    def _clean_video(self, path, ext):
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb > MAX_VIDEO_MB:
            self._toast("Privacy Cleaner: видео %d МБ слишком большое, метаданные не очищены" % int(size_mb))
            return None
        out = self._out_path(path, ext)
        shutil.copyfile(path, out)
        scrub_mp4_inplace(out)
        return out

    # ---------------------------------------------------------- меню
    def _register_menu(self):
        self._menu_items.append(self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.MESSAGE_CONTEXT_MENU, text=t("menu_check"), icon="msg_info",
            subtext="Privacy Cleaner", priority=5, on_click=self.on_menu_check)))
        self._menu_items.append(self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.MESSAGE_CONTEXT_MENU, text=t("menu_copy"), icon="msg_copy",
            priority=4, on_click=self.on_menu_copy)))
        self._menu_items.append(self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.MESSAGE_CONTEXT_MENU, text="🎥 Откуда записан кружок",
            icon="msg_round", subtext="Узнать устройство отправителя", priority=20,
            on_click=self.handle_detect_click)))
        self._menu_items.append(self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.CHAT_ACTION_MENU, text=t("menu_info"), icon="msg_list",
            on_click=self.show_dialog_info)))

    # ---------------------------------------------------------- проверка ссылок: хуки
    def _install_open_url_hook(self):
        handler = _OpenUrlHook()
        handler.plugin = self
        cls = find_class("org.telegram.messenger.browser.Browser")
        if cls is None:
            self.log("Browser not found, link check disabled")
            return
        self._browser_cls = cls
        hooks = self.hook_all_methods(cls, "openUrl", handler)
        if hooks:
            self._hooks.extend(hooks if isinstance(hooks, list) else [hooks])
            self.log("hooked Browser.openUrl")

    def _install_update_hook(self):
        for name in self.UPDATE_NAMES:
            try:
                self.add_hook(name)
            except Exception as e:
                self.log("hook %s failed: %s" % (name, e))

    def on_update_hook(self, update_name, account, update):
        self._consume_update(update)
        return HookResult()

    def on_updates_hook(self, container_name, account, updates):
        try:
            items = getattr(updates, "updates", None)
            if items is None:
                self._consume_update(updates)
                return HookResult()
            for i in range(items.size()):
                self._consume_update(items.get(i))
        except Exception as e:
            self.log("updates parse failed: %s" % e)
        return HookResult()

    def _consume_update(self, update):
        try:
            payload = getattr(update, "message", None)
            if isinstance(payload, str):
                self._index_anchors(payload, getattr(update, "entities", None))
                self._index_source(update, payload)
            elif payload is not None:
                text = getattr(payload, "message", None)
                self._index_anchors(text, getattr(payload, "entities", None))
                self._index_source(payload, text)
        except Exception as e:
            self.log("update parse failed: %s" % e)

    @staticmethod
    def _message_source(message):
        try:
            if getattr(message, "out", False):
                return "trusted"
            peer = getattr(message, "peer_id", None)
            if peer is not None and int(getattr(peer, "channel_id", 0) or 0):
                return "unknown"
            from_id = getattr(message, "from_id", None)
            user_id = int(getattr(message, "user_id", 0) or 0)
            for holder in (from_id, peer):
                if user_id:
                    break
                if holder is None:
                    continue
                user_id = int(getattr(holder, "user_id", 0) or 0)
            if not user_id:
                return "unknown"
            if get_messages_controller is None:
                return None
            user = get_messages_controller().getUser(user_id)
            if user is None:
                return None
            return "trusted" if getattr(user, "contact", False) else "unknown"
        except Exception:
            return None

    @staticmethod
    def _fragment_source():
        fragment = get_last_fragment()
        if fragment is None:
            return None
        try:
            if fragment.getCurrentChat() is not None:
                return "unknown"
        except Exception:
            pass
        try:
            user = fragment.getCurrentUser()
        except Exception:
            return None
        if user is None:
            return None
        try:
            return "trusted" if (getattr(user, "self", False) or getattr(user, "contact", False)) else "unknown"
        except Exception:
            return None

    @staticmethod
    def _anchor_urls(message):
        urls = []
        try:
            entities = getattr(message, "entities", None)
            for i in range(entities.size()):
                url = getattr(entities.get(i), "url", None)
                if url:
                    urls.append(str(url))
        except Exception:
            pass
        return urls

    def _index_source(self, message, text):
        source = self._message_source(message)
        if not source:
            return
        found = list(URL_RE.findall(str(text or "")))
        found.extend(self._anchor_urls(message))
        for url in found:
            if len(self._sources) >= ANCHOR_MAX:
                self._sources.clear()
            self._sources[url] = source

    def _index_anchors(self, text, entities):
        if not text or entities is None:
            return
        try:
            total = entities.size()
        except Exception:
            return
        text = str(text)
        for i in range(total):
            try:
                entity = entities.get(i)
                url = getattr(entity, "url", None)
                if not url:
                    continue
                offset = int(getattr(entity, "offset", 0) or 0)
                length = int(getattr(entity, "length", 0) or 0)
                shown = slice_utf16(text, offset, length)
                if shown:
                    if len(self._anchors) >= ANCHOR_MAX:
                        self._anchors.clear()
                    self._anchors[str(url)] = shown
            except Exception:
                continue

    def _cached_analyze(self, url, anchor=None):
        aggressive = self._aggressive()
        whitelist = self._whitelist()
        signature = (aggressive, tuple(sorted(whitelist)), anchor or "")
        now = time.time()
        hit = self._cache.get(url)
        if hit and hit[0] == signature and now - hit[1] < CACHE_TTL:
            return hit[2].clone()
        verdict = analyze(url, aggressive, whitelist, anchor)
        if len(self._cache) >= CACHE_MAX:
            self._cache.clear()
        self._cache[url] = (signature, now, verdict.clone())
        return verdict

    @staticmethod
    def _find_url_arg(param):
        for i, arg in enumerate(param.args):
            if arg is None:
                continue
            try:
                text = str(arg)
            except Exception:
                continue
            if "://" in text or text.lower().startswith("www."):
                return i, text
        return None, None

    def _is_approved(self, url):
        now = time.monotonic()
        for key, moment in list(self._bypass.items()):
            if now - moment > self.APPROVAL_WINDOW:
                self._bypass.pop(key, None)
        return url in self._bypass

    def on_open_url(self, param):
        if not self._on("check_enabled", True):
            return
        index, url = self._find_url_arg(param)
        if url is None or self._is_approved(url):
            return

        verdict = self._cached_analyze(url, self._anchors.get(url))
        verdict.source = self._sources.get(url) or self._fragment_source()

        if self._on("show_always", False):
            worth_showing = True
        elif verdict.source == "trusted":
            worth_showing = verdict.suspicious
        else:
            worth_showing = bool(verdict.flags)

        if not (worth_showing and self._can_dialog()):
            if self._on("clean_on_open", True) and verdict.cleaned != url:
                if self._replace_url_arg(param.args, index, verdict.cleaned):
                    removed = len(verdict.removed_params)
                    if removed:
                        run_on_ui_thread(lambda: self._toast(t("toast_cleaned", removed)))
            return

        param.setResult(None)
        self._show_verdict(verdict, param.method, list(param.args), index)

    # ---------------------------------------------------------- проверка ссылок: окна
    @staticmethod
    def _can_dialog():
        if AlertDialogBuilder is None:
            return False
        fragment = get_last_fragment()
        try:
            return bool(fragment and fragment.getParentActivity())
        except Exception:
            return False

    @staticmethod
    def _title(verdict):
        if verdict.risk == HIGH:
            return t("title_danger")
        if verdict.risk == MEDIUM:
            return t("title_suspicious")
        return t("title_info")

    def _describe(self, verdict):
        lines = []
        shown = verdict.display_host or verdict.host
        if shown:
            lines.append(t("lbl_domain", shown))
        if verdict.removed_params:
            lines.append(t("lbl_removed", len(verdict.removed_params), ", ".join(verdict.removed_params[:4])))
        if verdict.source == "unknown":
            lines.append(t("src_stranger"))
        elif verdict.source == "trusted":
            lines.append(t("src_trusted"))

        marks = {HIGH: "⛔", MEDIUM: "⚠️", LOW: "•", INFO: "•"}
        problems = sorted(verdict.flags, key=lambda f: -_RISK_ORDER[f[0]])
        if problems:
            lines.append("")
            for level, text in problems:
                lines.append("%s %s" % (marks[level], text))

        target = verdict.cleaned
        lines.append("")
        lines.append(target if len(target) <= 300 else target[:300] + "…")
        return "\n".join(lines)

    def _show_verdict(self, verdict, method, args, index):
        activity = get_last_fragment().getParentActivity()
        target = verdict.cleaned if self._on("clean_on_open", True) else verdict.original

        builder = AlertDialogBuilder(activity)
        builder.set_title(self._title(verdict))
        builder.set_message(self._describe(verdict))

        def do_open(dialog, which):
            dialog.dismiss()
            self._reopen(method, args, index, target)

        def do_trust(dialog, which):
            dialog.dismiss()
            self._confirm_trust(verdict, method, args, index, target)

        if verdict.risk == HIGH:
            builder.set_positive_button(t("btn_cancel"), lambda d, w: d.dismiss())
            builder.set_negative_button(t("btn_open"), do_open)
        else:
            builder.set_positive_button(t("btn_open"), do_open)
            builder.set_negative_button(t("btn_cancel"), lambda d, w: d.dismiss())
            if verdict.host:
                builder.set_neutral_button(t("btn_trust"), do_trust)
        builder.show()

    def _confirm_trust(self, verdict, method, args, index, target):
        domain = registrable(verdict.display_host or verdict.host)
        if not domain or not self._can_dialog():
            return

        def accept(dialog, which):
            dialog.dismiss()
            domains = self._whitelist_list()
            if domain not in domains:
                domains.append(domain)
            self._cache.clear()
            self.set_setting("whitelist", ", ".join(domains), reload_settings=True)
            self._toast(t("toast_trusted", domain))
            self._reopen(method, args, index, target)

        builder = AlertDialogBuilder(get_last_fragment().getParentActivity())
        builder.set_title(t("trust_title"))
        builder.set_message(t("trust_body", domain))
        builder.set_positive_button(t("btn_cancel"), lambda d, w: d.dismiss())
        builder.set_negative_button(t("btn_trust_yes"), accept)
        builder.show()

    # ---------------------------------------------------------- открытие ссылки после проверки
    @staticmethod
    def _replace_url_arg(args, index, url):
        if index is None or not args:
            return False
        current = args[index]
        if isinstance(current, str):
            args[index] = url
            return True
        try:
            uri_cls = find_class("android.net.Uri")
            if uri_cls is not None and getattr(current, "getScheme", None) is not None:
                args[index] = uri_cls.parse(url)
                return True
        except Exception as e:
            log("PrivacyCleaner: uri replace failed: %s" % e)
        return False

    @staticmethod
    def _context_from(args):
        for arg in args or ():
            if isinstance(arg, str) or arg is None:
                continue
            if getattr(arg, "getPackageName", None) is not None:
                return arg
        return None

    def _open_with_browser(self, context, url):
        if self._browser_cls is None or context is None:
            return False
        try:
            self._browser_cls.openUrl(context, url)
            return True
        except Exception as e:
            log("PrivacyCleaner: Browser.openUrl failed: %s" % e)
            return False

    @staticmethod
    def _open_with_intent(context, url):
        if context is None:
            return False
        try:
            intent_cls = find_class("android.content.Intent")
            uri_cls = find_class("android.net.Uri")
            intent = intent_cls(intent_cls.ACTION_VIEW, uri_cls.parse(url))
            intent.addFlags(intent_cls.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
            return True
        except Exception as e:
            log("PrivacyCleaner: intent failed: %s" % e)
            return False

    def _reopen(self, method, args, index, url):
        now = time.monotonic()
        self._bypass[url] = now
        original = None
        if index is not None and args and isinstance(args[index], str):
            original = args[index]
            self._bypass[original] = now

        context = self._context_from(args)
        if self._open_with_browser(context, url):
            return

        if method is not None:
            new_args = list(args or ())
            self._replace_url_arg(new_args, index, url)
            try:
                method.invoke(None, *new_args)
                return
            except Exception as e:
                log("PrivacyCleaner: reopen failed (varargs): %s" % e)
            try:
                method.invoke(None, new_args)
                return
            except Exception as e:
                log("PrivacyCleaner: reopen failed (list): %s" % e)

        if self._open_with_intent(context, url):
            return

        self._bypass.pop(url, None)
        if original:
            self._bypass.pop(original, None)
        self._copy(url)
        self._toast(t("toast_copied"))

    # ---------------------------------------------------------- пункты меню сообщения
    @staticmethod
    def _message_text(message):
        for getter in ("messageText", "caption"):
            try:
                value = getattr(message, getter, None)
                if value:
                    return str(value)
            except Exception:
                pass
        try:
            return str(message.messageOwner.message or "")
        except Exception:
            return ""

    def _collect_urls(self, message):
        text = self._message_text(message)
        try:
            self._index_anchors(text, message.messageOwner.entities)
        except Exception:
            pass
        found = list(URL_RE.findall(text))
        try:
            entities = message.messageOwner.entities
            for i in range(entities.size()):
                url = getattr(entities.get(i), "url", None)
                if url:
                    found.append(str(url))
        except Exception:
            pass
        return list(dict.fromkeys(found))

    def on_menu_check(self, context):
        message = context.get("message")
        if not message:
            return
        urls = self._collect_urls(message)
        if not urls:
            self._toast(t("toast_no_links"))
            return
        if not self._can_dialog():
            self._toast(t("toast_no_dialog"))
            return
        verdicts = [self._cached_analyze(u, self._anchors.get(u)) for u in urls[:5]]
        marks = {HIGH: "⛔", MEDIUM: "⚠️", LOW: "•", INFO: "✓"}
        blocks = ["%s %s\n%s" % (marks[v.risk], v.display_host or v.host or "?", self._describe(v))
                  for v in verdicts]
        builder = AlertDialogBuilder(get_last_fragment().getParentActivity())
        builder.set_title(t("checked_n", len(verdicts)))
        builder.set_message("\n\n".join(blocks))
        builder.set_positive_button(t("btn_ok"), lambda d, w: d.dismiss())
        builder.show()

    def on_menu_copy(self, context):
        message = context.get("message")
        if not message:
            return
        urls = self._collect_urls(message)
        if not urls:
            self._toast(t("toast_no_links"))
            return
        aggressive = self._aggressive()
        cleaned = [clean_url(u, aggressive)[0] for u in urls]
        self._copy("\n".join(cleaned))
        self._toast(t("toast_copied_ok"))

    # ---------------------------------------------------------- сведения о диалоге
    def show_dialog_info(self, context: Dict[str, Any]):
        fragment = get_last_fragment()
        dialog_id = context.get("peer")
        if not dialog_id and fragment is not None and hasattr(fragment, "getDialogId"):
            dialog_id = fragment.getDialogId()
        if not dialog_id or fragment is None:
            self._toast("Не удалось определить диалог")
            return
        run_on_ui_thread(lambda: self._present_dialog_info(fragment, dialog_id))

    @staticmethod
    def _stamp(seconds):
        try:
            return datetime.fromtimestamp(int(seconds)).strftime("%d.%m.%Y %H:%M")
        except Exception:
            return None

    def _dialog_rows(self, dialog_id):
        controller = get_messages_controller()
        rows = [("ID", str(dialog_id))]

        if dialog_id > 0:
            user = controller.getUser(dialog_id)
            if user is None:
                return rows
            rows.insert(0, ("Тип", "Бот" if getattr(user, "bot", False) else "Пользователь"))
            name = " ".join(p for p in (getattr(user, "first_name", ""), getattr(user, "last_name", "")) if p)
            rows.append(("Имя", name or "—"))
            handle = getattr(user, "username", None)
            if handle:
                rows.append(("Юзернейм", "@%s" % handle))
            flags = (("verified", "верифицирован"), ("premium", "Premium"), ("scam", "скам"),
                     ("fake", "фейк"), ("restricted", "ограничен"))
            marks = [label for attr, label in flags if getattr(user, attr, False)]
            if marks:
                rows.append(("Пометки", ", ".join(marks)))
            status = getattr(user, "status", None)
            if status is not None:
                if getattr(status, "expires", 0) > time.time():
                    rows.append(("Статус", "в сети"))
                elif getattr(status, "was_online", 0):
                    rows.append(("Был(а) в сети", self._stamp(status.was_online) or "—"))
        else:
            chat = controller.getChat(-dialog_id)
            if chat is None:
                return rows
            if getattr(chat, "megagroup", False) or getattr(chat, "gigagroup", False):
                kind = "Супергруппа"
            elif getattr(chat, "broadcast", False):
                kind = "Канал"
            else:
                kind = "Группа"
            rows.insert(0, ("Тип", kind))
            rows.append(("Название", str(getattr(chat, "title", "") or "—")))
            handle = getattr(chat, "username", None)
            if handle:
                rows.append(("Юзернейм", "@%s" % handle))
            count = getattr(chat, "participants_count", 0)
            if count:
                rows.append(("Участников", str(count)))
            if getattr(chat, "creator", False):
                rows.append(("Вы", "создатель"))
            if getattr(chat, "left", False):
                rows.append(("Вы", "вышли из чата"))

        dialog = controller.getDialog(dialog_id)
        last = self._stamp(getattr(dialog, "date", 0)) if dialog is not None else None
        if last:
            rows.append(("Последнее сообщение", last))
        return rows

    def _present_dialog_info(self, fragment, dialog_id):
        try:
            text = "\n".join("%s: %s" % row for row in self._dialog_rows(dialog_id))
        except Exception as e:
            self.log("dialog info failed: %s" % e)
            self._toast("Не удалось получить сведения о диалоге")
            return
        activity = fragment.getParentActivity() if hasattr(fragment, "getParentActivity") else None
        if AlertDialogBuilder is None or activity is None:
            self._toast(text)
            return

        def copy_and_close(dialog, which):
            self._copy(text)
            dialog.dismiss()

        builder = AlertDialogBuilder(activity)
        builder.set_title("Сведения о диалоге")
        builder.set_message(text)
        builder.set_positive_button("Копировать", copy_and_close)
        builder.set_negative_button("Закрыть", lambda d, w: d.dismiss())
        builder.show()

    # ---------------------------------------------------------- утилиты
    @staticmethod
    def _copy(text):
        try:
            if copy_to_clipboard is not None:
                copy_to_clipboard(text)
            else:
                find_class("org.telegram.messenger.AndroidUtilities").addToClipboard(text)
        except Exception as e:
            log("PrivacyCleaner: copy failed: %s" % e)

    @staticmethod
    def _toast(text):
        try:
            BulletinHelper.show_info(text, get_last_fragment())
        except Exception:
            log("PrivacyCleaner: %s" % text)

    # ---------------------------------------------------------- устройство записи кружка (@netconfiger)
    def _install_round_hook(self):
        self._tag_cache = ThreadSafeLRUCache(max_size=1000)
        self._field_cache = {}
        self._rc_enabled = bool(self.get_setting("time_badge_enabled", True))
        self._rc_checked = time.monotonic()
        self._theme_cls = find_class("org.telegram.ui.ActionBar.Theme")
        self._cached_paint = getattr(self._theme_cls, "chat_timePaint", None) if self._theme_cls else None
        self._cached_static_layout_cls = find_class("android.text.StaticLayout")
        self._cached_alignment_cls = find_class("android.text.Layout$Alignment")
        cell_cls = find_class("org.telegram.ui.Cells.ChatMessageCell")
        if cell_cls:
            self.hook_all_methods(cell_cls, "measureTime", _RoundCellMeasureTimeHook(self))
            self.log("hooked ChatMessageCell.measureTime")

    def _rc_is_enabled(self):
        # Настройка перечитывается не чаще раза в секунду: хук вызывается на каждую отрисовку.
        now = time.monotonic()
        if now - self._rc_checked > 1.0:
            self._rc_checked = now
            self._rc_enabled = bool(self.get_setting("time_badge_enabled", True))
        return self._rc_enabled

    def _get_cell_fields_map(self, cell: Any) -> Dict[str, Any]:
        cls_key = "default"
        try:
            cls_key = str(cell.getClass().getName())
        except Exception:
            try:
                cls_key = str(type(cell).__name__)
            except Exception:
                pass
        if cls_key in self._field_cache:
            return self._field_cache[cls_key]

        fields_dict: Dict[str, Any] = {}
        try:
            java_cls = cell.getClass()
            for f_name in ("currentTimeString", "timeWidth", "timeTextWidth", "timeLayout", "currentMessageObject"):
                c = java_cls
                while c:
                    try:
                        f = c.getDeclaredField(f_name)
                        if f:
                            f.setAccessible(True)
                            fields_dict[f_name] = f
                            break
                    except Exception:
                        pass
                    try:
                        c = c.getSuperclass()
                    except Exception:
                        break
        except Exception:
            pass
        self._field_cache[cls_key] = fields_dict
        return fields_dict

    def _get_cell_message(self, cell: Any) -> Any:
        f_msg = self._get_cell_fields_map(cell).get("currentMessageObject")
        if f_msg:
            try:
                return f_msg.get(cell)
            except Exception:
                pass
        return get_private_field(cell, "currentMessageObject")

    def _get_cell_time_string(self, cell: Any) -> Any:
        f_str = self._get_cell_fields_map(cell).get("currentTimeString")
        if f_str:
            try:
                return f_str.get(cell)
            except Exception:
                pass
        return get_private_field(cell, "currentTimeString")

    def _get_cell_time_width(self, cell: Any) -> int:
        f_w = self._get_cell_fields_map(cell).get("timeWidth")
        if f_w:
            try:
                return int(f_w.getInt(cell))
            except Exception:
                pass
        return int(get_private_field(cell, "timeWidth") or 0)

    def _get_cell_time_text_width(self, cell: Any) -> int:
        f_tw = self._get_cell_fields_map(cell).get("timeTextWidth")
        if f_tw:
            try:
                return int(f_tw.getInt(cell))
            except Exception:
                pass
        return int(get_private_field(cell, "timeTextWidth") or 0)

    def _set_cell_fields(self, cell: Any, new_str: str, tw: int, ttw: int, layout: Any) -> bool:
        fields = self._get_cell_fields_map(cell)
        f_layout = fields.get("timeLayout")
        if f_layout:
            try:
                f_str = fields.get("currentTimeString")
                if f_str:
                    f_str.set(cell, new_str)
                f_w = fields.get("timeWidth")
                if f_w:
                    f_w.setInt(cell, int(tw))
                f_tw = fields.get("timeTextWidth")
                if f_tw:
                    f_tw.setInt(cell, int(ttw))
                f_layout.set(cell, layout)
                return True
            except Exception:
                pass
        try:
            cell.timeLayout = layout
            cell.timeWidth = int(tw)
            return True
        except Exception:
            set_private_field(cell, "currentTimeString", new_str)
            set_private_field(cell, "timeWidth", int(tw))
            set_private_field(cell, "timeTextWidth", int(ttw))
            set_private_field(cell, "timeLayout", layout)
            return True

    def get_time_paint(self) -> Any:
        # Theme.chat_timePaint пересоздаётся при каждом входе в чат, поэтому читаем его заново.
        if self._theme_cls is None:
            self._theme_cls = find_class("org.telegram.ui.ActionBar.Theme")
        if self._theme_cls is not None:
            try:
                paint = getattr(self._theme_cls, "chat_timePaint", None)
                if paint is not None:
                    self._cached_paint = paint
                    return paint
            except Exception:
                pass
        return self._cached_paint

    def get_static_layout_class(self) -> Any:
        if self._cached_static_layout_cls is None:
            self._cached_static_layout_cls = find_class("android.text.StaticLayout")
        return self._cached_static_layout_cls

    def get_alignment_class(self) -> Any:
        if self._cached_alignment_cls is None:
            self._cached_alignment_cls = find_class("android.text.Layout$Alignment")
        return self._cached_alignment_cls

    def _is_round_video_message(self, message: Any) -> bool:
        if not message:
            return False
        if hasattr(message, "isRoundVideo") and callable(message.isRoundVideo):
            try:
                if message.isRoundVideo():
                    return True
            except Exception:
                pass
        if getattr(message, "type", None) == 5:
            return True
        doc = getattr(message, "getDocument", lambda: None)()
        if not doc and hasattr(message, "messageOwner") and hasattr(message.messageOwner, "media"):
            doc = getattr(message.messageOwner.media, "document", None)
        if doc and hasattr(doc, "attributes"):
            attrs = doc.attributes
            if attrs and hasattr(attrs, "size"):
                for i in range(attrs.size()):
                    if getattr(attrs.get(i), "round_message", False):
                        return True
        return False

    def _extract_document_file_name(self, message: Any) -> Optional[str]:
        doc = getattr(message, "getDocument", lambda: None)()
        if not doc and hasattr(message, "messageOwner") and hasattr(message.messageOwner, "media"):
            doc = getattr(message.messageOwner.media, "document", None)
        if not doc:
            return None
        fn = getattr(doc, "file_name", None)
        if fn:
            return str(fn)
        attrs = getattr(doc, "attributes", None)
        if attrs and hasattr(attrs, "size"):
            for i in range(attrs.size()):
                attr_fn = getattr(attrs.get(i), "file_name", None)
                if attr_fn:
                    return str(attr_fn)
        return None

    def get_round_tag_fast(self, message: Any, cache_key: Optional[Tuple[int, int, int]] = None) -> Optional[str]:
        if cache_key:
            cached_tag = self._tag_cache.get(cache_key)
            if cached_tag is not None:
                return cached_tag
        file_name = self._extract_document_file_name(message)
        if file_name:
            fn_lower = file_name.lower().strip()
            if fn_lower == "video.mp4":
                tag = "iOS"
            elif fn_lower.startswith("round_") or "desktop" in fn_lower:
                tag = "Win"
            else:
                tag = "custom"
        else:
            tag = "Android"
        if cache_key:
            self._tag_cache.put(cache_key, tag)
        return tag

    def _extract_video_file_path(self, message: Any, account: int) -> Optional[str]:
        if not message:
            return None
        owner = getattr(message, "messageOwner", message)
        try:
            from org.telegram.messenger import FileLoader
            fl = FileLoader.getInstance(account)

            file_obj = fl.getPathToMessage(owner)
            if file_obj:
                path = str(file_obj.getAbsolutePath()) if hasattr(file_obj, "getAbsolutePath") else str(file_obj)
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return path

            doc_obj = getattr(message, "getDocument", lambda: None)()
            if not doc_obj and hasattr(owner, "media"):
                doc_obj = getattr(owner.media, "document", None)
            if doc_obj:
                for call_variant in (
                    lambda: fl.getPathToAttach(doc_obj, True),
                    lambda: fl.getPathToAttach(doc_obj, "mp4", True),
                    lambda: fl.getPathToAttach(doc_obj, False),
                ):
                    try:
                        f_d = call_variant()
                        if f_d:
                            p_d = str(f_d.getAbsolutePath()) if hasattr(f_d, "getAbsolutePath") else str(f_d)
                            if os.path.isfile(p_d) and os.path.getsize(p_d) > 0:
                                return p_d
                    except Exception:
                        pass
        except Exception:
            pass
        return None

    def _show_ui(self, context: Any = None, title: str = "", message: str = ""):
        fragment = _safe_get(context, "fragment") if context else None
        if not fragment:
            fragment = get_last_fragment()
        if AlertDialogBuilder and fragment and hasattr(fragment, "getParentActivity"):
            try:
                activity = fragment.getParentActivity()
                if activity:
                    builder = AlertDialogBuilder(activity)
                    builder.set_title(title)
                    builder.set_message(message)
                    builder.set_positive_button(t("btn_ok"), None)
                    builder.show()
                    return
            except Exception:
                pass
        self._toast(message)

    def handle_detect_click(self, context: Any):
        try:
            message = _safe_get(context, "message")
            account = _safe_get(context, "account", 0)

            if not message or not self._is_round_video_message(message):
                self._show_ui(context, "Ошибка", "Выбранное сообщение не является кружком.")
                return

            file_name = self._extract_document_file_name(message)
            file_path = self._extract_video_file_path(message, account)
            analysis = analyze_round_video_data(file_name=file_name, file_path=file_path)

            report = [
                "🎥 Устройство: %s" % analysis["platform"],
                "ℹ️ Описание: %s" % analysis["description"],
            ]
            if analysis.get("reasons"):
                report.append("\n🔍 Признаки:")
                report.extend(" • %s" % r for r in analysis["reasons"])
            if self._on("show_technical_details", True) and analysis.get("details"):
                report.append("\n🔬 Метаданные файла:")
                report.extend(" • %s" % d for d in analysis["details"])
            report.append("\nОпределение приблизительное: оно строится на имени файла и энкодере.")
            self._show_ui(context, "Информация об устройстве", "\n".join(report))
        except Exception as e:
            self.log("detect failed: %s" % e)