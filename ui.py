# -*- coding: utf-8 -*-
# VeriHunt - ui.py

import base64
import json
import re
import uuid as _uuid_mod
from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JComboBox, JCheckBox, JTextArea,
    JScrollPane, JButton, JSplitPane, JList, DefaultListModel, JEditorPane,
    JTabbedPane, BorderFactory, JMenuItem, JPopupMenu, JFileChooser, Timer,
    DefaultListCellRenderer, BoxLayout, SwingUtilities, JTable, ListSelectionModel,
    Scrollable,
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.text.html import HTMLEditorKit, StyleSheet
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font, Dimension
from java.awt.event import (
    MouseAdapter, ActionListener as _ActionListener,
    KeyAdapter as _KeyAdapter, KeyEvent as _KeyEvent,
)
from javax.swing.event import DocumentListener as _DocumentListener
from javax.swing.event import ListSelectionListener as _ListSelectionListener
from javax.swing.event import ChangeListener as _ChangeListener
from java.lang import Thread as _JThread, Runnable as _JRunnable

from burp import IMessageEditorController

from prompt_handler import DEFAULT_USER_PROMPT_TEMPLATE, SYSTEM_PROMPT
from report_generator import _md_to_html as _md2html
from report_generator import (
    build_markdown_report as _build_md_report,
    build_html_report as _build_html_report,
    finding_record_to_markdown as _finding_to_md,
    AgenticBurpIssue as _AgenticBurpIssue,
)
import demo_data as _demo
from api_client import APIClient as _APIClient
from api_client import OAI_COMPAT_PROVIDERS, OAI_COMPAT_KEYS
from api_client import get_usage as _get_usage, reset_usage as _reset_usage
import hunt_engine as _hunt
from javax.swing import UIManager


# ── Theme adaptation (Burp light / dark) ──────────────────────────────────────
# The extension used to hardcode light backgrounds everywhere, so inside Burp's
# dark theme its panes rendered as glaring white blocks. Detect the active theme
# once from the Look & Feel's panel background luminance, then derive readable
# colours for both modes. Kept as a single module-level object so the cell
# renderer (a class-level construct) can reach it without a UI instance.

def _luminance(c):
    try:
        return (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255.0
    except Exception:
        return 1.0


def _detect_dark():
    """Robustly decide whether Burp's Look & Feel is a dark theme. A single key
    (Panel.background) is unreliable across Burp's custom L&Fs — some return null or
    an unexpected colour — so probe several surfaces, then fall back to inferring
    from a foreground/text colour (light text ⇒ dark theme)."""
    for key in ("Panel.background", "control", "List.background",
                "TextArea.background", "TextField.background", "Viewport.background"):
        try:
            c = UIManager.getColor(key)
        except Exception:
            c = None
        if c is not None:
            return _luminance(c) < 0.5
    for key in ("Panel.foreground", "textText", "controlText", "Label.foreground"):
        try:
            c = UIManager.getColor(key)
        except Exception:
            c = None
        if c is not None:
            return _luminance(c) > 0.5   # light text ⇒ dark theme
    return False


class _Theme(object):
    def muted_hex(self):
        return "#9AA0A6" if self.dark else "#666666"

    def __init__(self, dark=None):
        base = UIManager.getColor("Panel.background")
        list_bg = UIManager.getColor("List.background")
        # dark=None → auto-detect; otherwise honour the caller's explicit choice.
        self.dark = _detect_dark() if dark is None else bool(dark)

        if self.dark:
            # Lean on the L&F's own surfaces so we blend into Burp — but ONLY when
            # they are actually dark. If dark was forced while Burp's L&F is light
            # (base/list_bg come back light), fall back to hard dark colours so the
            # panel background matches the dark HTML palette instead of clashing.
            _dk = Color(0x2B2B2B)
            self.list_bg   = list_bg if (list_bg is not None and _luminance(list_bg) < 0.5) else _dk
            self.text      = Color(0xE6E6E6)
            self.muted     = Color(0x9AA0A6)
            self.sel_bg    = Color(0x3D4A66)
            self.sel_fg    = Color(0xFFFFFF)
            self.card_bg   = base if (base is not None and _luminance(base) < 0.5) else _dk
            # Advisory HTML palette
            self.html_bg   = "#2b2b2b"
            self.html_fg   = "#e6e6e6"
            self.html_bold = "#8ab4f8"
            self.html_code = "#d7ba7d"
            # Severity rows: dark tinted bg + light accent fg, vivid stripe kept.
            self.sev = {
                "High":        (Color(0xF44336), Color(0x3A2A2A), Color(0xFF8A80), Font.BOLD),
                "Medium":      (Color(0xFF9800), Color(0x3A3324), Color(0xFFCC80), Font.PLAIN),
                "Low":         (Color(0x2196F3), Color(0x24303A), Color(0x90CAF9), Font.PLAIN),
                "Information": (Color(0x9E9E9E), Color(0x2E3236), Color(0xCFD8DC), Font.PLAIN),
                "ph":          (Color(0xFF6B35), self.list_bg,    Color(0x9AA0A6), Font.ITALIC),
                "fp":          (Color(0x757575), self.list_bg,    Color(0x777777), Font.ITALIC),
                "default":     (Color(0x9E9E9E), self.list_bg,    Color(0xE6E6E6), Font.PLAIN),
            }
        else:
            self.list_bg   = Color(0xFFFFFF)
            self.text      = Color(0x212121)
            self.muted     = Color(0x666666)
            self.sel_bg    = Color(0xE8EAF6)
            self.sel_fg    = Color(0x1A237E)
            self.card_bg   = Color(0xFFFFFF)
            self.html_bg   = "#ffffff"
            self.html_fg   = "#1a1a2e"
            self.html_bold = "#1a1a2e"
            self.html_code = "#333333"
            self.sev = {
                "High":        (Color(0xF44336), Color(0xFFEBEE), Color(0xB71C1C), Font.BOLD),
                "Medium":      (Color(0xFF9800), Color(0xFFF8E1), Color(0xE65100), Font.PLAIN),
                "Low":         (Color(0x2196F3), Color(0xE3F2FD), Color(0x0D47A1), Font.PLAIN),
                "Information": (Color(0x9E9E9E), Color(0xF5F5F5), Color(0x424242), Font.PLAIN),
                "ph":          (Color(0xFF6B35), Color(0xFFFFFF), Color(0xAAAAAA), Font.ITALIC),
                "fp":          (Color(0xBDBDBD), Color(0xFFFFFF), Color(0xAAAAAA), Font.ITALIC),
                "default":     (Color(0x9E9E9E), Color(0xFFFFFF), Color(0x212121), Font.PLAIN),
            }


def _html_escape(s):
    """Escape user text for safe display inside the chat's HTML transcript."""
    if s is None:
        return ""
    return (str(s).replace(u"&", u"&amp;").replace(u"<", u"&lt;")
            .replace(u">", u"&gt;").replace(u"\n", u"<br>"))


_SEV_RANK = {"High": 0, "Medium": 1, "Low": 2, "Information": 3}


def _norm_finding_name(name):
    """Normalize a finding name for near-duplicate detection: drop parenthetical
    acronyms ("SQL Injection (SQLi)" -> "sql injection"), lowercase, collapse
    punctuation. Deliberately keeps a leading "potential" so a Potential finding is
    NOT merged with a confirmed one of the same class."""
    if not name:
        return u""
    n = name.lower()
    n = re.sub(r'\s*\([^)]*\)', u' ', n)     # strip "(SQLi)", "(XSS)" ...
    n = re.sub(r'[^a-z0-9]+', u' ', n).strip()
    return n


def _norm_finding_url(url):
    """Normalize a finding URL for cross-analysis dedup: drop query/fragment and any
    trailing slash, lowercase. Two analyses of the SAME endpoint (differing only by
    query values) collapse to one key, while different paths stay distinct."""
    try:
        s = str(url or u"").strip()
    except Exception:
        return u""
    if not s:
        return u""
    s = s.split(u"#", 1)[0].split(u"?", 1)[0].lower()
    if len(s) > 1 and s.endswith(u"/"):
        s = s[:-1]
    return s


def _names_dup(a, b):
    """True if two finding names denote the same issue: equal after normalization, or
    one's significant tokens are a subset of the other's (catches the model naming the
    same issue slightly differently across runs, e.g. 'Credentialed Wildcard' vs
    'Credentialed Wildcard Origin')."""
    na, nb = _norm_finding_name(a), _norm_finding_name(b)
    if not na or not nb:
        return na == nb
    if na == nb:
        return True
    ta = set(t for t in na.split() if len(t) > 2)
    tb = set(t for t in nb.split() if len(t) > 2)
    if ta and tb and (ta <= tb or tb <= ta):
        return True
    return False


# Generic fallback strings report_generator injects when the model provided no
# dedicated Background/Remediation section. Suppressed in the Advisory so they do
# not sit next to real, detailed content and read as unfinished. Keep in sync with
# report_generator.py's fallbacks.
_GENERIC_ADVISORY_FILLER = frozenset([
    u"Identified by VeriHunt AI analysis.",
    u"Review and remediate the identified vulnerability.",
    u"Review the AI analysis and perform manual verification.",
])


# Built lazily so it reads the L&F after Burp has set its theme.
_THEME = None
_THEME_MODE = "auto"   # "auto" | "light" | "dark" — user override from Settings


def _theme():
    global _THEME
    if _THEME is None:
        if _THEME_MODE == "dark":
            _THEME = _Theme(dark=True)
        elif _THEME_MODE == "light":
            _THEME = _Theme(dark=False)
        else:
            _THEME = _Theme()
    return _THEME


def set_theme_mode(mode):
    """Set the theme override and force a rebuild on next _theme() access."""
    global _THEME_MODE, _THEME
    _THEME_MODE = mode if mode in ("auto", "light", "dark") else "auto"
    _THEME = None


def _apply_html_theme(pane, is_chat=False):
    """(Re)apply the current theme's palette to a JEditorPane advisory/chat view.
    Rebuilds the HTMLEditorKit stylesheet and forces the component background so the
    pane never renders as a glaring white block inside Burp's dark theme."""
    th = _theme()
    kit = HTMLEditorKit()
    css = StyleSheet()
    if is_chat:
        css.addRule("body {{ font-family: SansSerif; font-size: 11pt; margin: 8px; "
                    "background-color: {0}; color: {1}; }}".format(th.html_bg, th.html_fg))
        css.addRule("pre, code {{ font-family: Monospaced; font-size: 10pt; color: {0}; }}".format(th.html_code))
    else:
        css.addRule("body {{ font-family: Arial, sans-serif; font-size: 12pt; margin: 10px; "
                    "background-color: {0}; color: {1}; }}".format(th.html_bg, th.html_fg))
        css.addRule("b    {{ color: {0}; }}".format(th.html_bold))
        css.addRule("pre  {{ font-family: Monospaced; font-size: 11pt; color: {0}; }}".format(th.html_code))
        css.addRule("code {{ font-family: Monospaced; font-size: 11pt; color: {0}; }}".format(th.html_code))
    kit.setStyleSheet(css)
    # Install OUR themed kit LAST. setContentType is a no-op once the pane is
    # already text/html, so it never replaces the stylesheet kit; setEditorKit
    # resets the document, so callers re-render content afterwards.
    pane.setContentType("text/html")
    pane.setEditorKit(kit)
    pane.setBackground(th.card_bg)


# ── Theme-aware button palettes ───────────────────────────────────────────────
# Solid-fill buttons keyed by semantic role. In dark mode the fills are lightened
# a step so they stand out against Burp's dark panels (a #37474F fill on a #2b2b2b
# panel is nearly invisible); in light mode the original saturated colours are kept.
# White text reads on every fill in both themes.
_BTN_FILL_LIGHT = {
    "primary":   0xFF6B35,  # orange  — Save Settings / Export / Send
    "secondary": 0x546E7A,  # slate   — Reset Prompt / Clear
    "neutral":   0x37474F,  # dk slate — Show All
    "danger":    0xC62828,  # red     — Stop
    "purple":    0x6A1B9A,  # purple  — Toggle False Positive
}
_BTN_FILL_DARK = {
    "primary":   0xFF7A45,
    "secondary": 0x607D8B,
    "neutral":   0x546E7A,
    "danger":    0xE53935,
    "purple":    0x9C4DCC,
}


def _btn_colors(role):
    """Return (bg, fg) Colors for a solid-fill button role in the active theme."""
    th = _theme()
    table = _BTN_FILL_DARK if th.dark else _BTN_FILL_LIGHT
    bg = table.get(role, table["secondary"])
    return Color(bg), Color(0xFFFFFF)


def _link_color(kind):
    """Foreground for a text-only (borderless) button. Dark mode uses brighter
    tints so 'Clear'/'Test Connection' don't disappear on dark button chrome."""
    th = _theme()
    if kind == "danger":
        return Color(0xEF5350) if th.dark else Color(0xC62828)
    # accent (links, Test Connection)
    return Color(0x64B5F6) if th.dark else Color(0x1565C0)


# Provider-specific safe Max Tokens defaults, applied when the user switches the
# Active Provider. Groq's free-tier tokens-per-minute limit is easily exceeded by
# a full request/response prompt, so cap the output lower to avoid 429s. Providers
# not listed keep whatever Max Tokens is currently set.
_PROVIDER_SAFE_MAX_TOKENS = {"Groq": 1536}


# ── API key obfuscation (XOR + Base64) ────────────────────────────────────────
# Prevents casual plaintext visibility in Burp's preferences file.
# Not cryptographically secure — for obfuscation only.

_OBF_KEY = "AgenticBurpKey16"  # 16 chars

def _obfuscate(text):
    if not text:
        return ""
    try:
        key = _OBF_KEY
        result = bytearray()
        for i, ch in enumerate(text.encode("utf-8")):
            result.append(ch ^ ord(key[i % len(key)]))
        return base64.b64encode(bytes(result)).decode("ascii")
    except Exception:
        return text

def _deobfuscate(text):
    if not text:
        return ""
    try:
        key = _OBF_KEY
        decoded = bytearray(base64.b64decode(text.encode("ascii")))
        result = bytearray()
        for i, b in enumerate(decoded):
            result.append(b ^ ord(key[i % len(key)]))
        return result.decode("utf-8")
    except Exception:
        return text  # Migration fallback: return plaintext as-is



class UI(object):
    def __init__(self, callbacks, version="dev"):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()   # used by the AI chat for req/resp text
        self.stdout = callbacks.getStdout()
        # Single source of truth: agenticburp.EXTENSION_VERSION is passed in so the
        # banner never drifts from the version Burp shows in the extension list.
        self._version = version

        # All completed findings: display_key -> issue object
        self._all_findings = {}
        # Active placeholder keys (set of strings)
        self._placeholders = set()
        # Filtered view model (what the JList shows)
        self._list_model = DefaultListModel()
        # Current filter string
        self._filter_str = ""

        # Guards provider-switch side effects (e.g. auto Max Tokens) from firing
        # while settings are being loaded into the widgets during construction.
        self._ui_ready = False
        self._api_client = _APIClient()
        self._build()
        self._load_settings()
        self._refresh_model_label()
        self._ui_ready = True

    def _on_provider_change(self):
        """User switched the Active Provider — refresh the model label and apply
        any provider-specific safe default (e.g. lower Max Tokens for Groq's TPM)."""
        self._refresh_model_label()
        if not getattr(self, "_ui_ready", False):
            return
        prov = str(self._provider_combo.getSelectedItem())
        safe = _PROVIDER_SAFE_MAX_TOKENS.get(prov)
        if safe is not None:
            self._max_tokens.setText(str(safe))
            self._log("{0} selected -- Max Tokens set to {1} to stay under the "
                      "tokens-per-minute limit (avoids 429). Adjust if needed.".format(prov, safe))

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[UI] " + msg + "\n")

    # ------------------------------------------------------------------ persist

    def _save_str(self, key, val):
        try:
            self._callbacks.saveExtensionSetting("ab." + key, str(val))
        except Exception:
            pass

    def _load_str(self, key, default=""):
        try:
            v = self._callbacks.loadExtensionSetting("ab." + key)
            return v if v else default
        except Exception:
            return default

    def _save_settings(self, e=None):
        self._save_str("provider",        self._provider_combo.getSelectedItem())
        # API keys stored obfuscated
        self._save_str("anthropic_key",   _obfuscate(self._ant_key.getText()))
        self._save_str("anthropic_model", self._ant_model.getSelectedItem())
        self._save_str("openai_key",      _obfuscate(self._oai_key.getText()))
        self._save_str("openai_model",    self._oai_model.getSelectedItem())
        self._save_str("or_key",          _obfuscate(self._or_key.getText()))
        self._save_str("or_model",        self._or_model.getText())
        self._save_str("gemini_key",      _obfuscate(self._gem_key.getText()))
        self._save_str("gemini_model",    self._gem_model.getSelectedItem())
        self._save_str("ollama_mode",     self._ollama_mode.getSelectedItem())
        self._save_str("ollama_url",      self._ollama_url.getText())
        self._save_str("ollama_key",      _obfuscate(self._ollama_key.getText()))
        self._save_str("ollama_model",    self._ollama_model.getText())
        # OpenAI-compatible providers (DeepSeek, Kimi, Mistral, Groq, xAI, ...)
        for key_prefix, (key_f, model_f, _s, base_f) in self._oai_fields.items():
            self._save_str(key_prefix + "_key",   _obfuscate(key_f.getText()))
            self._save_str(key_prefix + "_model", model_f.getText())
            self._save_str(key_prefix + "_base",  base_f.getText())
        self._save_str("max_tokens",      self._max_tokens.getText())
        self._save_str("max_concurrent",  self._max_concurrent.getText())
        self._save_str("scope_only",      str(self._scope_only_chk.isSelected()))
        self._save_str("self_verify",     str(self._self_verify_chk.isSelected()))
        self._save_str("theme_mode",      str(self._theme_combo.getSelectedItem()))
        self._save_str("prompt",          self._prompt_area.getText())
        self._refresh_model_label()
        self._apply_theme_now()   # re-detect (Auto) / re-skin after any theme change
        self._log("Settings saved.")

    def _load_settings(self):
        try:
            self._provider_combo.setSelectedItem(self._load_str("provider", "Anthropic"))
            # API keys loaded and de-obfuscated
            self._ant_key.setText(_deobfuscate(self._load_str("anthropic_key", "")))
            self._ant_model.setSelectedItem(self._load_str("anthropic_model", "claude-sonnet-5"))
            self._oai_key.setText(_deobfuscate(self._load_str("openai_key", "")))
            self._oai_model.setSelectedItem(self._load_str("openai_model", "gpt-5.1"))
            self._or_key.setText(_deobfuscate(self._load_str("or_key", "")))
            self._or_model.setText(self._load_str("or_model", "anthropic/claude-sonnet-5"))
            self._gem_key.setText(_deobfuscate(self._load_str("gemini_key", "")))
            self._gem_model.setSelectedItem(self._load_str("gemini_model", "gemini-2.5-flash"))
            self._ollama_mode.setSelectedItem(self._load_str("ollama_mode", "Local server"))
            self._ollama_url.setText(self._load_str("ollama_url", "http://localhost:11434"))
            self._ollama_key.setText(_deobfuscate(self._load_str("ollama_key", "")))
            self._ollama_model.setText(self._load_str("ollama_model", "qwen2.5-coder:7b"))
            for key_prefix, (key_f, model_f, _s, base_f) in self._oai_fields.items():
                key_f.setText(_deobfuscate(self._load_str(key_prefix + "_key", "")))
                saved_model = self._load_str(key_prefix + "_model", "")
                if saved_model:
                    model_f.setText(saved_model)
                saved_base = self._load_str(key_prefix + "_base", "")
                if saved_base:
                    base_f.setText(saved_base)
            self._max_tokens.setText(self._load_str("max_tokens", "2048"))
            self._max_concurrent.setText(self._load_str("max_concurrent", "2"))
            self._scope_only_chk.setSelected(
                self._load_str("scope_only", "False").lower() == "true")
            self._self_verify_chk.setSelected(
                self._load_str("self_verify", "True").lower() == "true")
            self._theme_combo.setSelectedItem(self._load_str("theme_mode", "Auto"))
            self._apply_theme_now()
            saved = self._load_str("prompt", "")
            if saved:
                self._prompt_area.setText(saved)
        except Exception as ex:
            self._log("load_settings error: " + str(ex))

    # ------------------------------------------------------------------ build

    def _build(self):
        main = JPanel(BorderLayout())
        main.add(self._build_banner(), BorderLayout.NORTH)
        self._tabs = JTabbedPane()
        self._tabs.setFont(Font("SansSerif", Font.BOLD, 12))
        self._tabs.addTab("  Settings  ", self._build_settings())
        self._tabs.addTab("  Results   ", self._build_results())
        self._tabs.addTab("  AI Hunt   ", self._build_hunt())
        self._tabs.addTab("  Dashboard ", self._build_dashboard())
        self._tabs.addTab("  About     ", self._build_about())
        # Refresh the dashboard whenever it becomes the selected tab.
        class _TabChange(_ChangeListener):
            def __init__(s, ui): s._ui = ui
            def stateChanged(s, e):
                try:
                    if s._ui._tabs.getSelectedComponent() is s._ui._dash_panel:
                        s._ui._refresh_dashboard()
                except Exception:
                    pass
        self._tabs.addChangeListener(_TabChange(self))
        main.add(self._tabs, BorderLayout.CENTER)
        self._panel = main

    def get_panel(self):
        return self._panel

    def _build_banner(self):
        """Branded header: default background, orange title accent."""
        _ORANGE = Color(0xFF6B35)
        _GRAY   = Color(0x777777)

        banner = JPanel(BorderLayout(0, 0))
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 2, 0, _ORANGE),
            BorderFactory.createEmptyBorder(6, 14, 6, 14),
        ))

        left = JPanel(GridLayout(2, 1, 0, 1))

        title = JLabel("VeriHunt")
        title.setFont(Font("SansSerif", Font.BOLD, 18))
        title.setForeground(_ORANGE)

        sub = JLabel(u"AI-Powered Web Security Analysis  \u2022  Multi-Provider  \u2022  v{0}".format(self._version))
        sub.setFont(Font("SansSerif", Font.PLAIN, 11))
        sub.setForeground(_GRAY)

        left.add(title)
        left.add(sub)
        banner.add(left, BorderLayout.WEST)

        badge = JLabel("Evidence-Grounded")
        badge.setFont(Font("SansSerif", Font.BOLD, 10))
        badge.setForeground(_ORANGE)
        badge.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(_ORANGE, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6),
        ))
        right = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0))
        right.add(badge)
        banner.add(right, BorderLayout.EAST)

        return banner

    # -- settings tab ----------------------------------------------------------

    def _build_settings(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Row: provider + max tokens + save
        top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        top.add(JLabel("Provider:"))
        self._provider_combo = JComboBox(
            ["Anthropic", "OpenAI", "OpenRouter", "Gemini", "Ollama"]
            + [p[0] for p in OAI_COMPAT_PROVIDERS])
        self._provider_combo.addActionListener(lambda e: self._on_provider_change())
        top.add(self._provider_combo)
        top.add(JLabel("Max Tokens:"))
        self._max_tokens = JTextField("2048", 6)
        self._max_tokens.setToolTipText(
            "Max tokens in AI response. "
            "Anthropic/OpenAI/Gemini: 4096-8192. "
            "DeepSeek/Kimi/Mistral/Groq/xAI: 4096-8192. "
            "OpenRouter free: <= 2048. "
            "Ollama local: <= 2048.")
        top.add(self._max_tokens)
        top.add(JLabel("Concurrent:"))
        self._max_concurrent = JTextField("2", 3)
        self._max_concurrent.setToolTipText(
            "Max parallel API analyses for bulk scans (1-10). "
            "Anthropic/OpenAI/Gemini: 3-5. "
            "OpenRouter free: 1-2. "
            "Ollama: 1.")
        top.add(self._max_concurrent)
        self._scope_only_chk = JCheckBox("Scope only")
        self._scope_only_chk.setToolTipText(
            "Only analyze requests inside Burp's Target Scope (Target > Scope).")
        top.add(self._scope_only_chk)
        self._self_verify_chk = JCheckBox("Self-verify", True)
        self._self_verify_chk.setToolTipText(
            "Run a second AI pass that checks each finding against the actual HTTP "
            "response: unproven findings are downgraded to 'Potential' and refuted "
            "ones dropped. Reduces false positives -- costs one extra API call per "
            "analysis.")
        top.add(self._self_verify_chk)
        self._memory_chk = JCheckBox("Memory", True)
        self._memory_chk.setToolTipText(
            "Cross-scan memory: remembers false positives + confirmed findings per "
            "host and feeds them to the AI so it skips known FPs on later scans. "
            "Toggle False Positive updates it. Persists across restarts.")
        top.add(self._memory_chk)
        clear_mem = self._skin_btn(JButton("Clear Memory"), "secondary")
        clear_mem.addActionListener(lambda e: self._clear_memory())
        top.add(clear_mem)
        top.add(JLabel("Theme:"))
        self._theme_combo = JComboBox(["Auto", "Light", "Dark"])
        self._theme_combo.setToolTipText(
            "UI theme. Auto follows Burp's Look & Feel; pick Light or Dark to force "
            "it if auto-detection guesses wrong. Applies immediately.")
        self._theme_combo.addActionListener(lambda e: self._apply_theme_now())
        top.add(self._theme_combo)
        save_btn = self._skin_btn(JButton("Save Settings"), "primary")
        save_btn.addActionListener(lambda e: self._save_settings())
        top.add(save_btn)
        reset_btn = self._skin_btn(JButton("Reset Prompt"), "secondary")
        reset_btn.addActionListener(lambda e: self._prompt_area.setText(DEFAULT_USER_PROMPT_TEMPLATE))
        top.add(reset_btn)
        outer.add(top, BorderLayout.NORTH)

        # Provider credential panels via tabbed pane
        cred_tabs = JTabbedPane()
        cred_tabs.addTab("Anthropic",  self._build_anthropic())
        cred_tabs.addTab("OpenAI",     self._build_openai())
        cred_tabs.addTab("OpenRouter", self._build_openrouter())
        cred_tabs.addTab("Gemini",     self._build_gemini())
        cred_tabs.addTab("Ollama",     self._build_ollama())
        # DeepSeek, Kimi (Moonshot), Mistral, Groq, xAI — all OpenAI-compatible,
        # one builder driven by the registry. Fields are stored on self by key
        # prefix so save/load and get_provider_settings can find them generically.
        self._oai_fields = {}   # key_prefix -> (key_field, model_field, status_lbl, base_field)
        for (label, base, default_model, key_url, model_hint) in OAI_COMPAT_PROVIDERS:
            cred_tabs.addTab(label, self._build_oai_compat(
                label, base, default_model, key_url, model_hint))
        cred_tabs.setMinimumSize(Dimension(0, 60))

        # Prompt area
        prompt_panel = JPanel(BorderLayout(4, 4))
        prompt_panel.setBorder(BorderFactory.createTitledBorder("User Prompt Template"))
        prompt_panel.setMinimumSize(Dimension(0, 60))
        self._prompt_area = JTextArea(DEFAULT_USER_PROMPT_TEMPLATE, 12, 60)
        self._prompt_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._prompt_area.setLineWrap(True)
        self._prompt_area.setWrapStyleWord(True)
        prompt_panel.add(JScrollPane(self._prompt_area), BorderLayout.CENTER)
        hint = JLabel("Placeholders: {URL} {METHOD} {REQUEST} {REQUEST_HEADERS} {REQUEST_BODY} {RESPONSE} {RESPONSE_HEADERS} {RESPONSE_BODY} {IS_TRUNCATED_PROMPT}")
        hint.setFont(Font("SansSerif", Font.PLAIN, 10))
        prompt_panel.add(hint, BorderLayout.SOUTH)

        # System prompt (read-only)
        sys_panel = JPanel(BorderLayout(4, 4))
        sys_panel.setBorder(BorderFactory.createTitledBorder("System Prompt (read-only)"))
        sys_panel.setMinimumSize(Dimension(0, 60))
        sys_area = JTextArea(SYSTEM_PROMPT, 5, 60)
        sys_area.setFont(Font("Monospaced", Font.PLAIN, 10))
        sys_area.setLineWrap(True)
        sys_area.setWrapStyleWord(True)
        sys_area.setEditable(False)
        sys_panel.add(JScrollPane(sys_area), BorderLayout.CENTER)

        # VERTICAL split: cred_tabs (top) | prompt (middle) | sys_prompt (bottom)
        # setResizeWeight(x): x fraction of extra space goes to TOP pane on resize
        # setDividerLocation with proportion only works AFTER pack(); use pixel fallback
        split1 = JSplitPane(JSplitPane.VERTICAL_SPLIT, cred_tabs, prompt_panel)
        split1.setResizeWeight(0.25)
        split1.setDividerSize(7)
        split1.setOneTouchExpandable(True)

        split2 = JSplitPane(JSplitPane.VERTICAL_SPLIT, split1, sys_panel)
        split2.setResizeWeight(0.75)
        split2.setDividerSize(7)
        split2.setOneTouchExpandable(True)

        # Defer divider positioning to after layout pass so proportions apply correctly
        def _set_dividers():
            h = split2.getHeight()
            if h > 0:
                split2.setDividerLocation(int(h * 0.72))
                split1.setDividerLocation(int(split2.getTopComponent().getHeight() * 0.28))
        SwingUtilities.invokeLater(_set_dividers)

        outer.add(split2, BorderLayout.CENTER)
        return outer

    def _row_panel(self, *items):
        p = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        for it in items:
            p.add(it)
        return p

    def _clear_key_btn(self, field, pref_key):
        """Return a small 'Clear' button that wipes a JPasswordField and its stored preference."""
        btn = JButton("Clear")
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 11.0))
        self._skin_link_btn(btn, "danger")
        btn.setToolTipText("Clear saved API key")
        ui_ref = self
        class _ClearAction(_ActionListener):
            def actionPerformed(self, _e):
                field.setText("")
                ui_ref._save_str(pref_key, "")
        btn.addActionListener(_ClearAction())
        return btn

    def _conn_status_lbl(self):
        """Return a new 'Not tested' status label."""
        lbl = JLabel(u"● Not tested")
        lbl.setFont(lbl.getFont().deriveFont(Font.PLAIN, 11.0))
        lbl.setForeground(Color(0x999999))
        return lbl

    def _test_conn_btn(self, status_lbl, test_fn):
        """Return a 'Test' button that runs test_fn() in a background thread."""
        btn = JButton("Test Connection")
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 11.0))
        self._skin_link_btn(btn, "accent")
        btn.setToolTipText("Test API connectivity with current credentials")

        class _TestAction(_ActionListener):
            def actionPerformed(self, _e):
                status_lbl.setText(u"● Testing...")
                status_lbl.setForeground(Color(0x777777))
                btn.setEnabled(False)

                class _Worker(_JRunnable):
                    def run(self):
                        try:
                            ok, msg = test_fn()
                        except Exception as ex:
                            ok, msg = False, str(ex)[:100]

                        def _update():
                            btn.setEnabled(True)
                            if ok:
                                status_lbl.setText(u"● " + msg)
                                status_lbl.setForeground(Color(0x2E7D32))
                            else:
                                status_lbl.setText(u"● Failed: " + msg[:80])
                                status_lbl.setForeground(Color(0xC62828))

                        SwingUtilities.invokeLater(_update)

                t = _JThread(_Worker())
                t.setDaemon(True)
                t.start()

        btn.addActionListener(_TestAction())
        return btn

    def _build_anthropic(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._ant_key   = JPasswordField(40)
        self._ant_model = JComboBox(["claude-sonnet-5", "claude-opus-5",
                                     "claude-haiku-4-5-20251001",
                                     "claude-fable-5-1",
                                     "claude-opus-4-8"])
        self._ant_model.setEditable(True)   # let users type any newer/other model id
        self._ant_status = self._conn_status_lbl()
        _client = self._api_client
        _key_f  = self._ant_key
        _mdl_f  = self._ant_model
        def _ant_test():
            return _client.test_anthropic(_key_f.getText(), str(_mdl_f.getSelectedItem()))
        rows.add(self._row_panel(JLabel("API Key:"), self._ant_key, self._clear_key_btn(self._ant_key, "anthropic_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._ant_model))
        rows.add(self._row_panel(self._test_conn_btn(self._ant_status, _ant_test), self._ant_status))
        rows.add(JLabel("Get key: console.anthropic.com  |  See About tab for model details"))
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_openai(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._oai_key   = JPasswordField(40)
        self._oai_model = JComboBox(["gpt-5.1", "gpt-5", "gpt-5-mini", "gpt-5-nano",
                                     "gpt-4.1", "gpt-4o", "o3", "o4-mini"])
        self._oai_model.setEditable(True)   # let users type any newer/other model id
        self._oai_status = self._conn_status_lbl()
        _client = self._api_client
        _key_f  = self._oai_key
        _mdl_f  = self._oai_model
        def _oai_test():
            return _client.test_openai(_key_f.getText(), str(_mdl_f.getSelectedItem()))
        rows.add(self._row_panel(JLabel("API Key:"), self._oai_key, self._clear_key_btn(self._oai_key, "openai_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._oai_model))
        rows.add(self._row_panel(self._test_conn_btn(self._oai_status, _oai_test), self._oai_status))
        rows.add(JLabel("Get key: platform.openai.com  |  See About tab for model details"))
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_openrouter(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._or_key   = JPasswordField(40)
        self._or_model = JTextField("anthropic/claude-sonnet-5", 40)
        self._or_status = self._conn_status_lbl()
        _client = self._api_client
        _key_f  = self._or_key
        _mdl_f  = self._or_model
        def _or_test():
            return _client.test_openrouter(_key_f.getText(), _mdl_f.getText())
        rows.add(self._row_panel(JLabel("API Key:  "), self._or_key, self._clear_key_btn(self._or_key, "or_key")))
        rows.add(self._row_panel(JLabel("Model ID: "), self._or_model))
        rows.add(self._row_panel(self._test_conn_btn(self._or_status, _or_test), self._or_status))

        fast_lbl = JLabel(u"Free: append ':free' to many models, e.g. meta-llama/llama-3.3-70b-instruct:free  \u2022  see openrouter.ai/models")
        fast_lbl.setFont(fast_lbl.getFont().deriveFont(Font.PLAIN, 11.0))
        rows.add(fast_lbl)

        paid_lbl = JLabel(u"Paid: anthropic/claude-sonnet-5  \u2022  openai/gpt-5.1  \u2022  google/gemini-2.5-pro  \u2022  x-ai/grok-4.6")
        paid_lbl.setFont(paid_lbl.getFont().deriveFont(Font.PLAIN, 11.0))
        rows.add(paid_lbl)

        rows.add(JLabel("Get key: openrouter.ai/keys   Browse: openrouter.ai/models"))
        note = JLabel("Note: Free models have token limits. Set Max Tokens <= 2048 to avoid Error 402.")
        note.setForeground(Color(0xE65100))
        note.setFont(note.getFont().deriveFont(Font.ITALIC))
        rows.add(note)
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_gemini(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._gem_key   = JPasswordField(40)
        self._gem_model = JComboBox(["gemini-2.5-flash",
                                     "gemini-2.5-pro",
                                     "gemini-2.5-flash-lite",
                                     "gemini-3-flash-preview",
                                     "gemini-3.1-pro-preview"])
        self._gem_model.setEditable(True)   # let users type any newer/other model id
        self._gem_status = self._conn_status_lbl()
        _client = self._api_client
        _key_f  = self._gem_key
        _mdl_f  = self._gem_model
        def _gem_test():
            return _client.test_gemini(_key_f.getText(), str(_mdl_f.getSelectedItem()))
        rows.add(self._row_panel(JLabel("API Key:"), self._gem_key, self._clear_key_btn(self._gem_key, "gemini_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._gem_model))
        rows.add(self._row_panel(self._test_conn_btn(self._gem_status, _gem_test), self._gem_status))
        rows.add(JLabel("Get key: aistudio.google.com/apikey  |  See About tab for model details"))
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_oai_compat(self, label, base_url, default_model, key_url, model_hint):
        """Generic credential panel for an OpenAI-compatible provider.

        DeepSeek / Kimi / Mistral / Groq / xAI / Z.AI differ only in base URL,
        default model and sign-up link, so they share this one builder. The Base
        URL is editable so enterprise users can point a provider (or the Custom
        entry) at an internal gateway (LiteLLM, Azure OpenAI-compatible, proxy).
        """
        key_prefix = OAI_COMPAT_KEYS.get(label, label.lower())
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))

        key_field   = JPasswordField(40)
        model_field = JTextField(default_model, 40)
        base_field  = JTextField(base_url, 40)
        status_lbl  = self._conn_status_lbl()
        self._oai_fields[key_prefix] = (key_field, model_field, status_lbl, base_field)

        _client = self._api_client
        _label  = label
        _base   = base_url

        def _test():
            return _client.test_openai_compatible(
                _label, base_field.getText().strip() or _base,
                key_field.getText(), model_field.getText())

        rows.add(self._row_panel(JLabel("API Key:  "), key_field,
                                 self._clear_key_btn(key_field, key_prefix + "_key")))
        rows.add(self._row_panel(JLabel("Model ID: "), model_field))
        rows.add(self._row_panel(JLabel("Base URL: "), base_field))
        rows.add(self._row_panel(self._test_conn_btn(status_lbl, _test), status_lbl))

        hint = JLabel("Models: " + model_hint)
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 11.0))
        rows.add(hint)
        ep = "Endpoint (default): {0}".format(base_url) if base_url else \
             "No default endpoint - enter your gateway's Base URL above."
        if key_url:
            ep += "   |   Get key: {0}".format(key_url)
        rows.add(JLabel(ep))

        note = JLabel("OpenAI-compatible. Base URL is editable (internal gateways); "
                      "set Max Tokens per the model's limit.")
        note.setFont(note.getFont().deriveFont(Font.ITALIC, 11.0))
        note.setForeground(Color(0x666666))
        rows.add(note)

        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_ollama(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))

        # Two modes: a self-hosted local server (no auth) or Ollama Cloud
        # (ollama.com, API key required).
        self._ollama_mode  = JComboBox(["Local server", "Ollama Cloud"])
        self._ollama_url   = JTextField("http://localhost:11434", 40)
        self._ollama_model = JTextField("qwen2.5-coder:7b", 40)
        self._ollama_key   = JPasswordField(40)
        self._ollama_status = self._conn_status_lbl()

        _client = self._api_client
        _url_f  = self._ollama_url
        _mdl_f  = self._ollama_model
        _key_f  = self._ollama_key
        _mode_f = self._ollama_mode

        def _is_cloud():
            return str(_mode_f.getSelectedItem()) == "Ollama Cloud"

        def _apply_mode():
            cloud = _is_cloud()
            _key_f.setEnabled(cloud)
            # Swap in the conventional endpoint only if the field still holds the
            # other mode's default (don't clobber a custom URL the user typed).
            cur = _url_f.getText().strip()
            if cloud and (not cur or "localhost" in cur or "127.0.0.1" in cur
                          or "host.docker.internal" in cur):
                _url_f.setText("https://ollama.com")
            elif (not cloud) and "ollama.com" in cur:
                _url_f.setText("http://localhost:11434")

        class _ModeListener(_ActionListener):
            def actionPerformed(self, _e):
                _apply_mode()
        self._ollama_mode.addActionListener(_ModeListener())

        def _ollama_test():
            key = _key_f.getText() if _is_cloud() else None
            return _client.test_ollama(_url_f.getText(), _mdl_f.getText(), key)

        rows.add(self._row_panel(JLabel("Mode:     "), self._ollama_mode))
        rows.add(self._row_panel(JLabel("Base URL: "), self._ollama_url))
        rows.add(self._row_panel(JLabel("API Key:  "), self._ollama_key,
                                 self._clear_key_btn(self._ollama_key, "ollama_key")))
        rows.add(self._row_panel(JLabel("Model:    "), self._ollama_model))
        rows.add(self._row_panel(self._test_conn_btn(self._ollama_status, _ollama_test), self._ollama_status))
        rows.add(JLabel("Local: run 'ollama serve' + 'ollama pull qwen2.5-coder:7b'  (no key needed)"))
        rows.add(JLabel("Cloud: get a key at ollama.com, base URL https://ollama.com"))
        p.add(rows, BorderLayout.NORTH)
        _apply_mode()
        return p

    # -- results tab -----------------------------------------------------------

    def _build_results(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        # Header row
        header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        self._status_lbl  = JLabel("Ready.")
        self._queue_lbl   = JLabel("")   # shows "Queue: X pending"
        # Severity tally across the whole session. A panel of plain coloured
        # labels — NOT an HTML JLabel — because Burp disables HTML rendering in
        # Swing components (hardening), so <html> markup shows up as raw text.
        self._summary_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        self._summary_panel.setOpaque(False)
        # Active provider + model, so it's obvious which AI produced the findings.
        self._model_lbl = JLabel("")
        self._model_lbl.setForeground(Color(0xFF6B35))
        # Session token usage — running total across all analyses this session
        # (last call + cumulative), for TPM/quota awareness.
        self._token_lbl = JLabel("")
        self._token_lbl.setToolTipText(
            "Token usage this session (from the provider's reported usage). "
            "Resets on Clear All.")
        header.add(JLabel("Analysis Results  "))
        header.add(self._status_lbl)
        header.add(self._queue_lbl)
        header.add(self._summary_panel)
        header.add(self._model_lbl)
        header.add(self._token_lbl)
        clear_btn  = self._skin_btn(JButton("Clear All"),   "secondary")
        clear_btn.addActionListener(lambda e: self._clear())
        header.add(clear_btn)
        demo_btn = self._skin_btn(JButton("Load Demo"), "secondary")
        demo_btn.setToolTipText(
            "Load sample findings + AI Hunt candidates (no API/internet) to showcase "
            "the full workflow -- ideal for a demo.")
        demo_btn.addActionListener(lambda e: self._load_demo())
        header.add(demo_btn)
        self._stop_btn = self._skin_btn(JButton("Stop"), "danger")
        self._stop_btn.setEnabled(False)
        self._stop_btn.addActionListener(lambda e: self._stop_analysis())
        header.add(self._stop_btn)
        export_btn = self._skin_btn(JButton("Export JSON"),  "primary")
        export_btn.addActionListener(lambda e: self._export_json())
        header.add(export_btn)
        # Export Report → popup with HTML / Markdown (client-ready deliverables).
        report_btn = self._skin_btn(JButton("Export Report"), "primary")
        report_menu = JPopupMenu()
        _html_item = JMenuItem("HTML report...")
        _html_item.addActionListener(lambda e: self._export_report("html"))
        _md_item = JMenuItem("Markdown report...")
        _md_item.addActionListener(lambda e: self._export_report("md"))
        report_menu.add(_html_item)
        report_menu.add(_md_item)
        report_btn.addActionListener(
            lambda e: report_menu.show(report_btn, 0, report_btn.getHeight()))
        header.add(report_btn)
        # NOTE: `header` is placed into `top_panel` below (with the filter bar) and
        # top_panel goes into outer.NORTH — do NOT add `header` to outer directly
        # here or it gets reparented, leaving a redundant no-op.
        # Queue cancel flag (checked by scanner workers)
        self._cancelled = False
        self._pending_count = 0
        # Debounce timer for filter field (initialized on first keystroke)
        self._filter_timer = None

        # Filter bar
        filter_bar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        filter_bar.add(JLabel("Filter Target:"))
        self._filter_field = JTextField(25)
        self._filter_field.setToolTipText(
            "Filter findings by host or keyword. Auto-set to current target host.")

        # DocumentListener to apply filter on every keystroke
        class _FilterListener(_DocumentListener):
            def __init__(self, ui):
                self._ui = ui
            def insertUpdate(self, e):
                self._ui._on_filter_change()
            def removeUpdate(self, e):
                self._ui._on_filter_change()
            def changedUpdate(self, e):
                self._ui._on_filter_change()

        self._filter_field.getDocument().addDocumentListener(_FilterListener(self))

        clear_filter_btn = self._skin_btn(JButton("Show All"), "neutral")
        clear_filter_btn.addActionListener(lambda e: self._clear_filter())
        filter_bar.add(self._filter_field)
        filter_bar.add(clear_filter_btn)
        # Severity filter — narrows the list to one severity; findings are always
        # sorted High -> Information regardless of this choice.
        filter_bar.add(JLabel("  Severity:"))
        self._sev_filter = JComboBox(
            ["All", "High", "Medium", "Low", "Information"])
        self._sev_filter.setToolTipText("Show only findings of this severity.")
        self._sev_filter.addActionListener(lambda e: self._apply_filter())
        filter_bar.add(self._sev_filter)
        self._hide_fp_chk = JCheckBox("Hide FP")
        self._hide_fp_chk.setToolTipText(
            "Hide findings marked as false positive from the list.")
        self._hide_fp_chk.addActionListener(lambda e: self._apply_filter())
        filter_bar.add(self._hide_fp_chk)

        top_panel = JPanel(BorderLayout())
        top_panel.add(header,     BorderLayout.NORTH)
        top_panel.add(filter_bar, BorderLayout.SOUTH)
        outer.add(top_panel, BorderLayout.NORTH)

        # Left: finding list
        self._result_list = JList(self._list_model)
        self._result_list.setCellRenderer(self._FindingCellRenderer())
        self._result_list.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._result_list.addListSelectionListener(lambda e: self._on_select(e))
        self._result_list.addMouseListener(self._MouseListener(self))
        list_scroll = JScrollPane(self._result_list)
        list_scroll.setPreferredSize(Dimension(300, 300))
        _NAVY = Color(0x1A1A2E)
        list_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(_NAVY, 1), "Findings"))

        # Right: detail pane
        self._detail_tabs = JTabbedPane()
        self._advisory    = JEditorPane()
        self._advisory.setEditable(False)
        # Configure the HTMLEditorKit + theme palette (also forces the pane
        # background so it never renders white inside Burp's dark theme).
        _apply_html_theme(self._advisory, is_chat=False)

        # Native Burp message editors — provide right-click, Send to Repeater, etc.
        self._editor_controller = _MessageEditorController()
        self._req_editor  = self._callbacks.createMessageEditor(
            self._editor_controller, False)
        self._resp_editor = self._callbacks.createMessageEditor(
            self._editor_controller, False)

        # Message editors are created read-only (editable=False above): the analysed
        # exchange is evidence, not a scratch pad. Name the tabs so that is explicit —
        # "Analyzed" applies whether the finding is Confirmed or Potential.
        self._detail_tabs.addTab("Advisory", JScrollPane(self._advisory))
        self._detail_tabs.addTab("Analyzed Request",  self._req_editor.getComponent())
        self._detail_tabs.addTab("Analyzed Response", self._resp_editor.getComponent())

        fp_btn = self._skin_btn(JButton("Toggle False Positive"), "purple")
        fp_btn.addActionListener(lambda e: self._toggle_fp())
        detail_area = JPanel(BorderLayout())
        detail_area.add(self._detail_tabs, BorderLayout.CENTER)
        detail_area.add(fp_btn, BorderLayout.SOUTH)

        # Right column: the advisory/detail on top and the AI chat directly below
        # it, so the chat sits level with the finding description instead of being
        # a full-width band at the bottom. The findings list then keeps the entire
        # left column at full height.
        chat_panel = self._build_chat()
        # Description on top, chat below — the divider between them is freely
        # draggable (drag up for a bigger chat) and the one-touch arrows fully
        # collapse either pane. Wide divider so it is easy to grab.
        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, detail_area, chat_panel)
        right_split.setResizeWeight(0.5)
        right_split.setDividerSize(10)
        right_split.setContinuousLayout(True)
        right_split.setOneTouchExpandable(True)
        chat_panel.setMinimumSize(Dimension(0, 120))
        detail_area.setMinimumSize(Dimension(0, 120))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, list_scroll, right_split)
        split.setDividerLocation(300)

        # Proportional setDividerLocation only takes effect once the pane has a
        # real height. Fire it after layout, retrying until the height is known,
        # so the chat starts at a usable ~half height instead of collapsed.
        class _SetDivider(_JRunnable):
            def run(self):
                h = right_split.getHeight()
                if h > 0:
                    right_split.setDividerLocation(int(h * 0.5))
                else:
                    SwingUtilities.invokeLater(self)
        SwingUtilities.invokeLater(_SetDivider())

        outer.add(split, BorderLayout.CENTER)
        return outer

    # -- interactive AI chat ---------------------------------------------------

    def _build_chat(self):
        th = _theme()
        panel = JPanel(BorderLayout(0, 0))
        panel.setBorder(BorderFactory.createLineBorder(Color(0xFF6B35), 1))

        # Per-session conversation + the request the chat is grounded on.
        self._chat_history = []          # list of (role, text)
        self._chat_context_msg = None    # currently selected IHttpRequestResponse

        # ── Header bar: solid accent strip with title + a context "chip" on the
        #    right. A coloured header (rather than a plain titled border) gives the
        #    panel its own identity and keeps the context always visible up top. ──
        header = JPanel(BorderLayout(8, 0))
        header.setBackground(Color(0xFF6B35))
        header.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 8))
        title = JLabel("AI Assistant")
        title.setForeground(Color.WHITE)
        title.setFont(title.getFont().deriveFont(Font.BOLD, 12.0))
        header.add(title, BorderLayout.WEST)

        self._chat_ctx_lbl = JLabel("No request selected")
        self._chat_ctx_lbl.setForeground(Color(0xFFE0CC))
        self._chat_ctx_lbl.setFont(self._chat_ctx_lbl.getFont().deriveFont(Font.PLAIN, 10.5))
        self._chat_ctx_lbl.setHorizontalAlignment(JLabel.RIGHT)
        header.add(self._chat_ctx_lbl, BorderLayout.CENTER)

        # Transcript (HTML pane, theme-aware — same approach as the Advisory).
        self._chat_view = JEditorPane()
        self._chat_view.setEditable(False)
        _apply_html_theme(self._chat_view, is_chat=True)
        chat_scroll = JScrollPane(self._chat_view)
        chat_scroll.setBorder(BorderFactory.createEmptyBorder())
        chat_scroll.setPreferredSize(Dimension(10, 240))

        # ── Multi-line, resizable input. A JTextArea (not a 1-line field) so a
        #    longer prompt is comfortable; Enter sends, Shift+Enter inserts a
        #    newline. The whole composer sits below a draggable divider so the
        #    user can grow it as large as they like. ──
        self._chat_input = JTextArea(3, 10)
        self._chat_input.setLineWrap(True)
        self._chat_input.setWrapStyleWord(True)
        self._chat_input.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._chat_input.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        self._chat_input.setToolTipText(
            "Ask the AI about the selected request, e.g. 'test the id parameter for LFI'. "
            "Enter to send, Shift+Enter for a new line.")
        input_scroll = JScrollPane(self._chat_input)
        input_scroll.setBorder(BorderFactory.createLineBorder(
            Color(0x8A8A8A) if not th.dark else Color(0x555555), 1))

        self._chat_send_btn = self._skin_btn(JButton("Send"), "primary")
        self._chat_send_btn.setFont(self._chat_send_btn.getFont().deriveFont(Font.BOLD))

        class _SendAction(_ActionListener):
            def __init__(self, ui): self._ui = ui
            def actionPerformed(self, _e): self._ui._chat_send()
        self._chat_send_btn.addActionListener(_SendAction(self))

        # Enter sends; Shift+Enter falls through to the JTextArea as a newline.
        class _ChatKey(_KeyAdapter):
            def __init__(self, ui): self._ui = ui
            def keyPressed(self, e):
                if e.getKeyCode() == _KeyEvent.VK_ENTER and not e.isShiftDown():
                    e.consume()
                    self._ui._chat_send()
        self._chat_input.addKeyListener(_ChatKey(self))

        clear_chat = self._skin_btn(JButton("Clear"), "secondary")
        class _ClearChat(_ActionListener):
            def __init__(self, ui): self._ui = ui
            def actionPerformed(self, _e): self._ui._chat_clear()
        clear_chat.addActionListener(_ClearChat(self))

        hint = JLabel("Enter to send  |  Shift+Enter for new line")
        hint.setForeground(th.muted)
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 10.0))

        toolbar = JPanel(BorderLayout(0, 0))
        toolbar.add(hint, BorderLayout.WEST)
        btns = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        btns.add(clear_chat)
        btns.add(self._chat_send_btn)
        toolbar.add(btns, BorderLayout.EAST)

        composer = JPanel(BorderLayout(0, 4))
        composer.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        composer.add(input_scroll, BorderLayout.CENTER)
        composer.add(toolbar, BorderLayout.SOUTH)
        composer.setMinimumSize(Dimension(0, 84))

        # Transcript on top, composer below, divider between = the chat's own
        # resize handle (independent of the outer detail/chat divider).
        chat_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, chat_scroll, composer)
        chat_split.setResizeWeight(1.0)          # transcript soaks up extra height
        chat_split.setDividerSize(8)
        chat_split.setContinuousLayout(True)
        chat_split.setOneTouchExpandable(True)
        chat_split.setBorder(BorderFactory.createEmptyBorder())

        panel.add(header, BorderLayout.NORTH)
        panel.add(chat_split, BorderLayout.CENTER)

        # Seat the composer at ~3 lines once the pane has a real height.
        class _SeatComposer(_JRunnable):
            def run(self):
                h = chat_split.getHeight()
                if h > 120:
                    chat_split.setDividerLocation(h - 108)
                else:
                    SwingUtilities.invokeLater(self)
        SwingUtilities.invokeLater(_SeatComposer())

        self._chat_render()
        return panel

    def _set_chat_context(self, msg, url):
        """Ground the chat on the selected finding's request/response."""
        self._chat_context_msg = msg
        if msg is not None:
            short = url if len(str(url)) <= 70 else str(url)[:68] + ".."
            self._chat_ctx_lbl.setText("Context: " + str(short))
            self._chat_ctx_lbl.setForeground(Color.WHITE)
        else:
            self._chat_ctx_lbl.setText("No request selected")
            self._chat_ctx_lbl.setForeground(Color(0xFFE0CC))

    def _chat_clear(self):
        self._chat_history = []
        self._chat_render()

    def _chat_render(self):
        th = _theme()
        # Accent + soft tint per role — rendered as tinted "bubble" cards (a table
        # with a bgcolor cell, which the Swing HTMLEditorKit renders reliably) so the
        # transcript reads as a conversation rather than a flat wall of paragraphs.
        if th.dark:
            you_c, you_bg = "#90CAF9", "#24303A"
            ai_c,  ai_bg  = "#FFB74D", "#3A3324"
        else:
            you_c, you_bg = "#1565C0", "#E7F0FB"
            ai_c,  ai_bg  = "#E65100", "#FFF1E3"
        fg = th.html_fg

        def _bubble(label, label_c, bg, content):
            return (
                "<table width='100%' cellspacing='0' cellpadding='6' "
                "style='margin:5px 0'><tr><td bgcolor='{0}'>"
                "<b style='color:{1}'>{2}</b><br>"
                "<span style='color:{3}'>{4}</span>"
                "</td></tr></table>"
            ).format(bg, label_c, label, fg, content)

        if not self._chat_history:
            body = ("<div style='margin:6px 2px'><i style='color:{0}'>"
                    "Ask about the selected request &mdash; e.g. "
                    "\"test the <code>file</code> parameter for LFI\" or "
                    "\"is this login endpoint injectable?\"</i></div>").format(th.muted_hex())
        else:
            rows = []
            for role, text in self._chat_history:
                if role == "you":
                    rows.append(_bubble("You", you_c, you_bg, _html_escape(text)))
                elif role == "ai":
                    rows.append(_bubble("AI", ai_c, ai_bg, _md2html(text)))
                else:  # system/notice — no bubble, just a muted status line
                    rows.append("<div style='margin:4px 2px;color:{0}'><i>{1}</i></div>".format(
                        th.muted_hex(), _html_escape(text)))
            body = "".join(rows)
        self._chat_view.setText("<html><body>" + body + "</body></html>")
        self._chat_view.setCaretPosition(self._chat_view.getDocument().getLength())

    def _chat_send(self):
        # Guard: Enter bypasses the disabled Send button, so ignore it while a
        # previous message is still being answered (avoids concurrent requests).
        if not self._chat_send_btn.isEnabled():
            return
        text = self._chat_input.getText().strip() if self._chat_input.getText() else ""
        if not text:
            return
        self._chat_history.append(("you", text))
        self._chat_input.setText("")
        self._chat_send_btn.setEnabled(False)
        self._chat_history.append(("system", "AI is thinking..."))
        self._chat_render()

        provider  = self.get_provider()
        settings  = self.get_provider_settings()
        max_tok   = self.get_max_tokens()
        ctx_msg   = self._chat_context_msg
        history   = list(self._chat_history)
        client    = self._api_client
        ui_ref    = self

        class _Worker(_JRunnable):
            def run(self):
                try:
                    sys_p, user_p = ui_ref._build_chat_prompt(history, ctx_msg)
                    reply = client.call_api(
                        provider=provider, settings=settings,
                        system_prompt=sys_p, user_prompt=user_p,
                        max_tokens=max_tok)
                except Exception as ex:
                    reply = "[Chat error] " + str(ex)[:300]

                def _update():
                    # Drop the "thinking..." notice, add the reply.
                    if ui_ref._chat_history and ui_ref._chat_history[-1][0] == "system":
                        ui_ref._chat_history.pop()
                    ui_ref._chat_history.append(("ai", reply))
                    ui_ref._chat_send_btn.setEnabled(True)
                    ui_ref._chat_render()
                SwingUtilities.invokeLater(_update)

        t = _JThread(_Worker())
        t.setDaemon(True)
        t.start()

    def _build_chat_prompt(self, history, ctx_msg):
        """Assemble a chat system + user prompt. Multi-turn is flattened into the
        user message so it works across every provider without changing the
        single-shot APIClient contract."""
        sys_p = (
            "You are a web application security assistant embedded in Burp Suite. "
            "The analyst is inspecting a specific HTTP request/response. Answer their "
            "questions precisely and practically. When asked to test for a vulnerability "
            "(e.g. LFI, SQLi, XSS, SSRF), give concrete, ready-to-run payloads and curl "
            "commands tailored to THIS request's parameters, plus what a positive result "
            "looks like. Be concise. Never fabricate evidence you cannot derive from the "
            "provided request/response.")

        lines = []
        # Grounding context: the selected request/response, truncated.
        if ctx_msg is not None:
            try:
                req = ctx_msg.getRequest()
                resp = ctx_msg.getResponse()
                req_s  = self._helpers.bytesToString(req)[:2500] if req else ""
                resp_s = self._helpers.bytesToString(resp)[:1500] if resp else ""
                lines.append("=== TARGET REQUEST ===\n" + req_s)
                if resp_s:
                    lines.append("=== RESPONSE (truncated) ===\n" + resp_s)
            except Exception:
                pass
        else:
            lines.append("(No specific request selected. Answer generally, and ask the "
                         "analyst to select a finding if request context is needed.)")

        # Conversation so far (exclude transient system notices).
        convo = [(r, t) for (r, t) in history if r in ("you", "ai")]
        lines.append("=== CONVERSATION ===")
        for role, t in convo:
            lines.append(("Analyst: " if role == "you" else "Assistant: ") + t)
        lines.append("Assistant:")
        return sys_p, "\n\n".join(lines)

    # -- AI Hunt tab -----------------------------------------------------------
    #
    # HUNT-style passive parameter heuristics (hunt_engine) surfaced in a modern
    # table, then optionally triaged by the LLM. Passive scan runs automatically
    # on in-scope Proxy traffic (see verihunt.py IHttpListener); AI triage is
    # on-demand to keep token usage under control.

    _HUNT_COLS = ["Potential Issue", "Endpoint", "Param", "Where", "Max Severity", "Status"]

    def _build_hunt(self):
        # Never let a build error kill the tab — surface it inside the panel so the
        # tab still opens and we can see what went wrong.
        try:
            return self._build_hunt_impl()
        except Exception as ex:
            import traceback
            tb = ""
            try:
                tb = traceback.format_exc()
            except Exception:
                pass
            self._log("AI Hunt build failed: " + str(ex))
            self._log(tb)
            p = JPanel(BorderLayout())
            ta = JTextArea("AI Hunt failed to build:\n\n{0}\n\n{1}".format(str(ex), tb))
            ta.setEditable(False)
            p.add(JScrollPane(ta), BorderLayout.CENTER)
            return p

    def _build_hunt_impl(self):
        from java.util import Vector
        th = _theme()
        self._helpers = self._callbacks.getHelpers()
        self._hunt_all  = []      # every hit dict (may carry "_msg")
        self._hunt_view = []      # hits currently shown (row-parallel)
        self._hunt_keys = set()   # dedup by dedup_key
        self._hunt_busy = False

        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        # ── Header / controls ──
        header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        title = JLabel("AI Hunt")
        title.setForeground(Color(0xFF6B35))
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13.0))
        header.add(title)

        # Default OFF so the plugin stays light until you opt in; tick to auto-flag
        # parameters as you browse (heuristics only — no payloads, no AI, static
        # assets skipped, work is throttled off the proxy thread).
        self._hunt_passive_cb = JCheckBox("Passive (Proxy)", False)
        self._hunt_passive_cb.setToolTipText(
            "Auto-flag suspicious parameters on Proxy traffic (heuristics only — no "
            "payloads, no AI). Static assets are skipped and scanning runs off the "
            "proxy thread, so it stays light.")
        header.add(self._hunt_passive_cb)

        # Retroactively scan Burp's existing Proxy history. Passive only sees traffic
        # that arrives AFTER you tick the box, so anything browsed earlier (or with
        # Passive off) is invisible until you press this.
        scan_hist = self._skin_btn(JButton("Scan History"), "secondary")
        scan_hist.setToolTipText(
            "Run the parameter heuristics over Burp's existing Proxy history now "
            "(retroactive). Use this if candidates are missing for a target you "
            "already browsed -- Passive only catches NEW traffic after it's enabled.")
        scan_hist.addActionListener(lambda e: self._hunt_scan_history())
        header.add(scan_hist)

        header.add(JLabel("Filter:"))
        self._hunt_filter = JTextField(16)
        class _FiltDoc(_DocumentListener):
            def __init__(s, ui): s._ui = ui
            def insertUpdate(s, e): s._ui._hunt_rebuild_table()
            def removeUpdate(s, e): s._ui._hunt_rebuild_table()
            def changedUpdate(s, e): s._ui._hunt_rebuild_table()
        self._hunt_filter.getDocument().addDocumentListener(_FiltDoc(self))
        header.add(self._hunt_filter)

        _classes = ["All classes"] + [s["cls"] for s in _hunt.SIGNATURES]
        try:
            _classes.append(_hunt.GENERIC_CLASS)
        except Exception:
            pass
        self._hunt_class_combo = JComboBox(_classes)
        self._hunt_class_combo.addActionListener(lambda e: self._hunt_rebuild_table())
        header.add(self._hunt_class_combo)

        triage_sel = self._skin_btn(JButton("Triage Selected (AI)"), "primary")
        triage_sel.addActionListener(lambda e: self._hunt_triage("selected"))
        header.add(triage_sel)
        triage_all = self._skin_btn(JButton("Triage All (AI)"), "secondary")
        triage_all.addActionListener(lambda e: self._hunt_triage("all"))
        header.add(triage_all)
        discover_btn = self._skin_btn(JButton("AI Discover"), "primary")
        discover_btn.setToolTipText(
            "Ask the AI to propose issues the parameter heuristics MISS (access "
            "control, business logic, sensitive data, headers) from the selected "
            "candidate's endpoint. Adds rows tagged 'AI:'.")
        discover_btn.addActionListener(lambda e: self._hunt_discover("selected"))
        header.add(discover_btn)
        clear_h = self._skin_btn(JButton("Clear"), "secondary")
        clear_h.addActionListener(lambda e: self._hunt_clear())
        header.add(clear_h)

        self._hunt_count_lbl = JLabel("")
        self._hunt_count_lbl.setForeground(th.muted)
        header.add(self._hunt_count_lbl)

        # Persistent disclaimer so candidates are never mistaken for confirmed
        # findings -- they are heuristic guesses until validated. ASCII-only text
        # (non-ASCII glyphs mojibake in Burp's label rendering).
        self._hunt_banner = JLabel(
            "  [!]  POTENTIAL candidates only -- heuristic guesses (parameter "
            "name/value), NOT confirmed. No payloads sent. Validate with Triage (AI) "
            "or manual testing before reporting.")
        self._hunt_banner.setOpaque(True)
        self._hunt_banner.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6))
        self._skin_hunt_banner()   # theme-aware colours (re-applied on theme switch)
        north = JPanel(BorderLayout())
        north.add(header, BorderLayout.NORTH)
        north.add(self._hunt_banner, BorderLayout.SOUTH)
        outer.add(north, BorderLayout.NORTH)

        # ── Findings table (left) + detail (right) ──
        class _Model(DefaultTableModel):
            def isCellEditable(self, r, c):
                return False
        _cols = Vector()
        for _c in self._HUNT_COLS:
            _cols.add(_c)
        self._hunt_model = _Model(_cols, 0)
        self._hunt_table = JTable(self._hunt_model)
        self._hunt_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._hunt_table.setRowHeight(22)
        self._hunt_table.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._hunt_table.getTableHeader().setReorderingAllowed(False)
        try:
            self._hunt_table.setAutoCreateRowSorter(True)
        except Exception:
            pass

        # Colour Severity + AI Verdict cells by value (theme resolved at paint time).
        class _Rend(DefaultTableCellRenderer):
            def getTableCellRendererComponent(s, table, value, sel, foc, row, col):
                comp = super(_Rend, s).getTableCellRendererComponent(
                    table, value, sel, foc, row, col)
                try:
                    thm = _theme()
                    dark = thm.dark
                    v = (str(value) if value is not None else "").upper()
                    colr = None
                    # Order matters: check UNLIKELY before LIKELY (substring), and
                    # the Status cell may carry a "% confidence" suffix.
                    if "UNLIKELY" in v:
                        colr = thm.muted
                    elif "LIKELY" in v or v == "HIGH":
                        colr = Color(0xFF8A80) if dark else Color(0xC62828)
                    elif "POSSIBLE" in v or "POTENTIAL" in v or v == "MEDIUM":
                        colr = Color(0xFFCC80) if dark else Color(0xE65100)
                    elif v == "LOW":
                        colr = Color(0x90CAF9) if dark else Color(0x1565C0)
                    if colr is not None and not sel:
                        comp.setForeground(colr)
                except Exception:
                    pass
                return comp
        _rend = _Rend()
        # Apply the colouring renderer to Severity (4) and AI Verdict (5).
        for _ci in (4, 5):
            try:
                self._hunt_table.getColumnModel().getColumn(_ci).setCellRenderer(_rend)
            except Exception:
                pass

        class _Sel(_ListSelectionListener):
            def __init__(s, ui): s._ui = ui
            def valueChanged(s, e):
                if not e.getValueIsAdjusting():
                    s._ui._hunt_on_select()
        self._hunt_table.getSelectionModel().addListSelectionListener(_Sel(self))

        # Right-click → Send to Repeater/Intruder / Copy URL for the selected row.
        class _HuntMouse(MouseAdapter):
            def __init__(s, ui): s._ui = ui
            def mouseReleased(s, e): s._popup(e)
            def mousePressed(s, e): s._popup(e)
            def _popup(s, e):
                if not e.isPopupTrigger():
                    return
                tbl = s._ui._hunt_table
                r = tbl.rowAtPoint(e.getPoint())
                if r < 0:
                    return
                if not tbl.isRowSelected(r):
                    tbl.setRowSelectionInterval(r, r)
                menu = JPopupMenu()
                for _label, _fn in (("Deep Analyze (AI)", s._ui._hunt_deep_analyze),
                                    ("Send to Repeater", s._ui._hunt_send_repeater),
                                    ("Send to Intruder", s._ui._hunt_send_intruder),
                                    ("Copy URL", s._ui._hunt_copy_url)):
                    mi = JMenuItem(_label)
                    class _A(_ActionListener):
                        def __init__(a, f): a._f = f
                        def actionPerformed(a, ev): a._f()
                    mi.addActionListener(_A(_fn))
                    menu.add(mi)
                menu.show(e.getComponent(), e.getX(), e.getY())
        self._hunt_table.addMouseListener(_HuntMouse(self))

        table_scroll = JScrollPane(self._hunt_table)
        table_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(0xFF6B35), 1), "Candidates"))

        # Right side: detail/methodology on top, the native request/response
        # viewer for the selected candidate below (with Burp's own right-click:
        # Send to Repeater/Intruder, etc.).
        self._hunt_detail = JEditorPane()
        self._hunt_detail.setEditable(False)
        _apply_html_theme(self._hunt_detail, is_chat=False)
        detail_scroll = JScrollPane(self._hunt_detail)
        detail_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(0xFF6B35), 1), "Detail & Methodology"))

        self._hunt_editor_controller = _MessageEditorController()
        self._hunt_req_editor  = self._callbacks.createMessageEditor(self._hunt_editor_controller, False)
        self._hunt_resp_editor = self._callbacks.createMessageEditor(self._hunt_editor_controller, False)
        msg_tabs = JTabbedPane()
        msg_tabs.addTab("Request",  self._hunt_req_editor.getComponent())
        msg_tabs.addTab("Response", self._hunt_resp_editor.getComponent())

        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, detail_scroll, msg_tabs)
        right_split.setResizeWeight(0.5)
        right_split.setDividerLocation(240)
        right_split.setContinuousLayout(True)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, table_scroll, right_split)
        split.setResizeWeight(0.55)
        split.setDividerLocation(520)
        split.setContinuousLayout(True)
        outer.add(split, BorderLayout.CENTER)

        self._hunt_render_empty()
        self._hunt_update_count()
        return outer

    # ── Passive ingestion (called from the IHttpListener, Burp thread) ──────────

    def set_scanner(self, scanner):
        """Wire the scanner so the UI can trigger Deep Analyze and reach memory."""
        self._scanner = scanner

    def is_hunt_passive(self):
        try:
            return bool(self._hunt_passive_cb.isSelected())
        except Exception:
            return False

    def _skin_hunt_banner(self):
        """Theme-aware colours for the POTENTIAL disclaimer banner (re-applied when
        the user switches Light/Dark)."""
        try:
            th = _theme()
            self._hunt_banner.setBackground(Color(0x3A2E1A) if th.dark else Color(0xFFF3E0))
            self._hunt_banner.setForeground(Color(0xFFCC80) if th.dark else Color(0xB35A00))
            self._hunt_banner.repaint()
        except Exception:
            pass

    def hunt_passive_scan(self, message):
        """Run heuristics on one proxied message and add new hits (thread-safe)."""
        try:
            hits = _hunt.analyze(self._helpers, message)
        except Exception:
            return
        if not hits:
            return
        for h in hits:
            h["_msg"] = message      # keep the exchange for later AI triage
        class _Add(_JRunnable):
            def __init__(s, ui, hh): s._ui = ui; s._hh = hh
            def run(s): s._ui._hunt_add_hits(s._hh)
        SwingUtilities.invokeLater(_Add(self, hits))

    def _hunt_add_hits(self, hits):
        """EDT: append genuinely-new hits, incrementally add matching rows."""
        MAX = 4000
        added_visible = 0
        for h in hits:
            key = h.get("dedup_key")
            if not key or key in self._hunt_keys:
                continue
            if len(self._hunt_all) >= MAX:
                break
            self._hunt_keys.add(key)
            self._hunt_all.append(h)
            if self._hunt_matches(h):
                self._hunt_model.addRow(self._hunt_row(h))
                self._hunt_view.append(h)
                added_visible += 1
        if added_visible:
            self._hunt_update_count()

    # ── Table helpers ───────────────────────────────────────────────────────────

    def _hunt_status_text(self, h):
        """Status cell: 'Potential' until triaged, then 'LIKELY 82%' etc."""
        v = h.get("ai_verdict")
        if not v:
            return u"Potential"
        c = h.get("ai_confidence")
        return u"{0} {1}%".format(v, c) if c else v

    def _hunt_row(self, h):
        # "Status" reads Potential until the AI (or you) validate it — never
        # present a heuristic candidate as a confirmed finding.
        return [h["cls"], h["endpoint"], h["param"], h["where"], h["sev"],
                self._hunt_status_text(h)]

    def _hunt_matches(self, h):
        try:
            cls = str(self._hunt_class_combo.getSelectedItem())
        except Exception:
            cls = "All classes"
        if cls and cls != "All classes" and h["cls"] != cls:
            return False
        q = ""
        try:
            q = (self._hunt_filter.getText() or "").strip().lower()
        except Exception:
            pass
        if q:
            hay = u"{0} {1} {2} {3}".format(
                h["cls"], h["endpoint"], h["param"], h.get("ai_verdict", "")).lower()
            if q not in hay:
                return False
        return True

    def _hunt_rebuild_table(self):
        try:
            self._hunt_model.setRowCount(0)
        except Exception:
            return
        self._hunt_view = []
        for h in self._hunt_all:
            if self._hunt_matches(h):
                self._hunt_model.addRow(self._hunt_row(h))
                self._hunt_view.append(h)
        self._hunt_update_count()

    def _hunt_refresh_row(self, h):
        """Update the AI Verdict cell for a hit already shown (after triage)."""
        try:
            idx = self._hunt_view.index(h)
        except ValueError:
            return
        try:
            # account for a row sorter (view vs model index)
            self._hunt_model.setValueAt(self._hunt_status_text(h), idx, 5)
        except Exception:
            pass

    def _hunt_update_count(self):
        total = len(self._hunt_all)
        shown = len(self._hunt_view)
        triaged = sum(1 for h in self._hunt_all if h.get("ai_verdict"))
        self._hunt_count_lbl.setText(
            "  {0} shown / {1} total  |  {2} AI-triaged".format(shown, total, triaged))

    def _hunt_on_select(self):
        try:
            row = self._hunt_table.getSelectedRow()
            if row < 0:
                return
            mrow = self._hunt_table.convertRowIndexToModel(row)
            if mrow < 0 or mrow >= len(self._hunt_view):
                return
            h = self._hunt_view[mrow]
            self._hunt_render_detail(h)
            self._hunt_show_message(h.get("_msg"))
        except Exception:
            pass

    def _hunt_show_message(self, msg):
        """Load the selected candidate's request/response into the native viewer."""
        try:
            if msg is not None:
                self._hunt_editor_controller.set_message(msg)
                req  = msg.getRequest()
                resp = msg.getResponse()
                self._hunt_req_editor.setMessage(req if req else [], True)
                self._hunt_resp_editor.setMessage(resp if resp else [], False)
            else:
                self._hunt_editor_controller.set_message(None)
                self._hunt_req_editor.setMessage([], True)
                self._hunt_resp_editor.setMessage([], False)
        except Exception:
            pass

    def _hunt_selected_hit(self):
        try:
            row = self._hunt_table.getSelectedRow()
            if row < 0:
                return None
            mrow = self._hunt_table.convertRowIndexToModel(row)
            if 0 <= mrow < len(self._hunt_view):
                return self._hunt_view[mrow]
        except Exception:
            pass
        return None

    def _hunt_send_repeater(self):
        h = self._hunt_selected_hit()
        if not h or not h.get("_msg"):
            self._status_lbl.setText("No captured request for this candidate.")
            return
        try:
            msg = h["_msg"]; svc = msg.getHttpService()
            self._callbacks.sendToRepeater(
                svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
                msg.getRequest(), "Hunt:" + h.get("param", ""))
            self._status_lbl.setText("Sent to Repeater: " + h.get("endpoint", ""))
        except Exception as ex:
            self._status_lbl.setText("Send to Repeater failed: " + str(ex))

    def _hunt_send_intruder(self):
        h = self._hunt_selected_hit()
        if not h or not h.get("_msg"):
            self._status_lbl.setText("No captured request for this candidate.")
            return
        try:
            msg = h["_msg"]; svc = msg.getHttpService()
            self._callbacks.sendToIntruder(
                svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
                msg.getRequest())
            self._status_lbl.setText("Sent to Intruder: " + h.get("endpoint", ""))
        except Exception as ex:
            self._status_lbl.setText("Send to Intruder failed: " + str(ex))

    def _hunt_copy_url(self):
        h = self._hunt_selected_hit()
        if not h:
            return
        try:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(h.get("url", "")), None)
            self._status_lbl.setText("Copied URL.")
        except Exception as ex:
            self._status_lbl.setText("Copy failed: " + str(ex))

    def _hunt_deep_analyze(self):
        """Send the selected candidate's captured exchange to the full Results
        'Analyze with AI' pipeline (heuristic candidate -> deep AI analysis)."""
        h = self._hunt_selected_hit()
        if not h or not h.get("_msg"):
            self._status_lbl.setText("No captured request for this candidate.")
            return
        scanner = getattr(self, "_scanner", None)
        if scanner is None:
            self._status_lbl.setText("Scanner not ready.")
            return
        try:
            scanner.analyze_message(h["_msg"])
            try:
                self._tabs.setSelectedIndex(1)   # jump to Results to watch it run
            except Exception:
                pass
            self._status_lbl.setText("Deep analyzing: " + h.get("endpoint", ""))
        except Exception as ex:
            self._status_lbl.setText("Deep analyze failed: " + str(ex))

    # ── Detail rendering ────────────────────────────────────────────────────────

    def _hunt_render_empty(self):
        th = _theme()
        body = ("<div style='color:{0}'>"
                "<p><b>AI Hunt</b> flags suspicious parameters by name/value (HUNT-style) "
                "with no payloads and no AI cost, then lets you triage the promising ones "
                "with the LLM on demand.</p>"
                "<p><b>To start:</b> tick <b>Passive (Proxy)</b> above, then browse the "
                "target through Burp &mdash; candidates appear here as you go. "
                "(Static assets are skipped; scanning runs off the proxy thread so it stays light.)</p>"
                "<p>Select a candidate to see why it was flagged, the testing methodology, "
                "and suggested payloads. Use <b>Triage (AI)</b> to have the model confirm "
                "and tailor payloads to the real request/response.</p>"
                "</div>").format(th.muted_hex())
        self._hunt_detail.setText("<html><body>" + body + "</body></html>")

    def _hunt_render_detail(self, h):
        th = _theme()
        acc = "#FF6B35"
        sev_c = {"High": "#E53935", "Medium": "#FB8C00", "Low": "#1E88E5"}.get(h["sev"], th.muted_hex())
        parts = []
        parts.append(u"<h2 style='color:{0};margin:2px 0'>Potential: {1}</h2>".format(
            acc, _html_escape(h["cls"])))
        # Always-visible "not confirmed" note, unless AI already judged it.
        if not h.get("ai_verdict"):
            warn = "#FFB74D" if th.dark else "#B35A00"
            parts.append(u"<p style='margin:2px 0;color:{0}'><i>Heuristic candidate — "
                         u"<b>not confirmed</b>. No payload was sent. Validate with "
                         u"Triage (AI) or manual testing.</i></p>".format(warn))
        parts.append(u"<p style='margin:2px 0'><b style='color:{0}'>{1}</b> potential impact "
                     u"&nbsp; <code>{2}</code></p>".format(sev_c, h["sev"], _html_escape(h["endpoint"])))
        parts.append(u"<p style='margin:2px 0'>Parameter <b>{0}</b> "
                     u"<span style='color:{1}'>({2})</span>{3}</p>".format(
                         _html_escape(h["param"]), th.muted_hex(), _html_escape(h["where"]),
                         (u" = <code>" + _html_escape(h["value"]) + u"</code>") if h["value"] else u""))
        parts.append(u"<p style='margin:6px 0'>{0}</p>".format(_html_escape(h["why"])))

        # Evidence excerpt: show the request line with the parameter highlighted,
        # and (if the value is reflected) the response snippet highlighted.
        try:
            msg = h.get("_msg")
            param = h.get("param", "")
            hl = "#FF6B35"
            if msg is not None and param and h.get("where") != "ai":
                rb = msg.getRequest()
                req_txt = self._helpers.bytesToString(rb) if rb else u""
                line, _i = _hunt.request_param_excerpt(req_txt, param)
                if line:
                    esc = _html_escape(line)
                    # bold+colour the param token within the escaped line
                    esc = esc.replace(_html_escape(param),
                                      u"<b style='color:{0}'>{1}</b>".format(hl, _html_escape(param)), 1)
                    parts.append(u"<p style='margin:6px 0 0'><b>In request:</b></p>"
                                 u"<pre>{0}</pre>".format(esc))
                val = h.get("value_full") or h.get("value")
                if val:
                    sb = msg.getResponse()
                    resp_txt = self._helpers.bytesToString(sb) if sb else u""
                    snip = _hunt.response_reflection_excerpt(resp_txt, val)
                    if snip:
                        esc = _html_escape(snip)
                        esc = esc.replace(_html_escape(val),
                                          u"<b style='color:{0}'>{1}</b>".format(hl, _html_escape(val)), 1)
                        parts.append(u"<p style='margin:6px 0 0;color:#2e7d32'><b>Reflected in "
                                     u"response:</b></p><pre>{0}</pre>".format(esc))
        except Exception:
            pass

        v = h.get("ai_verdict")
        if v:
            vc = {"LIKELY": "#2e7d32", "POSSIBLE": "#E65100", "UNLIKELY": th.muted_hex()}.get(v, th.muted_hex())
            if th.dark:
                vc = {"LIKELY": "#A5D6A7", "POSSIBLE": "#FFCC80", "UNLIKELY": th.muted_hex()}.get(v, th.muted_hex())
            conf = h.get("ai_confidence")
            head = u"AI verdict: {0}".format(v)
            if conf:
                head += u" &nbsp;<span style='color:{0}'>(confidence {1}%)</span>".format(th.muted_hex(), conf)
            parts.append(u"<div style='margin:8px 0'><b style='color:{0}'>{1}</b></div>".format(vc, head))
            if h.get("ai_reason"):
                parts.append(u"<p style='margin:2px 0'><b>Evidence:</b> {0}</p>".format(
                    _html_escape(h["ai_reason"])))
            if h.get("ai_payloads"):
                parts.append(u"<b style='color:{0}'>AI-tailored payloads</b><pre>{1}</pre>".format(
                    acc, _html_escape("\n".join(h["ai_payloads"]))))
            if h.get("ai_next"):
                parts.append(u"<p style='margin:2px 0'><b>Next step:</b> {0}</p>".format(
                    _html_escape(h["ai_next"])))

        parts.append(u"<h3 style='color:{0};margin:8px 0 2px'>Methodology</h3>"
                     u"<p style='margin:2px 0'>{1}</p>".format(acc, _html_escape(h["methodology"])))
        if h.get("payloads"):
            parts.append(u"<h3 style='color:{0};margin:8px 0 2px'>Try these</h3><pre>{1}</pre>".format(
                acc, _html_escape("\n".join(h["payloads"]))))
        self._hunt_detail.setText("<html><body>" + "".join(parts) + "</body></html>")
        self._hunt_detail.setCaretPosition(0)

    # ── AI triage (on-demand, background) ───────────────────────────────────────

    def _hunt_triage(self, scope):
        if self._hunt_busy:
            self._status_lbl.setText("Hunt triage already running...")
            return
        # Choose target hits
        targets = []
        if scope == "selected":
            rows = self._hunt_table.getSelectedRows()
            for r in rows:
                try:
                    mr = self._hunt_table.convertRowIndexToModel(r)
                    if 0 <= mr < len(self._hunt_view):
                        targets.append(self._hunt_view[mr])
                except Exception:
                    pass
            if not targets:
                self._status_lbl.setText("Select one or more candidates first.")
                return
        else:
            targets = list(self._hunt_view)
            if not targets:
                self._status_lbl.setText("No candidates to triage.")
                return

        # Group by endpoint, keeping a representative message per group.
        groups = []   # list of (endpoint, msg, [hits])
        by_ep = {}
        for h in targets:
            ep = h["endpoint"]
            if ep not in by_ep:
                by_ep[ep] = (h.get("_msg"), [])
                groups.append(ep)
            by_ep[ep][1].append(h)

        MAX_GROUPS = 30
        ordered = [(ep, by_ep[ep][0], by_ep[ep][1]) for ep in groups]
        capped = ordered[:MAX_GROUPS]
        remainder = len(ordered) - len(capped)

        provider = self.get_provider()
        settings = self.get_provider_settings()
        max_tokens = self.get_max_tokens()

        self._hunt_busy = True
        self._status_lbl.setText("AI triage: 0/{0} endpoints...".format(len(capped)))

        import threading
        def _worker():
          try:
            done = 0
            for ep, msg, hits in capped:
                # NOTE: deliberately does NOT check the Results-tab cancel flag —
                # that flag can be left True by a prior "Stop" and would silently
                # abort triage. Triage is bounded (MAX_GROUPS) instead.
                try:
                    req_txt = resp_txt = u""
                    if msg is not None:
                        try:
                            rb = msg.getRequest()
                            req_txt = self._helpers.bytesToString(rb) if rb else u""
                        except Exception:
                            pass
                        try:
                            sb = msg.getResponse()
                            resp_txt = self._helpers.bytesToString(sb) if sb else u""
                        except Exception:
                            pass
                    sys_p, usr_p = _hunt.build_triage_prompt(ep, hits, req_txt, resp_txt)
                    out = self._api_client.call_api(
                        provider=provider, settings=settings,
                        system_prompt=sys_p, user_prompt=usr_p,
                        max_tokens=min(int(max_tokens) if max_tokens else 1200, 1500))
                    verdicts = _hunt.parse_triage(out)
                    for i, h in enumerate(hits):
                        vv = verdicts.get(i)
                        if vv:
                            verdict, conf, evidence, payloads, nxt = vv
                            h["ai_verdict"] = verdict
                            h["ai_confidence"] = conf
                            h["ai_reason"] = evidence
                            h["ai_payloads"] = payloads
                            h["ai_next"] = nxt
                except Exception as ex:
                    self._log("Hunt triage error for {0}: {1}".format(ep, str(ex)))
                done += 1

                class _Prog(_JRunnable):
                    def __init__(s, ui, d, hh): s._ui = ui; s._d = d; s._hh = hh
                    def run(s):
                        s._ui._status_lbl.setText(
                            "AI triage: {0}/{1} endpoints...".format(s._d, len(capped)))
                        for _h in s._hh:
                            s._ui._hunt_refresh_row(_h)
                        s._ui._hunt_update_count()
                        s._ui.refresh_token_label()
                SwingUtilities.invokeLater(_Prog(self, done, hits))

            class _Fin(_JRunnable):
                def __init__(s, ui): s._ui = ui
                def run(s):
                    s._ui._hunt_busy = False
                    msg = "AI triage complete ({0} endpoint(s)).".format(len(capped))
                    if remainder > 0:
                        msg += " {0} more not triaged (cap {1}).".format(remainder, MAX_GROUPS)
                    s._ui._status_lbl.setText(msg)
                    s._ui._hunt_on_select()   # refresh detail of current selection
            SwingUtilities.invokeLater(_Fin(self))
          finally:
            # Safety net: never leave triage permanently "busy" even if something
            # above throws before _Fin is scheduled.
            class _Rst(_JRunnable):
                def __init__(s, ui): s._ui = ui
                def run(s): s._ui._hunt_busy = False
            SwingUtilities.invokeLater(_Rst(self))

        t = threading.Thread(target=_worker)
        t.daemon = True
        t.start()

    def _hunt_discover(self, scope):
        """AI auto-discovery: ask the model to propose issues the heuristics missed,
        for the selected candidate's endpoint. Adds new 'AI:' rows."""
        if self._hunt_busy:
            self._status_lbl.setText("Hunt AI task already running...")
            return
        h = self._hunt_selected_hit()
        if not h or not h.get("_msg"):
            self._status_lbl.setText("Select a candidate (with a captured request) first.")
            return
        msg = h["_msg"]; method = h.get("method", "GET"); path = h.get("path", "/")
        full_url = h.get("url", "")
        try:
            netloc = h.get("endpoint", " ").split(" ", 1)[1]
            netloc = netloc[:len(netloc) - len(path)] if path and netloc.endswith(path) else netloc
        except Exception:
            netloc = ""
        provider = self.get_provider(); settings = self.get_provider_settings()
        max_tokens = self.get_max_tokens()
        self._hunt_busy = True
        self._status_lbl.setText("AI discovery on " + h.get("endpoint", "") + " ...")

        import threading
        def _worker():
          try:
            req_txt = resp_txt = u""
            try:
                rb = msg.getRequest(); req_txt = self._helpers.bytesToString(rb) if rb else u""
            except Exception:
                pass
            try:
                sb = msg.getResponse(); resp_txt = self._helpers.bytesToString(sb) if sb else u""
            except Exception:
                pass
            sys_p, usr_p = _hunt.build_discovery_prompt(h.get("endpoint", ""), req_txt, resp_txt)
            out = self._api_client.call_api(
                provider=provider, settings=settings, system_prompt=sys_p,
                user_prompt=usr_p,
                max_tokens=min(int(max_tokens) if max_tokens else 1600, 2000))
            # Log the raw reply so a non-conforming / empty model response (e.g. prose,
            # or a provider returning reasoning-only) is diagnosable, not a silent 0.
            try:
                self._log(u"AI discovery raw reply ({0} chars): {1}".format(
                    len(out or u""), (out or u"(empty)")[:800]))
            except Exception:
                pass
            new_hits = _hunt.parse_discovery(out, method, netloc, path, full_url)
            for nh in new_hits:
                nh["_msg"] = msg
            raw_len = len(out or u"")
            class _Add(_JRunnable):
                def __init__(s, ui, hh): s._ui = ui; s._hh = hh
                def run(s):
                    before = len(s._ui._hunt_all)
                    s._ui._hunt_add_hits(s._hh)
                    added = len(s._ui._hunt_all) - before
                    s._ui.refresh_token_label()
                    if added:
                        s._ui._status_lbl.setText(
                            "AI discovery: added {0} new candidate(s).".format(added))
                    elif not s._hh:
                        s._ui._status_lbl.setText(
                            "AI discovery: model returned no parseable findings "
                            "(raw reply {0} chars -- see Extensions output; try another "
                            "model or raise Max Tokens).".format(raw_len))
                    else:
                        s._ui._status_lbl.setText(
                            "AI discovery: no NEW candidates (all already listed).")
            SwingUtilities.invokeLater(_Add(self, new_hits))
          except Exception as ex:
            self._log("Hunt discovery error: {0}".format(str(ex)))
          finally:
            class _Rst(_JRunnable):
                def __init__(s, ui): s._ui = ui
                def run(s): s._ui._hunt_busy = False
            SwingUtilities.invokeLater(_Rst(self))
        t = threading.Thread(target=_worker)
        t.daemon = True
        t.start()

    def _hunt_scan_history(self):
        """Retroactively run the passive heuristics over Burp's existing Proxy
        history, so candidates appear for traffic browsed BEFORE Passive was enabled
        (or with it off). Runs off the EDT; honours 'Scope only' + static-asset skip;
        flushes rows in batches so the UI stays responsive on large histories."""
        if getattr(self, "_hunt_hist_busy", False):
            self._status_lbl.setText("Proxy-history scan already running...")
            return
        self._hunt_hist_busy = True
        self._status_lbl.setText("Scanning Proxy history...")

        import threading
        def _worker():
          added = [0]
          scanned = [0]
          try:
            try:
                hist = self._callbacks.getProxyHistory() or []
            except Exception:
                hist = []
            try:
                scope_only = bool(self.get_scope_only())
            except Exception:
                scope_only = False
            MAXHIST = 8000            # bound work on very large histories
            batch = []

            def _flush(chunk):
                class _Add(_JRunnable):
                    def __init__(s, ui, hh): s._ui = ui; s._hh = hh
                    def run(s): s._ui._hunt_add_hits(s._hh)
                SwingUtilities.invokeLater(_Add(self, chunk))

            for msg in list(hist)[:MAXHIST]:
                scanned[0] += 1
                try:
                    url = self._helpers.analyzeRequest(msg).getUrl()
                    if _hunt.is_static_url(url.toString()):
                        continue
                    if scope_only and not self._callbacks.isInScope(url):
                        continue
                    hits = _hunt.analyze(self._helpers, msg)
                except Exception:
                    continue
                if not hits:
                    continue
                for h in hits:
                    h["_msg"] = msg
                batch.extend(hits)
                added[0] += len(hits)
                if len(batch) >= 200:
                    _flush(batch)
                    batch = []
            if batch:
                _flush(batch)
          except Exception as ex:
            self._log("Scan History error: " + str(ex))
          finally:
            _sc = scanned[0]
            class _Fin(_JRunnable):
                def __init__(s, ui, n): s._ui = ui; s._n = n
                def run(s):
                    s._ui._hunt_hist_busy = False
                    s._ui._hunt_update_count()
                    s._ui._status_lbl.setText(
                        "Scanned {0} proxy message(s). See AI Hunt candidates "
                        "(Scope only affects what's included).".format(s._n))
            SwingUtilities.invokeLater(_Fin(self, _sc))

        t = threading.Thread(target=_worker)
        t.daemon = True
        t.start()

    def _hunt_clear(self):
        self._hunt_all = []
        self._hunt_view = []
        self._hunt_keys = set()
        try:
            self._hunt_model.setRowCount(0)
        except Exception:
            pass
        self._hunt_render_empty()
        self._hunt_show_message(None)
        self._hunt_update_count()
        self._status_lbl.setText("Hunt cleared.")

    # -- dashboard tab ---------------------------------------------------------

    def _build_dashboard(self):
        self._dash_panel = JPanel(BorderLayout(4, 4))
        self._dash_panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        title = JLabel("Dashboard")
        title.setForeground(Color(0xFF6B35))
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13.0))
        header.add(title)
        refresh = self._skin_btn(JButton("Refresh"), "secondary")
        refresh.addActionListener(lambda e: self._refresh_dashboard())
        header.add(refresh)
        self._dash_panel.add(header, BorderLayout.NORTH)
        self._dash_view = JEditorPane()
        self._dash_view.setEditable(False)
        _apply_html_theme(self._dash_view, is_chat=False)
        self._dash_panel.add(JScrollPane(self._dash_view), BorderLayout.CENTER)
        self._refresh_dashboard()
        return self._dash_panel

    def _refresh_dashboard(self):
        import time
        try:
            th = _theme()
            # Re-apply the themed HTML kit + component background on every refresh so
            # the dashboard never keeps a stale (e.g. dark) background after a
            # Light/Dark switch — otherwise it renders as a black block on Light.
            try:
                _apply_html_theme(self._dash_view, is_chat=False)
            except Exception:
                pass
            esc   = _html_escape
            dark  = th.dark
            acc   = "#FF6B35"
            muted = th.muted_hex()
            SEVC  = {"High": "#E53935", "Medium": "#FB8C00", "Low": "#1E88E5",
                     "Information": "#9E9E9E"}
            VC    = {"LIKELY": "#2e7d32", "POSSIBLE": "#E65100",
                     "Potential": "#B35A00", "UNLIKELY": "#9E9E9E"}
            head_bg = "#3a3f44" if dark else "#eef1f5"
            card_bg = "#33373b" if dark else "#fafbfc"

            def tint(kind):
                if dark:
                    return {"High": "#4a2c2c", "Medium": "#4a3b26", "Low": "#26384a",
                            "Confirmed": "#25402c", "Potential": "#40331f",
                            "n": "#2f3438"}.get(kind, "#2f3438")
                return {"High": "#fdecea", "Medium": "#fff4e5", "Low": "#e8f1fc",
                        "Confirmed": "#e7f4ea", "Potential": "#fff2e0",
                        "n": "#f2f4f7"}.get(kind, "#f2f4f7")

            def num(n):
                try:
                    return u"{0:,}".format(int(n))
                except Exception:
                    return u"{0}".format(n)

            # ── gather data ─────────────────────────────────────────────────
            sev = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
            fp = confirmed = potential = 0
            hosts = {}
            for key, iss in self._all_findings.items():
                if iss is None:
                    continue
                if key.startswith("[FP]"):
                    fp += 1
                    continue
                s = iss.getSeverity()
                sev[s] = sev.get(s, 0) + 1
                try:
                    cf = (iss.getConfidence() or u"").lower()
                    nm = (iss.getIssueName() or u"")
                except Exception:
                    cf = nm = u""
                if cf in ("certain", "firm") and not nm.lower().startswith("potential"):
                    confirmed += 1
                else:
                    potential += 1
                try:
                    uo = iss.getUrl()
                    host = (uo.getHost() or u"") if uo else u""
                    prt = uo.getPort() if uo else -1
                    if host and prt not in (80, 443, -1, 0):
                        host = u"{0}:{1}".format(host, prt)
                except Exception:
                    host = u""
                if host:
                    d = hosts.setdefault(host, {"High": 0, "Medium": 0, "Low": 0, "Information": 0})
                    d[s] = d.get(s, 0) + 1
            total = sev["High"] + sev["Medium"] + sev["Low"] + sev["Information"]
            maxsev = max([1, sev["High"], sev["Medium"], sev["Low"], sev["Information"]])

            hunt_cls = {}
            hunt_status = {}
            triaged = 0
            for h in getattr(self, "_hunt_all", []):
                hunt_cls[h["cls"]] = hunt_cls.get(h["cls"], 0) + 1
                st = h.get("ai_verdict") or "Potential"
                hunt_status[st] = hunt_status.get(st, 0) + 1
                if h.get("ai_verdict"):
                    triaged += 1
            hunt_total = len(getattr(self, "_hunt_all", []))

            mem_fp = mem_cf = 0
            sc = getattr(self, "_scanner", None)
            if sc is not None and hasattr(sc, "memory"):
                try:
                    mem_fp, mem_cf = sc.memory.stats()
                except Exception:
                    pass
            req_analyzed = None
            try:
                if sc is not None and hasattr(sc, "_seen_hashes"):
                    req_analyzed = len(sc._seen_hashes)
            except Exception:
                pass
            try:
                usage = _get_usage() or {}
            except Exception:
                usage = {}
            tok = int(usage.get("total", 0)) if usage else 0
            try:
                prov, model = self._active_model()
            except Exception:
                prov, model = (u"", u"")

            # risk posture: severity-first (any High => at least HIGH), with a
            # weighted score only escalating to CRITICAL.
            score = 10 * sev["High"] + 4 * sev["Medium"] + 1 * sev["Low"]
            if total == 0:
                risk_lbl, risk_c = "NO DATA", muted
            elif sev["High"] >= 3 or score >= 40:
                risk_lbl, risk_c = "CRITICAL", "#B71C1C"
            elif sev["High"] >= 1:
                risk_lbl, risk_c = "HIGH", "#E53935"
            elif sev["Medium"] >= 1:
                risk_lbl, risk_c = "MEDIUM", "#FB8C00"
            elif sev["Low"] >= 1:
                risk_lbl, risk_c = "LOW", "#1E88E5"
            else:
                risk_lbl, risk_c = "CLEAN", "#2e7d32"

            # ── builders ────────────────────────────────────────────────────
            def tile(label, value, numc, bg):
                return (u"<td width='84' bgcolor='{0}' align='center'>"
                        u"<font size='6' color='{1}'><b>{2}</b></font><br>"
                        u"<font size='2' color='{3}'>{4}</font></td>").format(
                            bg, numc, esc(u"{0}".format(value)), muted, esc(label))

            def bar(label, count, maxc, color, denom):
                w = int(190.0 * count / maxc) if maxc > 0 else 0
                if count > 0 and w < 6:
                    w = 6
                pct = u"  <font color='{0}'>({1}%)</font>".format(
                    muted, int(round(100.0 * count / denom))) if denom else u""
                return (u"<tr><td><font size='3'>{0}</font></td>"
                        u"<td><table cellspacing='0' cellpadding='0'><tr>"
                        u"<td bgcolor='{1}' width='{2}'>&nbsp;</td>"
                        u"<td>&nbsp;<b>{3}</b>{4}</td></tr></table></td></tr>").format(
                            esc(label), color, w, count, pct)

            def card(title, inner):
                return (u"<table width='100%' cellspacing='0' cellpadding='5' border='0'>"
                        u"<tr><td bgcolor='{0}'><font color='{1}'><b>{2}</b></font></td></tr>"
                        u"<tr><td bgcolor='{3}'>{4}</td></tr></table><br>").format(
                            head_bg, acc, esc(title), card_bg, inner)

            H = []

            # header band + risk pill
            meta = []
            if model:
                meta.append(u"Model: {0} / {1}".format(esc(prov), esc(model)))
            elif prov:
                meta.append(u"Model: {0}".format(esc(prov)))
            meta.append(u"Updated " + time.strftime("%H:%M:%S"))
            meta.append(u"Hosts {0}".format(len(hosts)))
            if req_analyzed is not None:
                meta.append(u"Requests {0}".format(req_analyzed))
            pill = (u"<table cellspacing='0' cellpadding='2' border='0'><tr>"
                    u"<td bgcolor='{0}'>&nbsp;<font color='#ffffff'><b>{1}</b></font>&nbsp;"
                    u"</td></tr></table>").format(risk_c, esc(risk_lbl))
            H.append(
                u"<table width='100%' cellspacing='0' cellpadding='6' border='0'>"
                u"<tr><td bgcolor='{0}'><font size='5' color='{1}'><b>VeriHunt</b></font>"
                u"&nbsp;&nbsp;<font color='{2}'>Security Posture</font></td>"
                u"<td bgcolor='{0}' align='right'><font size='2' color='{2}'>RISK</font>"
                u"&nbsp;{3}</td></tr></table>".format(head_bg, acc, muted, pill))
            # meta parts are already escaped where needed (Model prov/model); do NOT
            # re-escape the joined string or '&' in a model id would double-encode.
            H.append(u"<font size='2' color='{0}'>{1}</font><br><br>".format(
                muted, u"   " + u"  |  ".join(meta)))

            # KPI tiles
            H.append(u"<table cellspacing='4' cellpadding='4' border='0'><tr>")
            H.append(tile("FINDINGS", total, acc, tint("n")))
            H.append(tile("HIGH", sev["High"], SEVC["High"], tint("High")))
            H.append(tile("MEDIUM", sev["Medium"], SEVC["Medium"], tint("Medium")))
            H.append(tile("LOW", sev["Low"], SEVC["Low"], tint("Low")))
            H.append(tile("CONFIRMED", confirmed, "#2e7d32", tint("Confirmed")))
            H.append(tile("POTENTIAL", potential, "#E65100", tint("Potential")))
            H.append(tile("HUNT", hunt_total, acc, tint("n")))
            H.append(tile("TOKENS", num(tok), (muted if tok == 0 else "#1E88E5"), tint("n")))
            H.append(u"</tr></table><br>")

            # two columns: severity | AI hunt coverage
            if total:
                sv = [u"<table cellspacing='0' cellpadding='1'>"]
                for s in ("High", "Medium", "Low", "Information"):
                    sv.append(bar(s, sev[s], maxsev, SEVC[s], total))
                sv.append(u"</table>")
                sv.append(u"<font size='2' color='{0}'>Total {1} active"
                          u"{2}</font>".format(
                              muted, total,
                              (u"  |  {0} false positive".format(fp) if fp else u"")))
                sev_inner = u"".join(sv)
            else:
                sev_inner = (u"<font color='{0}'><i>No findings yet. Analyze a request "
                             u"or click Load Demo in Results.</i></font>".format(muted))

            if hunt_total:
                hv = [u"<font size='3'>Candidates <b>{0}</b> &nbsp; Triaged <b>{1}</b>"
                      u" ({2}%)</font><br><br>".format(
                          hunt_total, triaged,
                          int(round(100.0 * triaged / hunt_total)) if hunt_total else 0)]
                chips = []
                for st in ("LIKELY", "POSSIBLE", "Potential", "UNLIKELY"):
                    if hunt_status.get(st):
                        chips.append(u"<font color='{0}'><b>{1}</b> {2}</font>".format(
                            VC.get(st, muted), hunt_status[st], st))
                hv.append(u" &nbsp;|&nbsp; ".join(chips) if chips else u"")
                top = sorted(hunt_cls.items(), key=lambda kv: -kv[1])[:5]
                if top:
                    hv.append(u"<br><br><font size='2' color='{0}'>Top classes:</font><br>".format(muted))
                    hv.append(u", ".join(u"{0} <b>{1}</b>".format(esc(c), n) for c, n in top))
                hunt_inner = u"".join(hv)
            else:
                hunt_inner = (u"<font color='{0}'><i>No AI Hunt candidates yet. Enable "
                              u"Passive (Proxy) and browse, or press Scan History.</i>"
                              u"</font>".format(muted))

            H.append(
                u"<table width='100%' cellspacing='0' cellpadding='0' border='0'><tr>"
                u"<td valign='top' width='49%' bgcolor='{0}'>"
                u"<table width='100%' cellpadding='5'><tr><td bgcolor='{1}'>"
                u"<font color='{2}'><b>Findings by Severity</b></font></td></tr>"
                u"<tr><td>{3}</td></tr></table></td>"
                u"<td width='2%'>&nbsp;</td>"
                u"<td valign='top' width='49%' bgcolor='{0}'>"
                u"<table width='100%' cellpadding='5'><tr><td bgcolor='{1}'>"
                u"<font color='{2}'><b>AI Hunt Coverage</b></font></td></tr>"
                u"<tr><td>{4}</td></tr></table></td>"
                u"</tr></table><br>".format(card_bg, head_bg, acc, sev_inner, hunt_inner))

            # top affected hosts
            if hosts:
                rows = sorted(hosts.items(),
                              key=lambda kv: -(kv[1]["High"] * 100 + kv[1]["Medium"] * 10 + kv[1]["Low"]))[:5]
                t = [u"<table width='100%' cellspacing='0' cellpadding='4'>"
                     u"<tr bgcolor='{0}'><td><b>Host</b></td>"
                     u"<td align='center'><font color='{1}'><b>High</b></font></td>"
                     u"<td align='center'><font color='{2}'><b>Med</b></font></td>"
                     u"<td align='center'><font color='{3}'><b>Low</b></font></td>"
                     u"<td align='center'><b>Total</b></td></tr>".format(
                         head_bg, SEVC["High"], SEVC["Medium"], SEVC["Low"])]
                for host, d in rows:
                    tt = d["High"] + d["Medium"] + d["Low"] + d["Information"]
                    t.append(u"<tr><td><font size='3'>{0}</font></td>"
                             u"<td align='center'>{1}</td><td align='center'>{2}</td>"
                             u"<td align='center'>{3}</td><td align='center'><b>{4}</b></td></tr>".format(
                                 esc(host), d["High"], d["Medium"], d["Low"], tt))
                t.append(u"</table>")
                H.append(card("Top Affected Hosts", u"".join(t)))

            # footer: memory + disclaimer
            foot = (u"<font size='3'>Cross-Scan Memory: <b>{0}</b> false positive(s), "
                    u"<b>{1}</b> confirmed <font color='{2}'>(persisted per host)</font>."
                    u"</font>".format(mem_fp, mem_cf, muted))
            if tok > 0:
                foot += (u"<br><font size='2' color='{0}'>Tokens this session: {1} "
                         u"({2} calls; last {3}).</font>".format(
                             muted, num(tok), usage.get("calls", 0), num(usage.get("last_total", 0))))
            foot += (u"<br><font size='2' color='{0}'><i>Passive tool — AI Hunt candidates "
                     u"are POTENTIAL until validated.</i></font>".format(muted))
            H.append(card("Memory & Session", foot))

            self._dash_view.setText(u"<html><body>" + u"".join(H) + u"</body></html>")
            self._dash_view.setCaretPosition(0)
        except Exception as ex:
            try:
                self._dash_view.setText(u"<html><body>Dashboard error: " +
                                        _html_escape(str(ex)) + u"</body></html>")
            except Exception:
                pass

    # -- about tab -------------------------------------------------------------

    def _build_about(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))

        content = _WidthTrackingPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        _mono   = Font("Monospaced", Font.PLAIN, 11)
        _mono_b = Font("Monospaced", Font.BOLD,  11)
        _sans   = Font("SansSerif",  Font.PLAIN, 11)
        _sans_b = Font("SansSerif",  Font.BOLD,  12)
        _big    = Font("SansSerif",  Font.BOLD,  15)
        _orange = Color(0xFF6B35)
        # Theme-aware muted colour so notes stay readable on the dark theme
        # (the old fixed 0x555555 was nearly invisible on dark backgrounds).
        _grey   = _theme().muted

        def _lbl(text, font=_sans, fg=None, top=0, bot=0):
            l = JLabel(text)
            l.setFont(font)
            if fg:
                l.setForeground(fg)
            if top or bot:
                l.setBorder(BorderFactory.createEmptyBorder(top, 0, bot, 0))
            l.setAlignmentX(0.0)
            return l

        def _sep():
            p = JPanel()
            p.setMaximumSize(Dimension(9999, 1))
            p.setBackground(Color(0xDDDDDD))
            p.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0))
            p.setAlignmentX(0.0)
            return p

        def _wrap(text, indent=6):
            """A read-only, transparent, word-wrapping paragraph that fills the
            width (uses the L&F default text colour so it reads on light + dark)."""
            ta = JTextArea(text)
            ta.setLineWrap(True)
            ta.setWrapStyleWord(True)
            ta.setEditable(False)
            ta.setOpaque(False)
            ta.setFocusable(False)
            ta.setFont(_sans)
            ta.setBorder(BorderFactory.createEmptyBorder(0, indent, 6, 0))
            ta.setAlignmentX(0.0)
            ta.setMaximumSize(Dimension(32767, 32767))
            return ta

        # ---- App header ----
        content.add(_lbl("VeriHunt", _big, _orange, top=2, bot=2))
        content.add(_lbl("AI-Powered Security Analysis for Burp Suite", _sans_b, _grey))
        content.add(_lbl("Part of the Agentic Web Pentest project  |  Jython 2.7  |  Burp Suite Extension", _sans, _grey, bot=6))
        content.add(_sep())

        # ---- About ----
        content.add(_lbl("About", _sans_b, _orange, top=6, bot=2))
        content.add(_wrap(
            "VeriHunt integrates large language models directly into Burp Suite to "
            "perform automated security analysis on HTTP requests and responses. Findings "
            "are structured, severity-classified, and registered as native Burp scan "
            "issues.\n\n"
            "Right-click any request in Proxy / Repeater / Scanner -> VeriHunt -> "
            "Analyze with AI. Single or bulk requests are supported; bulk scans use "
            "concurrent workers.\n\n"
            "The AI Hunt tab adds passive parameter hunting with on-demand AI triage. See "
            "the Features section below for everything the extension does."))
        content.add(_sep())

        # ---- Features ----
        content.add(_lbl("Features", _sans_b, _orange, top=6, bot=2))

        def _feat(title, lines):
            # Orange title + a single wrapping paragraph (fills width, wraps, and
            # uses the L&F default text colour so it reads on light and dark).
            content.add(_lbl("  > " + title, _sans_b, _orange, top=8, bot=1))
            content.add(_wrap(" ".join(lines), indent=14))

        _feat("AI Analysis (Results tab)", [
            "Right-click a request -> VeriHunt -> Analyze with AI. Single, or BATCH:",
            "select many in Proxy history to queue them ('Analyze N requests with AI')",
            "with concurrent workers, live progress, and a Stop button.",
            "Optional Self-verify second pass downgrades unproven findings to 'Potential'",
            "and drops refuted ones (anti-hallucination). Re-analysing the same endpoint no",
            "longer produces duplicate findings -- results are de-duplicated by severity +",
            "URL + parameter (host-level issues like CORS/CSP/CSRF are merged, distinct",
            "endpoints/parameters kept). Findings register as native Burp scan issues; view",
            "Advisory + Analyzed Request/Response, Toggle False Positive, and ask follow-ups",
            "in the AI Assistant chat.",
        ])

        _feat("AI Hunt (passive heuristics + enhanced AI triage)", [
            "HUNT-style scanner: flags suspicious parameters by name/value across 12 vuln",
            "classes (SQLi, XSS, LFI/Path Traversal, SSRF, IDOR/BOLA, Command Injection,",
            "SSTI, XXE, Open Redirect, Deserialization, Mass-Assignment, Debug).",
            "Every user-controllable parameter is surfaced: names/values that match a class",
            "are flagged as that class; anything else is listed as 'Other Parameter (review)'",
            "(Information) so a parameterised request is never silently empty (noise tokens",
            "like CSRF/session/captcha are skipped).",
            "Passive: tick 'Passive (Proxy)' -> flags params as you browse. Instant & FREE",
            "-- no payloads, no AI; static assets skipped, runs off the proxy thread so it",
            "stays light (default OFF). Candidates are POTENTIAL (heuristic, NOT confirmed)",
            "until you validate them.",
            "Scan History: passive only sees NEW traffic after it's enabled, so press",
            "'Scan History' to run the heuristics over Burp's existing Proxy history",
            "retroactively (honours 'Scope only', skips static assets) -- use it when",
            "candidates are missing for a target you already browsed.",
            "Pick a candidate to see why + methodology + the real Request/Response viewer;",
            "right-click -> Deep Analyze (AI) / Send to Repeater / Send to Intruder / Copy URL.",
            "Triage (AI) [on-demand]: evidence-grounded -- feeds reflection, SQL-error,",
            "stack-trace, status and content-type signals to the model, which returns a",
            "verdict (LIKELY/POSSIBLE/UNLIKELY) + confidence % + cited evidence + tailored",
            "payloads + next step. Triage Selected or Triage All; grouped per endpoint to",
            "control token spend.",
            "Deep Analyze (AI): right-click a candidate to run the FULL Results analysis",
            "pipeline (deep AI + self-verify) on that exact request -- heuristic -> deep dive.",
            "AI Discover: proposes issues the parameter heuristics MISS (access control,",
            "business logic, sensitive data, headers) from the endpoint -- rows tagged 'AI:'.",
            "Selecting a candidate shows an Evidence excerpt: the parameter highlighted in",
            "the request and, if reflected, the value highlighted in the response.",
        ])

        _feat("Reports & Export", [
            "Export JSON (all findings, machine-readable). Export Report -> HTML (styled,",
            "self-contained, printable) or Markdown -- grouped by severity with PoC +",
            "remediation, false-positives listed separately. Right-click a finding ->",
            "Copy as Markdown to paste into a ticket or report.",
        ])

        _feat("Cross-Scan Memory", [
            "Remembers, per host, the findings you mark False Positive and the ones the AI",
            "confirmed -- persisted across restarts. On later analyses of the same host it",
            "feeds this to the model (skip known FPs, stay aware of prior confirmations) and",
            "auto-drops findings you already dismissed. Toggle with 'Memory' in Settings;",
            "'Clear Memory' resets it.",
        ])

        _feat("Dashboard & Demo Mode", [
            "Dashboard tab: findings by severity, AI Hunt candidates by status + class,",
            "cross-scan memory and token totals -- refreshes when you open it.",
            "Load Demo (Results header): loads sample findings + AI Hunt candidates with",
            "no API/internet, to showcase the full workflow (great for a live demo).",
        ])

        _feat("Token Usage Tracker", [
            "The Results header shows tokens for the last call + the running session total",
            "and call count (from each provider's reported usage) -- useful for TPM-limited",
            "free tiers (e.g. Groq) and paid quotas. Resets on Clear All.",
        ])

        _feat("Providers, Models & Theme", [
            "12 providers (listed below), each with API key, model, base URL, max tokens and",
            "sampling controls, plus 'Test & Detect Models' to pull the live model list.",
            "Model IDs are current defaults but editable. Theme: Auto / Light / Dark",
            "(top of the Settings tab), applied live across all tabs.",
        ])
        content.add(_sep())

        # ---- Providers ----
        content.add(_lbl("Supported Providers", _sans_b, _orange, top=6, bot=2))
        content.add(_lbl("  Anthropic   --  Claude 5 family (Sonnet 5, Opus 5, Haiku 4.5, Fable 5.1)", _mono))
        content.add(_lbl("  OpenAI      --  GPT-5.x, GPT-4.1/4o, o3/o4-mini", _mono))
        content.add(_lbl("  OpenRouter  --  400+ models via unified API (free & paid)", _mono))
        content.add(_lbl("  Gemini      --  Google Gemini 3.x / 2.5 (pro, flash, flash-lite)", _mono))
        content.add(_lbl("  Ollama      --  Any local model (qwen, llama, mistral, deepseek)", _mono))
        content.add(_lbl("  DeepSeek    --  deepseek-chat (V-series), deepseek-reasoner", _mono))
        content.add(_lbl("  Kimi        --  Moonshot kimi-latest / kimi-k2 / moonshot-v1-*", _mono))
        content.add(_lbl("  Mistral     --  mistral-large / medium / small, codestral", _mono))
        content.add(_lbl("  Groq        --  llama-3.3/4, gpt-oss, kimi-k2 (very fast inference)", _mono))
        content.add(_lbl("  xAI (Grok)  --  grok-4.6 / 4.5 / 4.3", _mono))
        content.add(_lbl("  OpenCode Zen--  gateway (claude-sonnet-5, gpt-5.1, kimi-k3, ...)", _mono))
        content.add(_lbl("  Z.AI (GLM)  --  glm-4.6 (flagship) / glm-4.5 / -air / -flash", _mono))
        content.add(_lbl("  Z.AI Coding Plan --  SAME models; use this entry for GLM Coding", _mono))
        content.add(_lbl("                  Plan keys (endpoint .../api/coding/paas/v4)", _mono))
        content.add(_lbl("  Custom      --  your OpenAI-compatible gateway (LiteLLM, Azure,", _mono))
        content.add(_lbl("                  private proxy): set Base URL + Model + key", _mono))
        content.add(_lbl("  Every provider's Base URL is editable -- point VeriHunt at an", _sans, _grey, top=2))
        content.add(_lbl("  internal LLM gateway without code changes. Model IDs move fast --", _sans, _grey))
        content.add(_lbl("  use 'Test & Detect Models' for the live list.", _sans, _grey))
        content.add(_sep())

        # ---- Model reference table ----
        content.add(_lbl("Model Output Tokens & Context Window", _sans_b, _orange, top=6, bot=2))

        sections = [
            ("Anthropic", [
                ("  claude-sonnet-5          ", "out: 64k ", "ctx: 200k", "Best balance speed + quality  [Recommended]"),
                ("  claude-opus-5            ", "out: 32k ", "ctx: 200k", "Highest accuracy, slower"),
                ("  claude-haiku-4-5         ", "out: 16k ", "ctx: 200k", "Fastest, lowest cost"),
                ("  claude-fable-5-1         ", "out: varies", "ctx: 200k", "Lightweight Claude 5"),
                ("  claude-opus-4-8          ", "out: 32k ", "ctx: 200k", "Previous flagship, still strong"),
            ]),
            ("OpenAI", [
                ("  gpt-5.1                  ", "out: varies", "ctx: 400k", "Latest general model  [Recommended]"),
                ("  gpt-5                    ", "out: varies", "ctx: 400k", "GPT-5 base"),
                ("  gpt-5-mini               ", "out: varies", "ctx: 400k", "Cheaper, fast, good for bulk"),
                ("  gpt-4.1                  ", "out: 32k ", "ctx:   1M", "Large-context general model"),
                ("  gpt-4o                   ", "out: 16k ", "ctx: 128k", "Previous gen, cost-effective"),
                ("  o3 / o4-mini             ", "out: varies", "ctx: 200k", "Reasoning models"),
            ]),
            ("OpenRouter", [
                ("  Free models (append :free)        ", "out: varies", "ctx: varies", "Check model page on openrouter.ai/models"),
                ("  Paid models (claude/gpt/gemini)   ", "out: varies", "ctx: varies", "Same limits as direct provider"),
            ]),
            ("Gemini", [
                ("  gemini-2.5-flash         ", "out:  8k ", "ctx:   1M", "Fast, free tier  [Recommended]"),
                ("  gemini-2.5-pro           ", "out: 65k ", "ctx:   1M", "Best 2.5 quality"),
                ("  gemini-2.5-flash-lite    ", "out:  8k ", "ctx:   1M", "Lightest, cheapest"),
                ("  gemini-3-flash-preview   ", "out: varies", "ctx:   1M", "Gemini 3 fast (preview)"),
                ("  gemini-3.1-pro-preview   ", "out: varies", "ctx:   1M", "Gemini 3 flagship (preview)"),
            ]),
            ("Ollama (local)", [
                ("  qwen2.5-coder:7b       ", "~4GB RAM ", "ctx:  4k ", "Best for code/vuln analysis  [Recommended]"),
                ("  qwen2.5-coder:14b      ", "~8GB RAM ", "ctx:  8k ", "Better reasoning, needs GPU"),
                ("  llama3.2:3b            ", "~2GB RAM ", "ctx:  8k ", "Lightweight, fast on CPU"),
                ("  llama3.1:8b            ", "~5GB RAM ", "ctx: 128k", "Good general + security"),
                ("  deepseek-coder-v2:16b  ", "~10GB RAM", "ctx:  32k", "Strong code reasoning"),
                ("  mistral:7b             ", "~4GB RAM ", "ctx:  32k", "Balanced, good instruction"),
            ]),
            ("DeepSeek", [
                ("  deepseek-chat          ", "out:  8k ", "ctx:  64k", "V3, general purpose  [Recommended]"),
                ("  deepseek-reasoner      ", "out:  8k ", "ctx:  64k", "R1, chain-of-thought reasoning"),
            ]),
            ("Kimi (Moonshot)", [
                ("  kimi-latest            ", "out: varies", "ctx: 256k", "Auto-latest Kimi  [Recommended]"),
                ("  kimi-k2-0905-preview   ", "out: varies", "ctx: 256k", "Kimi K2 (strong agentic)"),
                ("  moonshot-v1-128k       ", "out:  8k ", "ctx: 128k", "Legacy large context"),
                ("  moonshot-v1-8k / -32k  ", "out:  8k ", "ctx: 8k/32k", "Legacy smaller contexts"),
            ]),
            ("Mistral", [
                ("  mistral-large-latest   ", "out:  8k ", "ctx: 128k", "Best quality  [Recommended]"),
                ("  mistral-medium-latest  ", "out:  8k ", "ctx: 128k", "Balanced quality/cost"),
                ("  mistral-small-latest   ", "out:  8k ", "ctx: 128k", "Fast, cheaper"),
                ("  codestral-latest       ", "out:  8k ", "ctx: 256k", "Code-specialised"),
            ]),
            ("Groq", [
                ("  llama-3.3-70b-versatile", "out:  8k ", "ctx: 128k", "Very fast inference  [Recommended]"),
                ("  llama-3.1-8b-instant   ", "out:  8k ", "ctx: 128k", "Fastest, good for bulk"),
                ("  openai/gpt-oss-120b    ", "out: varies", "ctx: 128k", "Open-weight, on Groq"),
                ("  moonshotai/kimi-k2-instruct", "out: varies", "ctx: 256k", "Kimi K2 on Groq"),
            ]),
            ("xAI (Grok)", [
                ("  grok-4.6               ", "out: varies", "ctx: 256k", "Latest flagship  [Recommended]"),
                ("  grok-4.5               ", "out: varies", "ctx: 256k", "Previous flagship"),
                ("  grok-4.3               ", "out: varies", "ctx: 256k", "Extended-context variant"),
            ]),
            ("Z.AI (GLM)", [
                ("  glm-4.6                ", "out: 128k", "ctx: 200k", "Flagship; strong agentic/coding  [Recommended]"),
                ("  glm-4.5                ", "out:  96k", "ctx: 128k", "Previous flagship"),
                ("  glm-4.5-air            ", "out:  96k", "ctx: 128k", "Lighter, faster, cheaper"),
                ("  glm-4.5-flash          ", "out:  96k", "ctx: 128k", "Free tier; good for bulk scans"),
            ]),
        ]

        for provider, rows in sections:
            ph = _lbl("  " + provider, _mono_b, _orange, top=4)
            content.add(ph)
            hdr = _lbl("  {0:<32} {1:<12} {2:<10} {3}".format(
                "Model", "Output", "Context", "Notes"), _mono_b, _grey)
            content.add(hdr)
            for model, out, ctx, note in rows:
                content.add(_lbl("  {0:<32} {1:<12} {2:<10} {3}".format(
                    model, out, ctx, note), _mono))

        content.add(_sep())

        # ---- Max Tokens & Concurrent reference ----
        content.add(_lbl("Max Tokens & Concurrent -- Quick Reference", _sans_b, _orange, top=6, bot=2))
        content.add(_lbl("  These settings are in the Settings tab (top bar). Tune per provider:", _sans, _grey, bot=2))

        tok_sections = [
            ("Anthropic", [
                ("  claude-sonnet-5    ", "4096-8192", "3-5", "Best quality; handles large responses"),
                ("  claude-opus-5      ", "4096-8192", "2-3", "Slower; lower concurrent to avoid timeout"),
                ("  claude-haiku-4-5   ", "2048-4096", "5-8", "High concurrency OK, very fast"),
            ]),
            ("OpenAI", [
                ("  gpt-5.1            ", "4096-8192", "3-5", "Balanced speed + quality"),
                ("  gpt-5-mini         ", "4096-8192", "5-8", "Best for bulk; cheap + fast"),
                ("  o3 / o4-mini       ", "4096",      "1-2", "Slow; reasoning tokens billed extra"),
            ]),
            ("OpenRouter", [
                ("  Free models        ", "<=2048",    "1-2", "Hard cap; >2048 causes Error 402"),
                ("  Paid models        ", "4096-8192", "3-5", "Same limits as direct provider"),
            ]),
            ("Gemini", [
                ("  gemini-2.5-pro     ", "4096-8192", "3-5", "Free: 15 req/min; paid: 360 req/min"),
                ("  gemini-2.5-flash   ", "2048-4096", "3-5", "Fast; generous free tier"),
                ("  gemini-3.1-pro-preview", "4096-8192", "2-3", "Newest; preview rate limits"),
            ]),
            ("Ollama (local)", [
                ("  qwen2.5-coder:7b   ", "<=2048",    "1",   "Single thread; GPU bottleneck"),
                ("  qwen2.5-coder:14b  ", "<=2048",    "1",   "Needs GPU; CPU too slow for concurrent"),
                ("  llama3.1:8b        ", "<=2048",    "1",   "128k ctx but slow without GPU"),
            ]),
            ("DeepSeek", [
                ("  deepseek-chat      ", "4096-8192", "3-5", "Cheap; good general analysis"),
                ("  deepseek-reasoner  ", "4096",      "1-2", "Slow; reasoning tokens billed extra"),
            ]),
            ("Kimi / Moonshot", [
                ("  kimi-latest        ", "2048-4096", "3-5", "Auto-latest Kimi"),
                ("  kimi-k2-0905-preview", "2048-4096", "2-3", "Strong agentic; higher latency"),
            ]),
            ("Mistral", [
                ("  mistral-large-latest", "4096-8192", "3-5", "Strong general reasoning"),
                ("  mistral-small-latest", "4096",      "5-8", "Cheap + fast for bulk"),
            ]),
            ("Groq", [
                ("  llama-3.3-70b      ", "4096-8192", "5-8", "Extremely fast; high concurrency OK"),
                ("  llama-3.1-8b       ", "4096",      "8-10","Fastest; best for bulk scans"),
            ]),
            ("xAI (Grok)", [
                ("  grok-4.6           ", "4096-8192", "3-5", "General purpose flagship"),
            ]),
            ("Z.AI (GLM)", [
                ("  glm-4.6            ", "4096-8192", "3-5", "Flagship; great for deep analysis"),
                ("  glm-4.5-flash      ", "<=4096",     "5-8", "Free tier; fast for bulk scans"),
            ]),
        ]

        for provider, rows in tok_sections:
            ph = _lbl("  " + provider, _mono_b, _orange, top=4)
            content.add(ph)
            hdr = _lbl("  {0:<22} {1:<12} {2:<10} {3}".format(
                "Model", "Max Tokens", "Concurrent", "Notes"), _mono_b, _grey)
            content.add(hdr)
            for model, tok, conc, note in rows:
                content.add(_lbl("  {0:<22} {1:<12} {2:<10} {3}".format(
                    model, tok, conc, note), _mono))

        content.add(_sep())

        # ---- Links ----
        content.add(_lbl("Links", _sans_b, _orange, top=6, bot=2))
        content.add(_lbl("  Anthropic API key : console.anthropic.com", _mono))
        content.add(_lbl("  OpenAI API key    : platform.openai.com", _mono))
        content.add(_lbl("  OpenRouter key    : openrouter.ai/keys", _mono))
        content.add(_lbl("  Gemini API key    : aistudio.google.com/apikey", _mono))
        content.add(_lbl("  Ollama download   : ollama.com", _mono))
        content.add(_lbl("  Browse OR models  : openrouter.ai/models", _mono))
        content.add(_lbl("  DeepSeek key      : platform.deepseek.com", _mono))
        content.add(_lbl("  Kimi/Moonshot key : platform.moonshot.ai", _mono))
        content.add(_lbl("  Mistral key       : console.mistral.ai", _mono))
        content.add(_lbl("  Groq key          : console.groq.com/keys", _mono))
        content.add(_lbl("  xAI (Grok) key    : console.x.ai", _mono))
        content.add(_lbl("  Z.AI (GLM) key    : z.ai  (open.bigmodel.cn for mainland)", _mono, bot=6))

        # content is a width-tracking Scrollable, so use it as the scroll view
        # directly -- this makes paragraphs fill and wrap to the panel width.
        scroll = JScrollPane(content)
        scroll.getVerticalScrollBar().setUnitIncrement(16)
        scroll.setBorder(None)
        outer.add(scroll, BorderLayout.CENTER)
        return outer

    # -- button styling --------------------------------------------------------

    @staticmethod
    def _style_btn(btn, bg, fg=None):
        """Apply a flat-look coloured background to a JButton."""
        btn.setBackground(bg)
        btn.setForeground(fg if fg else Color.WHITE)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        return btn

    def _skin_btn(self, btn, role):
        """Solid-fill button whose colours track the active theme. Registered so
        _apply_theme_now() re-skins it live when the user flips Light/Dark."""
        bg, fg = _btn_colors(role)
        self._style_btn(btn, bg, fg)
        if not hasattr(self, "_themed_btns"):
            self._themed_btns = []
        self._themed_btns.append(("fill", btn, role))
        return btn

    def _skin_link_btn(self, btn, kind):
        """Borderless text button (keeps the L&F chrome) with a theme-aware text
        colour, also registered for live re-skinning."""
        btn.setForeground(_link_color(kind))
        if not hasattr(self, "_themed_btns"):
            self._themed_btns = []
        self._themed_btns.append(("link", btn, kind))
        return btn

    def _reskin_buttons(self):
        """Re-apply theme-aware colours to every registered button. Called from
        _apply_theme_now so buttons don't keep stale colours after a theme switch."""
        for entry in getattr(self, "_themed_btns", []):
            try:
                kind, btn, role = entry
                if kind == "fill":
                    bg, fg = _btn_colors(role)
                    btn.setBackground(bg)
                    btn.setForeground(fg)
                else:
                    btn.setForeground(_link_color(role))
                btn.repaint()
            except Exception:
                pass

    # -- getters for Scanner ---------------------------------------------------

    def get_provider(self):
        return str(self._provider_combo.getSelectedItem())

    def get_provider_settings(self):
        base = {
            "anthropic_key":    self._ant_key.getText(),
            "anthropic_model":  str(self._ant_model.getSelectedItem()),
            "openai_key":       self._oai_key.getText(),
            "openai_model":     str(self._oai_model.getSelectedItem()),
            "openrouter_key":   self._or_key.getText(),
            "openrouter_model": self._or_model.getText(),
            "gemini_key":       self._gem_key.getText(),
            "gemini_model":     str(self._gem_model.getSelectedItem()),
            "ollama_mode":      "cloud" if str(self._ollama_mode.getSelectedItem()) == "Ollama Cloud" else "local",
            "ollama_base_url":  self._ollama_url.getText(),
            "ollama_api_key":   self._ollama_key.getText(),
            "ollama_model":     self._ollama_model.getText(),
        }
        # OpenAI-compatible providers: expose <prefix>_key, <prefix>_model and
        # <prefix>_base, matching the keys call_api() reads via _settings_key().
        for key_prefix, (key_f, model_f, _s, base_f) in self._oai_fields.items():
            base["{0}_key".format(key_prefix)]   = key_f.getText()
            base["{0}_model".format(key_prefix)] = model_f.getText()
            base["{0}_base".format(key_prefix)]  = base_f.getText().strip()
        return base

    def get_max_tokens(self):
        try:
            return int(self._max_tokens.getText())
        except Exception:
            return 4096

    def get_max_concurrent(self):
        try:
            v = int(self._max_concurrent.getText())
            return max(1, min(v, 10))
        except Exception:
            return 2

    def get_self_verify(self):
        try:
            return self._self_verify_chk.isSelected()
        except Exception:
            return False

    def get_use_memory(self):
        try:
            return self._memory_chk.isSelected()
        except Exception:
            return True

    def _clear_memory(self):
        scanner = getattr(self, "_scanner", None)
        if scanner is None or not hasattr(scanner, "memory"):
            self._status_lbl.setText("Memory not available.")
            return
        try:
            fp, cf = scanner.memory.stats()
            scanner.memory.clear()
            self._status_lbl.setText(
                "Cross-scan memory cleared ({0} FP, {1} confirmed removed).".format(fp, cf))
        except Exception as ex:
            self._status_lbl.setText("Clear memory failed: " + str(ex))

    def get_scope_only(self):
        return self._scope_only_chk.isSelected()

    def get_prompt_template(self):
        return self._prompt_area.getText()

    # -- queue management (bulk scan) -----------------------------------------

    def start_queue(self, total):
        """Called when a bulk scan begins. total = number of requests queued."""
        self._cancelled     = False
        self._pending_count = total
        self._queue_total   = total
        self._stop_btn.setEnabled(True)
        self._status_lbl.setText("Batch analysis: {0} request(s) queued...".format(total))
        self._update_queue_lbl()

    def decrement_queue(self):
        """Called by each worker when it finishes (success or error)."""
        self._pending_count = max(0, self._pending_count - 1)
        if self._pending_count == 0:
            if not self._placeholders:
                self._stop_btn.setEnabled(False)
            total = getattr(self, "_queue_total", 0)
            self._queue_lbl.setText("")
            if total > 1:
                self._status_lbl.setText("Batch complete: {0} request(s) analyzed.".format(total))
        else:
            self._update_queue_lbl()

    def _update_queue_lbl(self):
        total = getattr(self, "_queue_total", 0)
        if self._pending_count > 0 and total > 0:
            done = max(0, total - self._pending_count)
            self._queue_lbl.setText(
                "| Analyzing {0}/{1}  ({2} pending)".format(done, total, self._pending_count))
        elif self._pending_count > 0:
            self._queue_lbl.setText("| Queue: {0} pending".format(self._pending_count))

    def _stop_analysis(self):
        """Stop any in-progress single or bulk analysis."""
        self._cancelled = True
        self._stop_btn.setEnabled(False)
        self._queue_lbl.setText("| Stopped")
        self._status_lbl.setText("Analysis stopped.")

    def is_cancelled(self):
        return self._cancelled

    def _finding_records(self):
        """Extract every finding as a plain dict (shared by JSON + report export)."""
        records = []
        for key, issue in self._all_findings.items():
            if issue is None:
                continue
            records.append({
                "name":       issue.getIssueName(),
                "severity":   issue.getSeverity(),
                "confidence": issue.getConfidence(),
                "false_positive": key.startswith("[FP]"),
                "url":        str(issue.getUrl()),
                "cvss":       issue.getCvssScore() if hasattr(issue, "getCvssScore") else "",
                "cve":        issue.getCve()       if hasattr(issue, "getCve")       else "",
                "parameter":  issue.getParameter() if hasattr(issue, "getParameter") else "",
                "detail":     issue.getDetailMarkdown()     if hasattr(issue, "getDetailMarkdown")     else "",
                "background": issue.getBackgroundMarkdown() if hasattr(issue, "getBackgroundMarkdown") else "",
                "remediation":issue.getRemediationMarkdown() if hasattr(issue, "getRemediationMarkdown") else "",
            })
        return records

    def _report_meta(self):
        import time
        return {
            "tool": "VeriHunt",
            "version": "1.6.0",
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _export_json(self):
        """Export all current findings to a JSON file chosen by the user."""
        if not self._all_findings:
            self._status_lbl.setText("No findings to export.")
            return
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Export Findings as JSON")
            chooser.setSelectedFile(
                __import__("java.io", fromlist=["File"]).File("agenticburp_findings.json"))
            ret = chooser.showSaveDialog(None)
            if ret != JFileChooser.APPROVE_OPTION:
                return

            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".json"):
                path += ".json"

            records = self._finding_records()
            active = sum(1 for r in records if not r["false_positive"])

            with open(path, "w") as f:
                json.dump({"findings": records,
                           "total": len(records),
                           "total_active": active,
                           "total_false_positive": len(records) - active}, f, indent=2)

            self._status_lbl.setText("Exported {0} finding(s) ({1} active) to {2}".format(
                len(records), active, path))
            self._log("Exported {0} findings to {1}".format(len(records), path))

        except Exception as ex:
            self._status_lbl.setText("Export failed: " + str(ex))
            self._log("Export error: " + str(ex))

    def _export_report(self, fmt):
        """Export all findings as a professional report. fmt is 'html' or 'md'."""
        if not self._all_findings:
            self._status_lbl.setText("No findings to export.")
            return
        try:
            ext  = ".html" if fmt == "html" else ".md"
            label = "HTML" if fmt == "html" else "Markdown"
            chooser = JFileChooser()
            chooser.setDialogTitle("Export {0} Report".format(label))
            chooser.setSelectedFile(
                __import__("java.io", fromlist=["File"]).File("agenticburp_report" + ext))
            ret = chooser.showSaveDialog(None)
            if ret != JFileChooser.APPROVE_OPTION:
                return

            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(ext):
                path += ext

            records = self._finding_records()
            meta = self._report_meta()
            content = (_build_html_report(records, meta) if fmt == "html"
                       else _build_md_report(records, meta))

            # Write UTF-8 explicitly (Jython open() defaults to platform encoding).
            import codecs
            with codecs.open(path, "w", "utf-8") as f:
                f.write(content)

            active = sum(1 for r in records if not r["false_positive"])
            self._status_lbl.setText("Exported {0} report ({1} finding(s)) to {2}".format(
                label, active, path))
            self._log("Exported {0} report to {1}".format(label, path))

        except Exception as ex:
            self._status_lbl.setText("Report export failed: " + str(ex))
            self._log("Report export error: " + str(ex))

    def _copy_finding_markdown(self):
        """Copy the currently selected finding to the clipboard as Markdown."""
        try:
            key = self._result_list.getSelectedValue()
            if not key or key not in self._all_findings:
                self._status_lbl.setText("Select a finding first.")
                return
            issue = self._all_findings[key]
            if issue is None:
                return
            rec = {
                "name": issue.getIssueName(), "severity": issue.getSeverity(),
                "confidence": issue.getConfidence(), "false_positive": key.startswith("[FP]"),
                "url": str(issue.getUrl()),
                "cvss": issue.getCvssScore() if hasattr(issue, "getCvssScore") else "",
                "cve": issue.getCve() if hasattr(issue, "getCve") else "",
                "parameter": issue.getParameter() if hasattr(issue, "getParameter") else "",
                "detail": issue.getDetailMarkdown() if hasattr(issue, "getDetailMarkdown") else "",
                "background": issue.getBackgroundMarkdown() if hasattr(issue, "getBackgroundMarkdown") else "",
                "remediation": issue.getRemediationMarkdown() if hasattr(issue, "getRemediationMarkdown") else "",
            }
            md = _finding_to_md(rec, heading="##")
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(md), None)
            self._status_lbl.setText("Copied finding as Markdown.")
        except Exception as ex:
            self._status_lbl.setText("Copy failed: " + str(ex))
            self._log("Copy markdown error: " + str(ex))

    # -- filter helpers --------------------------------------------------------

    def _on_filter_change(self):
        """Debounce: only apply filter 300ms after the last keystroke."""
        if hasattr(self, "_filter_timer") and self._filter_timer is not None:
            self._filter_timer.stop()

        ui_ref = self

        class _Debounce(_ActionListener):
            def actionPerformed(self, e):
                ui_ref._filter_str = ui_ref._filter_field.getText().strip().lower()
                ui_ref._apply_filter()
                ui_ref._filter_timer = None

        self._filter_timer = Timer(300, _Debounce())
        self._filter_timer.setRepeats(False)
        self._filter_timer.start()

    def _clear_filter(self):
        self._filter_field.setText("")
        self._filter_str = ""
        try:
            self._sev_filter.setSelectedItem("All")
        except Exception:
            pass
        try:
            self._hide_fp_chk.setSelected(False)
        except Exception:
            pass
        self._apply_filter()

    def _apply_filter(self):
        """Rebuild list model from _all_findings applying the target + severity
        filters, sorted High -> Information. Active placeholders stay pinned on top."""
        self._list_model.clear()
        # Re-add active placeholders first (always visible while analysing)
        for ph in sorted(self._placeholders):
            self._list_model.addElement(ph)

        flt = self._filter_str
        try:
            sev_choice = str(self._sev_filter.getSelectedItem())
        except Exception:
            sev_choice = "All"
        try:
            hide_fp = self._hide_fp_chk.isSelected()
        except Exception:
            hide_fp = False

        matched = []
        for key, issue in self._all_findings.items():
            if hide_fp and key.startswith("[FP]"):
                continue
            try:
                sev = issue.getSeverity() if issue else "Information"
            except Exception:
                sev = "Information"
            if sev_choice != "All" and sev != sev_choice:
                continue
            if flt:
                url_str = ""
                try:
                    url_str = str(issue.getUrl()).lower() if issue else ""
                except Exception:
                    pass
                if flt not in key.lower() and flt not in url_str:
                    continue
            matched.append((key, sev))

        # Sort High -> Medium -> Low -> Information, then alphabetically by name.
        matched.sort(key=lambda ks: (_SEV_RANK.get(ks[1], 4), ks[0].lower()))
        for key, _sev in matched:
            self._list_model.addElement(key)

        self._status_lbl.setText("{0} finding(s).".format(len(matched)))
        self._update_summary()

    def _active_model(self):
        """Return (provider, model) for whatever provider is currently selected."""
        prov = self.get_provider()
        try:
            if prov == "Anthropic":   m = str(self._ant_model.getSelectedItem())
            elif prov == "OpenAI":    m = str(self._oai_model.getSelectedItem())
            elif prov == "OpenRouter": m = self._or_model.getText()
            elif prov == "Gemini":    m = str(self._gem_model.getSelectedItem())
            elif prov == "Ollama":
                mode = "Cloud" if str(self._ollama_mode.getSelectedItem()) == "Ollama Cloud" else "Local"
                return "Ollama ({0})".format(mode), self._ollama_model.getText()
            else:  # OpenAI-compatible providers (DeepSeek, Kimi, ..., OpenCode Zen)
                key_prefix = OAI_COMPAT_KEYS.get(prov, prov.lower())
                fields = self._oai_fields.get(key_prefix)
                m = fields[1].getText() if fields else ""
        except Exception:
            m = ""
        return prov, m

    def _refresh_model_label(self):
        try:
            prov, model = self._active_model()
            self._model_lbl.setText("   Model: {0} / {1}".format(prov, model) if model
                                    else "   Model: {0}".format(prov))
        except Exception:
            pass

    def _theme_mode(self):
        try:
            return str(self._theme_combo.getSelectedItem()).lower()
        except Exception:
            return "auto"

    def _apply_theme_now(self, e=None):
        """Rebuild the theme (honouring the Auto/Light/Dark override) and re-skin the
        live surfaces — advisory, chat, findings list — then repaint. Lets the user
        fix a mis-detected dark theme without reloading the extension."""
        try:
            set_theme_mode(self._theme_mode())
        except Exception:
            pass
        th = _theme()
        try:
            _apply_html_theme(self._advisory, is_chat=False)
        except Exception:
            pass
        try:
            _apply_html_theme(self._chat_view, is_chat=True)
        except Exception:
            pass
        try:
            _apply_html_theme(self._hunt_detail, is_chat=False)
            self._hunt_on_select()   # re-render detail with the new palette
            self._skin_hunt_banner()  # re-colour the POTENTIAL banner for the new theme
            self._hunt_table.repaint()  # re-run cell renderer (Status/Severity colours)
        except Exception:
            pass
        # Dashboard: re-skin its editor pane (kit + background) and re-render so it
        # follows the new theme instead of keeping a stale dark/black background.
        try:
            self._refresh_dashboard()
        except Exception:
            pass
        # Re-render content so the new palette actually paints. setEditorKit reset
        # the document to empty, so an unselected advisory MUST be re-set to a themed
        # empty body — otherwise the stale (old-theme) background stays on screen.
        try:
            if self._result_list.getSelectedValue():
                self._on_select(None)
            else:
                self._advisory.setText(u"<html><body></body></html>")
        except Exception:
            pass
        try:
            self._chat_render()
        except Exception:
            pass
        # Findings list + force a repaint of every reskinned surface.
        try:
            self._result_list.setBackground(th.list_bg)
            self._result_list.repaint()
        except Exception:
            pass
        for _c in (getattr(self, "_advisory", None), getattr(self, "_chat_view", None)):
            try:
                _c.revalidate(); _c.repaint()
            except Exception:
                pass
        # Re-colour every registered button for the new theme.
        self._reskin_buttons()
        self._log("Theme applied: {0}".format(_THEME_MODE))

    def _update_summary(self):
        """Severity tally across the WHOLE session (ignores the target filter), so
        an analyst sees overall posture at a glance instead of scrolling the list.

        Rendered as plain coloured JLabels (no HTML) — Burp strips HTML from Swing
        labels, so markup would show up literally.
        """
        tally = {"High": 0, "Medium": 0, "Low": 0, "Information": 0, "FP": 0}
        for key in self._all_findings.keys():
            if key.startswith("[FP]"):
                tally["FP"] += 1
            elif key.startswith("[High]"):
                tally["High"] += 1
            elif key.startswith("[Medium]"):
                tally["Medium"] += 1
            elif key.startswith("[Low]"):
                tally["Low"] += 1
            elif key.startswith("[Information]"):
                tally["Information"] += 1
        total = sum(tally.values())

        self._summary_panel.removeAll()
        if total > 0:
            th = _theme()
            # Vivid severity colours read on both light and dark backgrounds.
            for label, colour, short in (
                ("High", Color(0xE53935), "High"), ("Medium", Color(0xFB8C00), "Med"),
                ("Low", Color(0x1E88E5), "Low"), ("Information", th.muted, "Info"),
                ("FP", th.muted, "FP"),
            ):
                if tally[label]:
                    chip = JLabel("{0} {1}".format(tally[label], short))
                    chip.setForeground(colour)
                    if label in ("High", "Medium", "Low"):
                        chip.setFont(chip.getFont().deriveFont(Font.BOLD))
                    self._summary_panel.add(chip)
            tot = JLabel("({0} total)".format(total))
            tot.setForeground(th.muted)
            self._summary_panel.add(tot)
        self._summary_panel.revalidate()
        self._summary_panel.repaint()

    # -- result helpers (called from Scanner on EDT) ---------------------------

    def add_placeholder(self, url, auto_filter=True):
        """Add an in-progress placeholder. Returns a collision-free UUID key."""
        key = "[...] Analyzing - " + url + "  [" + str(_uuid_mod.uuid4())[:8] + "]"
        self._placeholders.add(key)
        self._list_model.addElement(key)
        # Enable Stop button and reset cancel flag for every new analysis
        self._cancelled = False
        self._stop_btn.setEnabled(True)
        # Auto-filter to the host of the new target (only for single scans or first in bulk)
        if auto_filter:
            try:
                from java.net import URL as _URL
                host = _URL(url).getHost()
                if host:
                    self._filter_field.setText(host)
                    self._filter_str = host.lower()
            except Exception:
                pass
        self._status_lbl.setText("Analyzing...")
        self._refresh_model_label()
        return key

    def _is_cross_dup(self, issue):
        """True if an equivalent finding is already stored from a previous analysis
        (matched on severity + normalized URL + parameter + equal/subset name). Also
        matches findings the user dismissed as FP, so a re-scan won't resurrect them."""
        try:
            sev   = issue.getSeverity()
            url   = _norm_finding_url(issue.getUrl())
            name  = issue.getIssueName()
            try:
                param = (issue.getParameter() or u"").strip().lower()
            except Exception:
                param = u""
        except Exception:
            return False
        for other in self._all_findings.values():
            if other is None:
                continue
            try:
                if other.getSeverity() != sev:
                    continue
                if _norm_finding_url(other.getUrl()) != url:
                    continue
                try:
                    op = (other.getParameter() or u"").strip().lower()
                except Exception:
                    op = u""
                if op != param:
                    continue
                if _names_dup(name, other.getIssueName()):
                    return True
            except Exception:
                continue
        return False

    def update_results(self, placeholder_key, issues):
        """Replace placeholder with completed findings and refresh filtered list."""
        # Remove placeholder
        self._placeholders.discard(placeholder_key)
        for i in range(self._list_model.getSize()):
            if self._list_model.getElementAt(i) == placeholder_key:
                self._list_model.remove(i)
                break

        # Collapse near-duplicate findings within THIS analysis batch: the model
        # often emits e.g. "SQL Injection" and "SQL Injection (SQLi)" for the same
        # request. Key on (severity, normalized-URL, parameter, normalized-name) so a
        # true near-duplicate collapses, but two genuinely distinct findings of the
        # same class on DIFFERENT parameters/URLs are both kept.
        batch_seen = set()
        deduped = []
        for issue in issues:
            try:
                try:
                    param = (issue.getParameter() or u"").strip().lower()
                except Exception:
                    param = u""
                sig = (issue.getSeverity(), _norm_finding_url(issue.getUrl()), param,
                       _norm_finding_name(issue.getIssueName()))
            except Exception:
                sig = None
            if sig is not None and sig in batch_seen:
                self._log("Dedup: dropped near-duplicate '{0}'".format(issue.getIssueName()))
                continue
            if sig is not None:
                batch_seen.add(sig)
            deduped.append(issue)

        # Store completed findings. Skip a finding already present from a PRIOR run of
        # the same endpoint (same severity + normalized URL + parameter + equal/subset
        # name) so re-analyzing a target no longer produces "... (2)" repeats of
        # host-level issues (CORS / CSP / missing CSRF). Genuinely distinct findings
        # (different URL, parameter, or class) are still kept and counter-suffixed.
        for issue in deduped:
            if self._is_cross_dup(issue):
                self._log("Dedup: dropped cross-analysis duplicate '{0}'".format(
                    issue.getIssueName()))
                continue
            sev     = issue.getSeverity()
            name    = issue.getIssueName()
            base    = "[{0}] {1}".format(sev, name)
            display = base
            counter = 2
            while display in self._all_findings:
                display = "{0} ({1})".format(base, counter)
                counter += 1
            self._all_findings[display] = issue

        # Rebuild visible list (filter applied)
        self._apply_filter()
        # Refresh the session token counter (the analysis call just recorded usage)
        self.refresh_token_label()
        # Disable Stop button when all placeholders are resolved (single scan done)
        if not self._placeholders and self._pending_count == 0:
            self._stop_btn.setEnabled(False)

    def refresh_token_label(self):
        """Update the header token counter from the shared session usage total."""
        try:
            u = _get_usage()
            if not u or u.get("total", 0) <= 0:
                self._token_lbl.setText("")
                return
            def _k(n):
                return "{0:,}".format(int(n))
            self._token_lbl.setText(
                u"Tokens: last {0} · session {1} ({2} calls)".format(
                    _k(u.get("last_total", 0)), _k(u.get("total", 0)), u.get("calls", 0)))
        except Exception:
            pass

    def _load_demo(self):
        """Populate Results + AI Hunt with bundled sample data (no API/internet)."""
        try:
            for d in _demo.DEMO_FINDINGS:
                issue = _AgenticBurpIssue(
                    http_service=None, url=d["url"], http_messages=[],
                    name=d["name"], detail=d["detail"], background=d["background"],
                    remediation=d["remediation"], severity=d["severity"],
                    confidence=d["confidence"], cvss_score=d.get("cvss", ""),
                    parameter=d.get("parameter", ""), cve=d.get("cve", ""))
                disp = d["confidence"] == "Tentative" and not d["name"].lower().startswith("potential")
                nm = ("Potential " + d["name"]) if disp else d["name"]
                key = "[{0}] {1}".format(d["severity"], nm)
                c = 2
                while key in self._all_findings:
                    key = "[{0}] {1} ({2})".format(d["severity"], nm, c); c += 1
                self._all_findings[key] = issue
            self._update_summary()
            self._apply_filter()
        except Exception as ex:
            self._log("Demo findings error: " + str(ex))
        try:
            self._hunt_add_hits([dict(x) for x in _demo.DEMO_HUNT])
        except Exception as ex:
            self._log("Demo hunt error: " + str(ex))
        self._status_lbl.setText(
            "Demo data loaded: {0} findings + {1} AI Hunt candidates (see AI Hunt tab).".format(
                len(_demo.DEMO_FINDINGS), len(_demo.DEMO_HUNT)))

    def _clear(self):
        self._list_model.clear()
        self._all_findings.clear()
        self._placeholders.clear()
        self._advisory.setText("")
        self._update_summary()
        self._editor_controller.set_message(None)
        self._req_editor.setMessage([], True)
        self._resp_editor.setMessage([], False)
        self._stop_btn.setEnabled(False)
        self._queue_lbl.setText("")
        # Reset the session token counter alongside the findings.
        try:
            _reset_usage()
        except Exception:
            pass
        self._token_lbl.setText("")
        self._status_lbl.setText("Cleared.")

    def _on_select(self, event):
        if event and event.getValueIsAdjusting():
            return
        key = self._result_list.getSelectedValue()
        if not key:
            return
        issue = self._all_findings.get(key)
        if not issue:
            return
        try:
            detail_md      = issue.getDetailMarkdown()      if hasattr(issue, "getDetailMarkdown")      else (issue.getIssueDetail() or "")
            bg_md          = issue.getBackgroundMarkdown()  if hasattr(issue, "getBackgroundMarkdown")  else (issue.getIssueBackground() or "")
            remediation_md = issue.getRemediationMarkdown() if hasattr(issue, "getRemediationMarkdown") else (issue.getRemediationDetail() or "")

            sections = [
                "# " + issue.getIssueName(),
                "**Severity:** " + issue.getSeverity() + " &nbsp; "
                "**Confidence:** " + issue.getConfidence() + "  \n"
                "**URL:** `" + str(issue.getUrl()) + "`",
                "---",
            ]
            # Hide the generic fallback strings the parser injects when the model
            # gave no dedicated Background/Remediation section — showing
            # "Review and remediate the identified vulnerability." next to a real,
            # detailed fix in Issue Detail reads as unfinished. Real content still
            # renders; only the boilerplate placeholders are suppressed.
            def _meaningful(md):
                return md.strip() and md.strip() not in _GENERIC_ADVISORY_FILLER
            if detail_md.strip():
                sections.append("## Issue Detail\n\n" + detail_md.strip())
            if _meaningful(bg_md):
                sections.append("## Issue Background\n\n" + bg_md.strip())
            if _meaningful(remediation_md):
                sections.append("## Remediation\n\n" + remediation_md.strip())
            combined_md = "\n\n".join(sections)
            body_html = _md2html(combined_md)
            # Stylesheet is pre-configured on the HTMLEditorKit — no inline CSS needed.
            self._advisory.setText("<html><body>" + body_html + "</body></html>")
            self._advisory.setCaretPosition(0)

            msgs = issue.getHttpMessages()
            if msgs and len(msgs) > 0:
                msg = msgs[0]
                self._editor_controller.set_message(msg)
                req  = msg.getRequest()
                resp = msg.getResponse()
                self._req_editor.setMessage(req  if req  else [], True)
                self._resp_editor.setMessage(resp if resp else [], False)
                self._set_chat_context(msg, issue.getUrl())
            else:
                self._editor_controller.set_message(None)
                self._req_editor.setMessage([], True)
                self._resp_editor.setMessage([], False)
                self._set_chat_context(None, None)
        except Exception as ex:
            self._advisory.setText(
                "<html><body>Error displaying result: " + str(ex) + "</body></html>")

    def _toggle_fp(self):
        key = self._result_list.getSelectedValue()
        if not key or key not in self._all_findings:
            return
        issue   = self._all_findings[key]
        becoming_fp = not key.startswith("[FP]")
        new_key = ("[FP] " + key) if becoming_fp else key[5:]
        del self._all_findings[key]
        self._all_findings[new_key] = issue
        self._apply_filter()
        # Cross-scan memory: remember (or forget) this as a false positive so
        # future analyses of the same host skip it.
        try:
            scanner = getattr(self, "_scanner", None)
            if scanner is not None and issue is not None and hasattr(scanner, "memory"):
                u = issue.getUrl()
                host = u.getHost() if u else ""
                path = u.getPath() if u else ""
                nm = issue.getIssueName()
                if becoming_fp:
                    scanner.memory.add_fp(host, path, nm)
                else:
                    scanner.memory.remove_fp(host, nm)
        except Exception:
            pass

    def _delete_item(self, idx):
        if 0 <= idx < self._list_model.getSize():
            key = self._list_model.getElementAt(idx)
            if key in self._all_findings:
                del self._all_findings[key]
            self._placeholders.discard(key)
            self._apply_filter()

    # -- severity-coloured list cell renderer ----------------------------------

    class _FindingCellRenderer(DefaultListCellRenderer):
        """
        Left-accent-stripe design (no HTML — avoids Jython rendering quirks):
          [High]        → red stripe,    light-red bg,    bold dark-red text
          [Medium]      → amber stripe,  light-amber bg,  dark-amber text
          [Low]         → blue stripe,   light-blue bg,   dark-blue text
          [Information] → gray stripe,   near-white bg,   gray text
          [...]         → orange stripe, white bg,        italic gray (in-progress)
          [FP]          → gray stripe,   white bg,        gray italic (false positive)
        Selected row: light-indigo bg, keep accent stripe.
        """
        # Styles come from the active theme (light or Burp-dark), resolved at
        # render time so the palette matches whatever Look & Feel Burp is using.

        def getListCellRendererComponent(self, lst, value, index, isSelected, hasFocus):
            comp = DefaultListCellRenderer.getListCellRendererComponent(
                self, lst, value, index, isSelected, hasFocus)
            if value is None:
                return comp
            text = str(value)

            # Pick style bucket
            if text.startswith("[...]"):
                key = "ph"
            elif text.startswith("[FP]"):
                key = "fp"
            elif text.startswith("[High]"):
                key = "High"
            elif text.startswith("[Medium]"):
                key = "Medium"
            elif text.startswith("[Low]"):
                key = "Low"
            elif text.startswith("[Information]"):
                key = "Information"
            else:
                key = "default"

            th = _theme()
            stripe_c, bg_c, fg_c, font_style = th.sev[key]

            # Left stripe + padding border
            stripe = BorderFactory.createMatteBorder(0, 4, 0, 0, stripe_c)
            pad    = BorderFactory.createEmptyBorder(3, 7, 3, 6)
            comp.setBorder(BorderFactory.createCompoundBorder(stripe, pad))

            # Font
            comp.setFont(comp.getFont().deriveFont(font_style))

            if isSelected:
                comp.setBackground(th.sel_bg)
                comp.setForeground(th.sel_fg)
            else:
                comp.setBackground(bg_c)
                comp.setForeground(fg_c)

            comp.setOpaque(True)
            return comp

    class _MouseListener(MouseAdapter):
        def __init__(self, ui):
            self._ui = ui

        def mouseReleased(self, e):
            self._maybe_popup(e)

        def mousePressed(self, e):
            self._maybe_popup(e)

        def _maybe_popup(self, e):
            if not e.isPopupTrigger():
                return
            lst = e.getComponent()
            idx = lst.locationToIndex(e.getPoint())
            if idx < 0:
                return
            lst.setSelectedIndex(idx)
            menu     = JPopupMenu()
            copy_item = JMenuItem("Copy as Markdown")
            copy_item.addActionListener(lambda ev: self._ui._copy_finding_markdown())
            menu.add(copy_item)
            fp_item  = JMenuItem("Toggle False Positive")
            fp_item.addActionListener(lambda ev: self._ui._toggle_fp())
            menu.add(fp_item)
            del_item = JMenuItem("Delete")
            del_item.addActionListener(lambda ev, i=idx: self._ui._delete_item(i))
            menu.add(del_item)
            menu.show(e.getComponent(), e.getX(), e.getY())


# ── Burp native message editor controller ─────────────────────────────────────

class _MessageEditorController(IMessageEditorController):
    """
    Provides context for Burp's IMessageEditor so that right-click actions
    like 'Send to Repeater' and 'Send to Intruder' work correctly.
    """
    def __init__(self):
        self._http_service = None
        self._request      = None
        self._response     = None

    def set_message(self, http_message):
        """Update with the currently selected IHttpRequestResponse."""
        if http_message is None:
            self._http_service = None
            self._request      = None
            self._response     = None
        else:
            self._http_service = http_message.getHttpService()
            self._request      = http_message.getRequest()
            self._response     = http_message.getResponse()

    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response


class _WidthTrackingPanel(JPanel, Scrollable):
    """A BoxLayout panel that fills the scroll viewport's WIDTH (so wrapping
    JTextAreas inside actually wrap to the available width instead of keeping a
    narrow preferred width) while scrolling vertically."""
    def getPreferredScrollableViewportSize(self):
        return self.getPreferredSize()
    def getScrollableUnitIncrement(self, visibleRect, orientation, direction):
        return 16
    def getScrollableBlockIncrement(self, visibleRect, orientation, direction):
        return 160
    def getScrollableTracksViewportWidth(self):
        return True
    def getScrollableTracksViewportHeight(self):
        return False
