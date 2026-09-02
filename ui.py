# -*- coding: utf-8 -*-
# AgenticBurp - ui.py

import base64
import json
import re
import uuid as _uuid_mod
from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JComboBox, JCheckBox, JTextArea,
    JScrollPane, JButton, JSplitPane, JList, DefaultListModel, JEditorPane,
    JTabbedPane, BorderFactory, JMenuItem, JPopupMenu, JFileChooser, Timer,
    DefaultListCellRenderer, BoxLayout, SwingUtilities,
)
from javax.swing.text.html import HTMLEditorKit, StyleSheet
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font, Dimension
from java.awt.event import (
    MouseAdapter, ActionListener as _ActionListener,
    KeyAdapter as _KeyAdapter, KeyEvent as _KeyEvent,
)
from javax.swing.event import DocumentListener as _DocumentListener
from java.lang import Thread as _JThread, Runnable as _JRunnable

from burp import IMessageEditorController

from prompt_handler import DEFAULT_USER_PROMPT_TEMPLATE, SYSTEM_PROMPT
from report_generator import _md_to_html as _md2html
from api_client import APIClient as _APIClient
from api_client import OAI_COMPAT_PROVIDERS, OAI_COMPAT_KEYS
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


# Generic fallback strings report_generator injects when the model provided no
# dedicated Background/Remediation section. Suppressed in the Advisory so they do
# not sit next to real, detailed content and read as unfinished. Keep in sync with
# report_generator.py's fallbacks.
_GENERIC_ADVISORY_FILLER = frozenset([
    u"Identified by AgenticBurp AI analysis.",
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
            self._log("{0} selected — Max Tokens set to {1} to stay under the "
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
        # OpenAI-compatible providers (DeepSeek, Kimi, Mistral, Groq, xAI)
        for key_prefix, (key_f, model_f, _s) in self._oai_fields.items():
            self._save_str(key_prefix + "_key",   _obfuscate(key_f.getText()))
            self._save_str(key_prefix + "_model", model_f.getText())
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
            self._ant_model.setSelectedItem(self._load_str("anthropic_model", "claude-sonnet-4-6"))
            self._oai_key.setText(_deobfuscate(self._load_str("openai_key", "")))
            self._oai_model.setSelectedItem(self._load_str("openai_model", "gpt-4o"))
            self._or_key.setText(_deobfuscate(self._load_str("or_key", "")))
            self._or_model.setText(self._load_str("or_model", "anthropic/claude-sonnet-4-6"))
            self._gem_key.setText(_deobfuscate(self._load_str("gemini_key", "")))
            self._gem_model.setSelectedItem(self._load_str("gemini_model", "gemini-2.0-flash"))
            self._ollama_mode.setSelectedItem(self._load_str("ollama_mode", "Local server"))
            self._ollama_url.setText(self._load_str("ollama_url", "http://localhost:11434"))
            self._ollama_key.setText(_deobfuscate(self._load_str("ollama_key", "")))
            self._ollama_model.setText(self._load_str("ollama_model", "qwen2.5-coder:7b"))
            for key_prefix, (key_f, model_f, _s) in self._oai_fields.items():
                key_f.setText(_deobfuscate(self._load_str(key_prefix + "_key", "")))
                saved_model = self._load_str(key_prefix + "_model", "")
                if saved_model:
                    model_f.setText(saved_model)
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
        self._tabs.addTab("  About     ", self._build_about())
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

        title = JLabel("AgenticBurp")
        title.setFont(Font("SansSerif", Font.BOLD, 18))
        title.setForeground(_ORANGE)

        sub = JLabel(u"AI-Powered Web Security Analysis  \u2022  Multi-Provider  \u2022  v{0}".format(self._version))
        sub.setFont(Font("SansSerif", Font.PLAIN, 11))
        sub.setForeground(_GRAY)

        left.add(title)
        left.add(sub)
        banner.add(left, BorderLayout.WEST)

        badge = JLabel("Agentic Pentest")
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
            "ones dropped. Reduces false positives — costs one extra API call per "
            "analysis.")
        top.add(self._self_verify_chk)
        top.add(JLabel("Theme:"))
        self._theme_combo = JComboBox(["Auto", "Light", "Dark"])
        self._theme_combo.setToolTipText(
            "UI theme. Auto follows Burp's Look & Feel; pick Light or Dark to force "
            "it if auto-detection guesses wrong. Applies immediately.")
        self._theme_combo.addActionListener(lambda e: self._apply_theme_now())
        top.add(self._theme_combo)
        save_btn = self._style_btn(JButton("Save Settings"), Color(0xFF6B35), Color.WHITE)
        save_btn.addActionListener(lambda e: self._save_settings())
        top.add(save_btn)
        reset_btn = self._style_btn(JButton("Reset Prompt"), Color(0x546E7A), Color.WHITE)
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
        self._oai_fields = {}   # key_prefix -> (key_field, model_field, status_lbl)
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
        btn.setForeground(Color(0xC62828))
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
        btn.setForeground(Color(0x1565C0))
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
        self._ant_model = JComboBox(["claude-sonnet-4-6", "claude-opus-4-6",
                                     "claude-haiku-4-5-20251001",
                                     "claude-3-5-sonnet-20241022",
                                     "claude-3-5-haiku-20241022"])
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
        self._oai_model = JComboBox(["gpt-4o", "gpt-4o-mini", "gpt-4-turbo",
                                     "gpt-4", "gpt-3.5-turbo", "o1", "o1-mini", "o3-mini"])
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
        self._or_model = JTextField("meta-llama/llama-3.3-70b-instruct:free", 40)
        self._or_status = self._conn_status_lbl()
        _client = self._api_client
        _key_f  = self._or_key
        _mdl_f  = self._or_model
        def _or_test():
            return _client.test_openrouter(_key_f.getText(), _mdl_f.getText())
        rows.add(self._row_panel(JLabel("API Key:  "), self._or_key, self._clear_key_btn(self._or_key, "or_key")))
        rows.add(self._row_panel(JLabel("Model ID: "), self._or_model))
        rows.add(self._row_panel(self._test_conn_btn(self._or_status, _or_test), self._or_status))

        fast_lbl = JLabel(u"Free: meta-llama/llama-3.3-70b-instruct:free  \u2022  google/gemma-3-27b-it:free  \u2022  deepseek/deepseek-r1:free")
        fast_lbl.setFont(fast_lbl.getFont().deriveFont(Font.PLAIN, 11.0))
        rows.add(fast_lbl)

        paid_lbl = JLabel(u"Paid: anthropic/claude-sonnet-4-6  \u2022  openai/gpt-4o  \u2022  google/gemini-2.5-pro")
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
        self._gem_model = JComboBox(["gemini-2.0-flash",
                                     "gemini-2.0-flash-lite",
                                     "gemini-2.5-pro",
                                     "gemini-1.5-pro",
                                     "gemini-1.5-flash",
                                     "gemini-1.5-flash-8b"])
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

        DeepSeek / Kimi / Mistral / Groq / xAI differ only in base URL, default
        model and sign-up link, so they share this one builder instead of five
        near-identical methods.
        """
        key_prefix = OAI_COMPAT_KEYS.get(label, label.lower())
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))

        key_field   = JPasswordField(40)
        model_field = JTextField(default_model, 40)
        status_lbl  = self._conn_status_lbl()
        self._oai_fields[key_prefix] = (key_field, model_field, status_lbl)

        _client = self._api_client
        _label  = label
        _base   = base_url

        def _test():
            return _client.test_openai_compatible(
                _label, _base, key_field.getText(), model_field.getText())

        rows.add(self._row_panel(JLabel("API Key:  "), key_field,
                                 self._clear_key_btn(key_field, key_prefix + "_key")))
        rows.add(self._row_panel(JLabel("Model ID: "), model_field))
        rows.add(self._row_panel(self._test_conn_btn(status_lbl, _test), status_lbl))

        hint = JLabel("Models: " + model_hint)
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 11.0))
        rows.add(hint)
        rows.add(JLabel("Endpoint: {0}   |   Get key: {1}".format(base_url, key_url)))

        note = JLabel("OpenAI-compatible provider. Set Max Tokens per the model's limit.")
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
        header.add(JLabel("Analysis Results  "))
        header.add(self._status_lbl)
        header.add(self._queue_lbl)
        header.add(self._summary_panel)
        header.add(self._model_lbl)
        clear_btn  = self._style_btn(JButton("Clear All"),   Color(0x546E7A), Color.WHITE)
        clear_btn.addActionListener(lambda e: self._clear())
        header.add(clear_btn)
        self._stop_btn = self._style_btn(JButton("Stop"), Color(0xC62828), Color.WHITE)
        self._stop_btn.setEnabled(False)
        self._stop_btn.addActionListener(lambda e: self._stop_analysis())
        header.add(self._stop_btn)
        export_btn = self._style_btn(JButton("Export JSON"),  Color(0xFF6B35), Color.WHITE)
        export_btn.addActionListener(lambda e: self._export_json())
        header.add(export_btn)
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

        clear_filter_btn = self._style_btn(JButton("Show All"), Color(0x37474F), Color.WHITE)
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

        fp_btn = self._style_btn(JButton("Toggle False Positive"), Color(0x6A1B9A), Color.WHITE)
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

        self._chat_send_btn = self._style_btn(JButton("Send"), Color(0xFF6B35), Color.WHITE)
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

        clear_chat = self._style_btn(JButton("Clear"), Color(0x546E7A), Color.WHITE)
        class _ClearChat(_ActionListener):
            def __init__(self, ui): self._ui = ui
            def actionPerformed(self, _e): self._ui._chat_clear()
        clear_chat.addActionListener(_ClearChat(self))

        hint = JLabel("Enter to send  ·  Shift+Enter for new line")
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

    # -- about tab -------------------------------------------------------------

    def _build_about(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))

        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        _mono   = Font("Monospaced", Font.PLAIN, 11)
        _mono_b = Font("Monospaced", Font.BOLD,  11)
        _sans   = Font("SansSerif",  Font.PLAIN, 11)
        _sans_b = Font("SansSerif",  Font.BOLD,  12)
        _big    = Font("SansSerif",  Font.BOLD,  15)
        _orange = Color(0xFF6B35)
        _grey   = Color(0x555555)

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

        # ---- App header ----
        content.add(_lbl("AgenticBurp", _big, _orange, top=2, bot=2))
        content.add(_lbl("AI-Powered Security Analysis for Burp Suite", _sans_b, _grey))
        content.add(_lbl("Part of the Agentic Web Pentest project  |  Jython 2.7  |  Burp Suite Extension", _sans, _grey, bot=6))
        content.add(_sep())

        # ---- About ----
        content.add(_lbl("About", _sans_b, _orange, top=6, bot=2))
        about_lines = [
            "AgenticBurp integrates large language models directly into Burp Suite to perform",
            "automated security analysis on HTTP requests and responses. Findings are structured,",
            "severity-classified, and registered as native Burp scan issues.",
            "",
            "Right-click any request in Proxy/Repeater/Scanner -> AgenticBurp -> Analyze with AI.",
            "Single or bulk requests are supported. Bulk scans use concurrent workers.",
        ]
        for line in about_lines:
            content.add(_lbl(line if line else " ", _sans))
        content.add(_sep())

        # ---- Providers ----
        content.add(_lbl("Supported Providers", _sans_b, _orange, top=6, bot=2))
        content.add(_lbl("  Anthropic   --  Claude models (Sonnet, Opus, Haiku)", _mono))
        content.add(_lbl("  OpenAI      --  GPT-4o, o1, o3 models", _mono))
        content.add(_lbl("  OpenRouter  --  400+ models via unified API (free & paid)", _mono))
        content.add(_lbl("  Gemini      --  Google Gemini 2.0/2.5/1.5 models", _mono))
        content.add(_lbl("  Ollama      --  Any local model (qwen, llama, mistral, deepseek)", _mono))
        content.add(_lbl("  DeepSeek    --  deepseek-chat (V3), deepseek-reasoner (R1)", _mono))
        content.add(_lbl("  Kimi        --  Moonshot moonshot-v1-8k/32k/128k, kimi-k2", _mono))
        content.add(_lbl("  Mistral     --  mistral-large / small, codestral", _mono))
        content.add(_lbl("  Groq        --  llama-3.3 / 3.1 at very fast inference speed", _mono))
        content.add(_lbl("  xAI (Grok)  --  grok-2, grok-2-vision, grok-beta", _mono))
        content.add(_sep())

        # ---- Model reference table ----
        content.add(_lbl("Model Output Tokens & Context Window", _sans_b, _orange, top=6, bot=2))

        sections = [
            ("Anthropic", [
                ("  claude-sonnet-4-6      ", "out: 64k ", "ctx: 200k", "Best balance speed + quality  [Recommended]"),
                ("  claude-opus-4-6        ", "out: 32k ", "ctx: 200k", "Highest accuracy, slower"),
                ("  claude-haiku-4-5       ", "out: 16k ", "ctx: 200k", "Fastest, lowest cost"),
                ("  claude-3-5-sonnet      ", "out:  8k ", "ctx: 200k", "Previous gen, still strong"),
                ("  claude-3-5-haiku       ", "out:  8k ", "ctx: 200k", "Previous gen fast/cheap"),
            ]),
            ("OpenAI", [
                ("  gpt-4o                 ", "out: 16k ", "ctx: 128k", "Best balance speed + quality  [Recommended]"),
                ("  gpt-4o-mini            ", "out: 16k ", "ctx: 128k", "Cheapest, fast, good for bulk"),
                ("  gpt-4-turbo            ", "out:  4k ", "ctx: 128k", "Strong reasoning, higher cost"),
                ("  o1                     ", "out: 32k ", "ctx: 200k", "Deep reasoning, very slow"),
                ("  o1-mini                ", "out: 65k ", "ctx: 128k", "Faster reasoning model"),
                ("  o3-mini                ", "out: 100k", "ctx: 200k", "Latest reasoning, efficient"),
            ]),
            ("OpenRouter", [
                ("  Free models (llama/gemma/deepseek)", "out: varies", "ctx: varies", "Check model page on openrouter.ai/models"),
                ("  Paid models (claude/gpt/gemini)   ", "out: varies", "ctx: varies", "Same limits as direct provider"),
            ]),
            ("Gemini", [
                ("  gemini-2.5-pro         ", "out: 65k ", "ctx:   1M", "Best quality, free tier available"),
                ("  gemini-2.0-flash       ", "out:  8k ", "ctx:   1M", "Fast, free tier  [Recommended]"),
                ("  gemini-2.0-flash-lite  ", "out:  8k ", "ctx:   1M", "Lightest, cheapest"),
                ("  gemini-1.5-pro         ", "out:  8k ", "ctx:   2M", "Largest context window"),
                ("  gemini-1.5-flash       ", "out:  8k ", "ctx:   1M", "Balanced, free tier"),
                ("  gemini-1.5-flash-8b    ", "out:  8k ", "ctx:   1M", "Fastest, very low cost"),
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
                ("  moonshot-v1-8k         ", "out:  8k ", "ctx:   8k", "Fast, low cost  [Recommended]"),
                ("  moonshot-v1-32k        ", "out:  8k ", "ctx:  32k", "Medium context"),
                ("  moonshot-v1-128k       ", "out:  8k ", "ctx: 128k", "Largest context"),
                ("  kimi-k2-0711-preview   ", "out: varies", "ctx: 128k", "Latest Kimi K2 (check console)"),
            ]),
            ("Mistral", [
                ("  mistral-large-latest   ", "out:  8k ", "ctx: 128k", "Best quality  [Recommended]"),
                ("  mistral-small-latest   ", "out:  8k ", "ctx:  32k", "Fast, cheaper"),
                ("  codestral-latest       ", "out:  8k ", "ctx:  32k", "Code-specialised"),
            ]),
            ("Groq", [
                ("  llama-3.3-70b-versatile", "out:  8k ", "ctx: 128k", "Very fast inference  [Recommended]"),
                ("  llama-3.1-8b-instant   ", "out:  8k ", "ctx: 128k", "Fastest, good for bulk"),
            ]),
            ("xAI (Grok)", [
                ("  grok-2-latest          ", "out:  8k ", "ctx: 128k", "General purpose  [Recommended]"),
                ("  grok-2-vision-latest   ", "out:  8k ", "ctx:  32k", "Multimodal"),
                ("  grok-beta              ", "out:  8k ", "ctx: 128k", "Preview model"),
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
                ("  claude-sonnet-4-6  ", "4096-8192", "3-5", "Best quality; handles large responses"),
                ("  claude-opus-4-6    ", "4096-8192", "2-3", "Slower; lower concurrent to avoid timeout"),
                ("  claude-haiku-4-5   ", "2048-4096", "5-8", "High concurrency OK, very fast"),
            ]),
            ("OpenAI", [
                ("  gpt-4o             ", "4096-8192", "3-5", "Balanced speed + quality"),
                ("  gpt-4o-mini        ", "4096-8192", "5-8", "Best for bulk; cheap + fast"),
                ("  o1 / o3-mini       ", "4096",      "1-2", "Very slow; reasoning tokens billed extra"),
            ]),
            ("OpenRouter", [
                ("  Free models        ", "<=2048",    "1-2", "Hard cap; >2048 causes Error 402"),
                ("  Paid models        ", "4096-8192", "3-5", "Same limits as direct provider"),
            ]),
            ("Gemini", [
                ("  gemini-2.5-pro     ", "4096-8192", "3-5", "Free: 15 req/min; paid: 360 req/min"),
                ("  gemini-2.0-flash   ", "2048-4096", "3-5", "Free: 15 req/min"),
                ("  gemini-1.5-pro     ", "2048-4096", "2-3", "2M ctx but stricter rate limit"),
                ("  gemini-flash-8b    ", "2048",      "5-8", "Very fast, low cost, lower quality"),
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
                ("  moonshot-v1-8k     ", "2048-4096", "3-5", "Fast, low cost"),
                ("  moonshot-v1-128k   ", "2048-4096", "2-3", "Large ctx; higher latency"),
            ]),
            ("Mistral", [
                ("  mistral-large      ", "4096-8192", "3-5", "Strong general reasoning"),
                ("  mistral-small      ", "4096",      "5-8", "Cheap + fast for bulk"),
            ]),
            ("Groq", [
                ("  llama-3.3-70b      ", "4096-8192", "5-8", "Extremely fast; high concurrency OK"),
                ("  llama-3.1-8b       ", "4096",      "8-10","Fastest; best for bulk scans"),
            ]),
            ("xAI (Grok)", [
                ("  grok-2-latest      ", "4096-8192", "3-5", "General purpose"),
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
        content.add(_lbl("  xAI (Grok) key    : console.x.ai", _mono, bot=6))

        # Wrap in scroll
        wrap = JPanel(BorderLayout())
        wrap.add(content, BorderLayout.NORTH)
        scroll = JScrollPane(wrap)
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
        # OpenAI-compatible providers: expose <prefix>_key and <prefix>_model,
        # matching the keys call_api() reads via _settings_key().
        for key_prefix, (key_f, model_f, _s) in self._oai_fields.items():
            base["{0}_key".format(key_prefix)]   = key_f.getText()
            base["{0}_model".format(key_prefix)] = model_f.getText()
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

    def get_scope_only(self):
        return self._scope_only_chk.isSelected()

    def get_prompt_template(self):
        return self._prompt_area.getText()

    # -- queue management (bulk scan) -----------------------------------------

    def start_queue(self, total):
        """Called when a bulk scan begins. total = number of requests queued."""
        self._cancelled     = False
        self._pending_count = total
        self._stop_btn.setEnabled(True)
        self._update_queue_lbl()

    def decrement_queue(self):
        """Called by each worker when it finishes (success or error)."""
        self._pending_count = max(0, self._pending_count - 1)
        if self._pending_count == 0:
            if not self._placeholders:
                self._stop_btn.setEnabled(False)
            self._queue_lbl.setText("")
        else:
            self._update_queue_lbl()

    def _update_queue_lbl(self):
        if self._pending_count > 0:
            self._queue_lbl.setText("| Queue: {0} pending".format(self._pending_count))

    def _stop_analysis(self):
        """Stop any in-progress single or bulk analysis."""
        self._cancelled = True
        self._stop_btn.setEnabled(False)
        self._queue_lbl.setText("| Stopped")
        self._status_lbl.setText("Analysis stopped.")

    def is_cancelled(self):
        return self._cancelled

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

            records = []
            active = 0
            for key, issue in self._all_findings.items():
                if issue is None:
                    continue
                is_fp = key.startswith("[FP]")
                if not is_fp:
                    active += 1
                records.append({
                    "name":       issue.getIssueName(),
                    "severity":   issue.getSeverity(),
                    "confidence": issue.getConfidence(),
                    "false_positive": is_fp,
                    "url":        str(issue.getUrl()),
                    "cvss":       issue.getCvssScore() if hasattr(issue, "getCvssScore") else "",
                    "cve":        issue.getCve()       if hasattr(issue, "getCve")       else "",
                    "parameter":  issue.getParameter() if hasattr(issue, "getParameter") else "",
                    "detail":     issue.getDetailMarkdown()     if hasattr(issue, "getDetailMarkdown")     else "",
                    "background": issue.getBackgroundMarkdown() if hasattr(issue, "getBackgroundMarkdown") else "",
                    "remediation":issue.getRemediationMarkdown() if hasattr(issue, "getRemediationMarkdown") else "",
                })

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
        # request. Keep the first of each (severity, normalized-name) signature.
        batch_seen = set()
        deduped = []
        for issue in issues:
            try:
                sig = (issue.getSeverity(), _norm_finding_name(issue.getIssueName()))
            except Exception:
                sig = None
            if sig is not None and sig in batch_seen:
                self._log("Dedup: dropped near-duplicate '{0}'".format(issue.getIssueName()))
                continue
            if sig is not None:
                batch_seen.add(sig)
            deduped.append(issue)

        # Store completed findings (cross-analysis collisions still get a counter)
        for issue in deduped:
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
        # Disable Stop button when all placeholders are resolved (single scan done)
        if not self._placeholders and self._pending_count == 0:
            self._stop_btn.setEnabled(False)

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
        new_key = ("[FP] " + key) if not key.startswith("[FP]") else key[5:]
        del self._all_findings[key]
        self._all_findings[new_key] = issue
        self._apply_filter()

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
            del_item = JMenuItem("Delete")
            del_item.addActionListener(lambda ev, i=idx: self._ui._delete_item(i))
            menu.add(del_item)
            fp_item  = JMenuItem("Toggle False Positive")
            fp_item.addActionListener(lambda ev: self._ui._toggle_fp())
            menu.add(fp_item)
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
