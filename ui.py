# -*- coding: utf-8 -*-
# AgenticBurp - ui.py

import base64
import json
import uuid as _uuid_mod
from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JComboBox, JCheckBox, JTextArea,
    JScrollPane, JButton, JSplitPane, JList, DefaultListModel, JEditorPane,
    JTabbedPane, BorderFactory, JMenuItem, JPopupMenu, JFileChooser, Timer,
    DefaultListCellRenderer, BoxLayout, SwingUtilities,
)
from javax.swing.text.html import HTMLEditorKit, StyleSheet
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font, Dimension
from java.awt.event import MouseAdapter, ActionListener as _ActionListener
from javax.swing.event import DocumentListener as _DocumentListener

from burp import IMessageEditorController

from prompt_handler import DEFAULT_USER_PROMPT_TEMPLATE, SYSTEM_PROMPT
from report_generator import _md_to_html as _md2html


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
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self.stdout = callbacks.getStdout()

        # All completed findings: display_key -> issue object
        self._all_findings = {}
        # Active placeholder keys (set of strings)
        self._placeholders = set()
        # Filtered view model (what the JList shows)
        self._list_model = DefaultListModel()
        # Current filter string
        self._filter_str = ""

        self._build()
        self._load_settings()

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
        self._save_str("ollama_url",      self._ollama_url.getText())
        self._save_str("ollama_model",    self._ollama_model.getText())
        self._save_str("max_tokens",      self._max_tokens.getText())
        self._save_str("max_concurrent",  self._max_concurrent.getText())
        self._save_str("scope_only",      str(self._scope_only_chk.isSelected()))
        self._save_str("prompt",          self._prompt_area.getText())
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
            self._ollama_url.setText(self._load_str("ollama_url", "http://localhost:11434"))
            self._ollama_model.setText(self._load_str("ollama_model", "qwen2.5-coder:7b"))
            self._max_tokens.setText(self._load_str("max_tokens", "2048"))
            self._max_concurrent.setText(self._load_str("max_concurrent", "2"))
            self._scope_only_chk.setSelected(
                self._load_str("scope_only", "False").lower() == "true")
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

        sub = JLabel(u"AI-Powered Web Security Analysis  \u2022  Multi-Provider  \u2022  v1.0.0")
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
        self._provider_combo = JComboBox(["Anthropic", "OpenAI", "OpenRouter", "Gemini", "Ollama"])
        top.add(self._provider_combo)
        top.add(JLabel("Max Tokens:"))
        self._max_tokens = JTextField("2048", 6)
        self._max_tokens.setToolTipText(
            "Max tokens in AI response. "
            "Anthropic/OpenAI/Gemini: 4096-8192. "
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

    def _build_anthropic(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._ant_key   = JPasswordField(40)
        self._ant_model = JComboBox(["claude-sonnet-4-6", "claude-opus-4-6",
                                     "claude-haiku-4-5-20251001",
                                     "claude-3-5-sonnet-20241022",
                                     "claude-3-5-haiku-20241022"])
        rows.add(self._row_panel(JLabel("API Key:"), self._ant_key, self._clear_key_btn(self._ant_key, "anthropic_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._ant_model))
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
        rows.add(self._row_panel(JLabel("API Key:"), self._oai_key, self._clear_key_btn(self._oai_key, "openai_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._oai_model))
        rows.add(JLabel("Get key: platform.openai.com  |  See About tab for model details"))
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_openrouter(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._or_key   = JPasswordField(40)
        self._or_model = JTextField("meta-llama/llama-3.3-70b-instruct:free", 40)
        rows.add(self._row_panel(JLabel("API Key:  "), self._or_key, self._clear_key_btn(self._or_key, "or_key")))
        rows.add(self._row_panel(JLabel("Model ID: "), self._or_model))

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
        rows.add(self._row_panel(JLabel("API Key:"), self._gem_key, self._clear_key_btn(self._gem_key, "gemini_key")))
        rows.add(self._row_panel(JLabel("Model:  "), self._gem_model))
        rows.add(JLabel("Get key: aistudio.google.com/apikey  |  See About tab for model details"))
        p.add(rows, BorderLayout.NORTH)
        return p

    def _build_ollama(self):
        p = JPanel(BorderLayout(4, 2))
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        rows = JPanel(GridLayout(0, 1, 2, 2))
        self._ollama_url   = JTextField("http://localhost:11434", 40)
        self._ollama_model = JTextField("qwen2.5-coder:7b", 40)
        rows.add(self._row_panel(JLabel("Base URL: "), self._ollama_url))
        rows.add(self._row_panel(JLabel("Model:    "), self._ollama_model))
        rows.add(JLabel("Run: ollama serve   Pull: ollama pull qwen2.5-coder:7b"))
        rows.add(JLabel("See About tab for recommended models & token/concurrent settings"))
        p.add(rows, BorderLayout.NORTH)
        return p

    # -- results tab -----------------------------------------------------------

    def _build_results(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        # Header row
        header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        self._status_lbl  = JLabel("Ready.")
        self._queue_lbl   = JLabel("")   # shows "Queue: X pending"
        header.add(JLabel("Analysis Results  "))
        header.add(self._status_lbl)
        header.add(self._queue_lbl)
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
        outer.add(header, BorderLayout.NORTH)
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
        # Configure HTMLEditorKit with a stylesheet once — prevents Swing from
        # ever reverting to plain-text mode and rendering raw HTML tags.
        _kit = HTMLEditorKit()
        _css = StyleSheet()
        _css.addRule("body { font-family: Arial, sans-serif; font-size: 12pt; margin: 10px; }")
        _css.addRule("b    { color: #1A1A2E; }")
        _css.addRule("pre  { font-family: Monospaced; font-size: 11pt; }")
        _css.addRule("code { font-family: Monospaced; font-size: 11pt; }")
        _kit.setStyleSheet(_css)
        self._advisory.setEditorKit(_kit)
        self._advisory.setContentType("text/html")

        # Native Burp message editors — provide right-click, Send to Repeater, etc.
        self._editor_controller = _MessageEditorController()
        self._req_editor  = self._callbacks.createMessageEditor(
            self._editor_controller, False)
        self._resp_editor = self._callbacks.createMessageEditor(
            self._editor_controller, False)

        self._detail_tabs.addTab("Advisory", JScrollPane(self._advisory))
        self._detail_tabs.addTab("Request",  self._req_editor.getComponent())
        self._detail_tabs.addTab("Response", self._resp_editor.getComponent())

        fp_btn = self._style_btn(JButton("Toggle False Positive"), Color(0x6A1B9A), Color.WHITE)
        fp_btn.addActionListener(lambda e: self._toggle_fp())
        right = JPanel(BorderLayout())
        right.add(self._detail_tabs, BorderLayout.CENTER)
        right.add(fp_btn, BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, list_scroll, right)
        split.setDividerLocation(300)
        outer.add(split, BorderLayout.CENTER)
        return outer

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
        content.add(_lbl("  Browse OR models  : openrouter.ai/models", _mono, bot=6))

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
        return {
            "anthropic_key":    self._ant_key.getText(),
            "anthropic_model":  str(self._ant_model.getSelectedItem()),
            "openai_key":       self._oai_key.getText(),
            "openai_model":     str(self._oai_model.getSelectedItem()),
            "openrouter_key":   self._or_key.getText(),
            "openrouter_model": self._or_model.getText(),
            "gemini_key":       self._gem_key.getText(),
            "gemini_model":     str(self._gem_model.getSelectedItem()),
            "ollama_base_url":  self._ollama_url.getText(),
            "ollama_model":     self._ollama_model.getText(),
        }

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
            for issue in self._all_findings.values():
                if issue is None:
                    continue
                records.append({
                    "name":       issue.getIssueName(),
                    "severity":   issue.getSeverity(),
                    "confidence": issue.getConfidence(),
                    "url":        str(issue.getUrl()),
                    "cvss":       issue.getCvssScore() if hasattr(issue, "getCvssScore") else "",
                    "cve":        issue.getCve()       if hasattr(issue, "getCve")       else "",
                    "parameter":  issue.getParameter() if hasattr(issue, "getParameter") else "",
                    "detail":     issue.getDetailMarkdown()     if hasattr(issue, "getDetailMarkdown")     else "",
                    "background": issue.getBackgroundMarkdown() if hasattr(issue, "getBackgroundMarkdown") else "",
                    "remediation":issue.getRemediationMarkdown() if hasattr(issue, "getRemediationMarkdown") else "",
                })

            with open(path, "w") as f:
                json.dump({"findings": records, "total": len(records)}, f, indent=2)

            self._status_lbl.setText("Exported {0} finding(s) to {1}".format(
                len(records), path))
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
        self._apply_filter()

    def _apply_filter(self):
        """Rebuild list model from _all_findings using current filter, keeping placeholders."""
        self._list_model.clear()
        # Re-add active placeholders first
        for ph in sorted(self._placeholders):
            self._list_model.addElement(ph)
        # Then add matching completed findings
        flt = self._filter_str
        count = 0
        for key, issue in self._all_findings.items():
            if not flt:
                self._list_model.addElement(key)
                count += 1
            else:
                # Match against display key (name+severity) OR the issue URL
                url_str = ""
                try:
                    url_str = str(issue.getUrl()).lower() if issue else ""
                except Exception:
                    pass
                if flt in key.lower() or flt in url_str:
                    self._list_model.addElement(key)
                    count += 1
        self._status_lbl.setText("{0} finding(s).".format(count))

    # -- result helpers (called from Scanner on EDT) ---------------------------

    def add_placeholder(self, url, auto_filter=True):
        """Add an in-progress placeholder. Returns a collision-free UUID key."""
        key = "[...] Analyzing - " + url + " #" + str(_uuid_mod.uuid4())[:8]
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
        return key

    def update_results(self, placeholder_key, issues):
        """Replace placeholder with completed findings and refresh filtered list."""
        # Remove placeholder
        self._placeholders.discard(placeholder_key)
        for i in range(self._list_model.getSize()):
            if self._list_model.getElementAt(i) == placeholder_key:
                self._list_model.remove(i)
                break

        # Store completed findings
        for issue in issues:
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
            if detail_md.strip():
                sections.append("## Issue Detail\n\n" + detail_md.strip())
            if bg_md.strip():
                sections.append("## Issue Background\n\n" + bg_md.strip())
            if remediation_md.strip():
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
            else:
                self._editor_controller.set_message(None)
                self._req_editor.setMessage([], True)
                self._resp_editor.setMessage([], False)
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
        # Stripe + bg + fg per severity
        _STYLES = {
            "High":        (Color(0xF44336), Color(0xFFEBEE), Color(0xB71C1C), Font.BOLD),
            "Medium":      (Color(0xFF9800), Color(0xFFF8E1), Color(0xE65100), Font.PLAIN),
            "Low":         (Color(0x2196F3), Color(0xE3F2FD), Color(0x0D47A1), Font.PLAIN),
            "Information": (Color(0x9E9E9E), Color(0xF5F5F5), Color(0x424242), Font.PLAIN),
            "ph":          (Color(0xFF6B35), Color(0xFFFFFF), Color(0xAAAAAA), Font.ITALIC),
            "fp":          (Color(0xBDBDBD), Color(0xFFFFFF), Color(0xAAAAAA), Font.ITALIC),
            "default":     (Color(0x9E9E9E), Color(0xFFFFFF), Color(0x212121), Font.PLAIN),
        }
        _SEL_BG = Color(0xE8EAF6)
        _SEL_FG = Color(0x1A237E)

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

            stripe_c, bg_c, fg_c, font_style = self._STYLES[key]

            # Left stripe + padding border
            stripe = BorderFactory.createMatteBorder(0, 4, 0, 0, stripe_c)
            pad    = BorderFactory.createEmptyBorder(3, 7, 3, 6)
            comp.setBorder(BorderFactory.createCompoundBorder(stripe, pad))

            # Font
            comp.setFont(comp.getFont().deriveFont(font_style))

            if isSelected:
                comp.setBackground(self._SEL_BG)
                comp.setForeground(self._SEL_FG)
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
