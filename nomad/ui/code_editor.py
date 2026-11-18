"""The Editor page's text editor (QScintilla, the engine Notepad++ is built on): Cisco highlighting and folding by
mode, XML for pfSense, line numbers, column selection (Alt+drag), and a Find/Replace bar with regular expressions."""
import re

from PyQt5.Qsci import QsciLexerCustom, QsciLexerXML, QsciScintilla
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QToolButton, QVBoxLayout, QWidget

from .common import set_hint
from .theme import COLORS, monospace_font

CISCO, XML, PLAIN = "cisco", "xml", "plain"
LANGUAGE_NAMES = {CISCO: "Cisco config", XML: "XML", PLAIN: "Plain text"}

# Cisco styles
DEFAULT, COMMENT, MODE, NEGATION, ADDRESS, SECRET, KEYWORD = range(7)
STYLE_COLORS = {DEFAULT: COLORS["text"], COMMENT: COLORS["muted"], MODE: COLORS["accent"], NEGATION: "#ff9e64",
                ADDRESS: COLORS["link"], SECRET: COLORS["warning"], KEYWORD: "#c792ea"}
STYLE_NAMES = {DEFAULT: "Default", COMMENT: "Comment", MODE: "Mode", NEGATION: "No", ADDRESS: "Address",
               SECRET: "Secret", KEYWORD: "Keyword"}
MODE_WORDS = re.compile(r"^(?:interface|router|line|ip access-list|ipv6 access-list|route-map|class-map|policy-map|"
                        r"vlan|vrf definition|ip vrf|key chain|crypto|object-group|controller|address-family|"
                        r"monitor session|aaa group server|ip dhcp pool|track|ip sla|event manager applet|"
                        r"spanning-tree mst configuration|redundancy|archive|control-plane|template|"
                        r"af-interface|topology|policy-list|zone|zone-pair|parameter-map)\b")
ADDRESS_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}"
                             r"(?:/\d{1,3})?\b")
SECRET_PATTERN = re.compile(r"\b(?:secret|password|key|community|pre-shared-key|key-string|authentication-key)"
                            r"(?:\s+[0-9])?\s+(\S+)")
KEYWORD_PATTERN = re.compile(r"\b(?:permit|deny|shutdown|remark)\b")

# Markers the Compare view puts on lines
MARK_ADDED, MARK_REMOVED, MARK_CHANGED, MARK_MOVED, MARK_HIDDEN, MARK_COPY, MARK_CURRENT = range(7)
MARK_COLORS = {MARK_ADDED: "#1d4a32", MARK_REMOVED: "#5a2326", MARK_CHANGED: "#4d4120", MARK_MOVED: "#1f3550",
               MARK_HIDDEN: "#1c232b", MARK_CURRENT: "#2d3a46"}
SYMBOL_MARGIN, FOLD_MARGIN = 1, 2


def qcolor(name):
    return QColor(COLORS.get(name, name))


class CiscoLexer(QsciLexerCustom):
    """Colors for a configuration, and folding by indentation: each mode (interface, router bgp...) folds away."""

    def __init__(self, parent):
        super().__init__(parent)
        font = monospace_font()
        for style, color in STYLE_COLORS.items():
            self.setColor(QColor(color), style)
            self.setPaper(qcolor("input"), style)
            self.setFont(QFont(font.family(), font.pointSize(), QFont.Bold if style == MODE else QFont.Normal), style)
        self.setDefaultPaper(qcolor("input"))
        self.setDefaultColor(qcolor("text"))
        self.setDefaultFont(font)

    def language(self):
        return "Cisco"

    def description(self, style):
        return STYLE_NAMES.get(style, "")

    def styleText(self, start, end):
        editor = self.editor()
        if editor is None:
            return
        first = editor.SendScintilla(QsciScintilla.SCI_LINEFROMPOSITION, start)
        last = editor.SendScintilla(QsciScintilla.SCI_LINEFROMPOSITION, end)
        first = max(first - 1, 0)  # The line before may have become a mode (folding)
        count = editor.lines()
        for line in range(first, min(last, count - 1) + 1):
            text = editor.text(line)
            position = editor.SendScintilla(QsciScintilla.SCI_POSITIONFROMLINE, line)
            self.startStyling(position)
            for length, style in line_styles(text):
                self.setStyling(length, style)
            editor.SendScintilla(QsciScintilla.SCI_SETFOLDLEVEL, line, fold_level(text, editor.text(line + 1)
                                                                                    if line + 1 < count else ""))


def indent_of(text):
    stripped = text.rstrip("\r\n")
    return len(stripped) - len(stripped.lstrip(" \t")) if stripped.strip() else None


def fold_level(text, following):
    level = QsciScintilla.SC_FOLDLEVELBASE
    indent = indent_of(text)
    if indent is None or text.strip().startswith("!"):
        return level + 0 | QsciScintilla.SC_FOLDLEVELWHITEFLAG
    after = indent_of(following)
    flags = QsciScintilla.SC_FOLDLEVELHEADERFLAG if after is not None and after > indent and \
        not following.strip().startswith("!") else 0
    return (level + min(indent, 4000)) | flags


def line_styles(text):
    """[(length in bytes, style)] for one line (newline included)."""
    stripped = text.lstrip()
    if stripped.startswith("!") or stripped.startswith("#"):
        return [(len(text.encode("utf-8")), COMMENT)]
    spans = []  # (start, end, style) in characters
    body = text.rstrip("\r\n")
    indent = len(body) - len(body.lstrip())
    content = body[indent:]
    if content.startswith("no "):
        spans.append((indent, indent + 2, NEGATION))
    elif indent == 0 and MODE_WORDS.match(content):
        spans.append((0, len(body), MODE))
    for match in KEYWORD_PATTERN.finditer(body):
        spans.append((match.start(), match.end(), KEYWORD))
    for match in ADDRESS_PATTERN.finditer(body):
        spans.append((match.start(), match.end(), ADDRESS))
    for match in SECRET_PATTERN.finditer(body):
        spans.append((match.start(1), match.end(1), SECRET))
    styles = [DEFAULT] * len(text)
    for start, end, style in spans:  # Later ones win (a secret over an address)
        for index in range(start, min(end, len(styles))):
            if style != MODE or styles[index] == DEFAULT:
                styles[index] = style
    runs = []
    for index, character in enumerate(text):
        size = len(character.encode("utf-8"))
        if runs and runs[-1][1] == styles[index]:
            runs[-1][0] += size
        else:
            runs.append([size, styles[index]])
    return [(length, style) for length, style in runs]


def language_for(path="", sample=""):
    """Which highlighting suits a file: XML for .xml files and pfSense configs, else Cisco."""
    if path.lower().endswith((".xml", ".html", ".htm")) or sample.lstrip().startswith(("<?xml", "<pfsense")):
        return XML
    return CISCO


class CodeEditor(QsciScintilla):
    """One file's editor."""
    focused = pyqtSignal()

    def __init__(self, parent=None, read_only=False):
        super().__init__(parent)
        self.setUtf8(True)
        self.setEolMode(QsciScintilla.EolUnix)
        self.setWrapMode(QsciScintilla.WrapNone)
        self.setTabWidth(4)
        self.setIndentationsUseTabs(False)
        self.setAutoIndent(True)
        font = monospace_font()
        self.setFont(font)
        self.setMarginsFont(font)
        self.setMarginType(0, QsciScintilla.NumberMargin)
        self.setMarginWidth(0, "00000")
        self.setMarginType(SYMBOL_MARGIN, QsciScintilla.SymbolMargin)
        self.setMarginWidth(SYMBOL_MARGIN, 0)
        self.setMarginsBackgroundColor(qcolor("panel"))
        self.setMarginsForegroundColor(qcolor("muted"))
        self.setFolding(QsciScintilla.BoxedTreeFoldStyle, FOLD_MARGIN)
        self.setFoldMarginColors(qcolor("panel"), qcolor("panel"))
        self.setCaretForegroundColor(qcolor("accent"))
        self.setCaretLineVisible(True)
        self.setCaretLineBackgroundColor(qcolor("panel_alt"))
        self.setSelectionBackgroundColor(QColor("#264f78"))
        self.setSelectionForegroundColor(qcolor("text"))
        self.setPaper(qcolor("input"))
        self.setColor(qcolor("text"))
        self.setMatchedBraceBackgroundColor(qcolor("hover"))
        self.setIndentationGuides(False)
        self.setAnnotationDisplay(QsciScintilla.AnnotationStandard)
        # Alt+drag selects a column; typing then goes into every line of it, as in Notepad++
        self.SendScintilla(QsciScintilla.SCI_SETMULTIPLESELECTION, True)
        self.SendScintilla(QsciScintilla.SCI_SETADDITIONALSELECTIONTYPING, True)
        self.SendScintilla(QsciScintilla.SCI_SETMULTIPASTE, 1)
        self.SendScintilla(QsciScintilla.SCI_SETRECTANGULARSELECTIONMODIFIER, QsciScintilla.SCMOD_ALT)
        for marker, color in MARK_COLORS.items():
            self.markerDefine(QsciScintilla.Background, marker)
            self.setMarkerBackgroundColor(QColor(color), marker)
        self.language = PLAIN
        self.set_language(CISCO)
        self.setReadOnly(read_only)
        self.linesChanged.connect(self.fit_line_numbers)

    def set_language(self, language):
        if language == self.language:
            return
        self.language = language
        if language == CISCO:
            self.setLexer(CiscoLexer(self))
        elif language == XML:
            lexer = QsciLexerXML(self)
            lexer.setDefaultPaper(qcolor("input"))
            lexer.setPaper(qcolor("input"), -1)
            lexer.setDefaultColor(qcolor("text"))
            for style in range(0, 32):
                lexer.setPaper(qcolor("input"), style)
                lexer.setFont(monospace_font(), style)
            lexer.setColor(qcolor("text"), QsciLexerXML.Default)
            lexer.setColor(qcolor("accent"), QsciLexerXML.Tag)
            lexer.setColor(qcolor("link"), QsciLexerXML.Attribute)
            lexer.setColor(qcolor("warning"), QsciLexerXML.HTMLDoubleQuotedString)
            lexer.setColor(qcolor("muted"), QsciLexerXML.HTMLComment)
            self.setLexer(lexer)
        else:
            self.setLexer(None)
            self.setPaper(qcolor("input"))
            self.setColor(qcolor("text"))
            self.setFont(monospace_font())
        self.setMarginsBackgroundColor(qcolor("panel"))
        self.setMarginsForegroundColor(qcolor("muted"))
        self.setFoldMarginColors(qcolor("panel"), qcolor("panel"))

    def fit_line_numbers(self):
        self.setMarginWidth(0, "0" * (len(str(self.lines())) + 2))

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self.focused.emit()

    def set_text_keeping_place(self, text):
        line = self.firstVisibleLine()
        self.setText(text)
        self.setFirstVisibleLine(line)

    def go_to(self, line):
        """Put line in view (a few lines down from the top) with the cursor at its start."""
        line = max(0, min(line, self.lines() - 1))
        self.setCursorPosition(line, 0)
        visible = self.SendScintilla(QsciScintilla.SCI_VISIBLEFROMDOCLINE, line)
        self.setFirstVisibleLine(max(visible - 3, 0))

    def replace_lines(self, start, end, lines):
        """Put lines in place of lines start..end (end not included; start == end: insert), as one undo step."""
        count = self.lines()
        if end < count:
            first = self.SendScintilla(QsciScintilla.SCI_POSITIONFROMLINE, start)
            last = self.SendScintilla(QsciScintilla.SCI_POSITIONFROMLINE, end)
            replacement = "".join(line + "\n" for line in lines)
        else:
            last = self.SendScintilla(QsciScintilla.SCI_GETLENGTH)
            if start > 0:
                first = self.SendScintilla(QsciScintilla.SCI_GETLINEENDPOSITION, min(start, count) - 1)
                replacement = "".join("\n" + line for line in lines)
            else:
                first = 0
                replacement = "\n".join(lines)
        data = replacement.encode("utf-8")
        self.beginUndoAction()
        self.SendScintilla(QsciScintilla.SCI_SETTARGETSTART, first)
        self.SendScintilla(QsciScintilla.SCI_SETTARGETEND, last)
        self.SendScintilla(QsciScintilla.SCI_REPLACETARGET, len(data), data)
        self.endUndoAction()


class FindBar(QWidget):
    """Find and Replace for the editor in front: regular expressions (ECMAScript, as in Notepad++), match case,
    whole word; Replace All is one undo step."""
    closed = pyqtSignal()

    def __init__(self, parent, editor_getter):
        super().__init__(parent)
        self.editor_getter = editor_getter
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)
        row = QHBoxLayout()
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find")
        self.find_input.setClearButtonEnabled(True)
        self.regex = QCheckBox("Regular expression")
        self.case = QCheckBox("Match case")
        self.word = QCheckBox("Whole word")
        previous_button, next_button, count_button = QPushButton("Previous"), QPushButton("Next"), QPushButton("Count")
        close_button = QToolButton()
        close_button.setText("✕")
        close_button.setToolTip("Close (Esc)")
        close_button.setAutoRaise(True)
        for widget in (self.find_input, self.regex, self.case, self.word, previous_button, next_button, count_button,
                       close_button):
            row.addWidget(widget, 1 if widget is self.find_input else 0)
        layout.addLayout(row)
        self.replace_row = QWidget()
        replace_layout = QHBoxLayout(self.replace_row)
        replace_layout.setContentsMargins(0, 0, 0, 0)
        self.replace_input = QLineEdit()
        self.replace_input.setPlaceholderText("Replace with (\\1 for a group, with Regular expression)")
        replace_button, replace_all_button = QPushButton("Replace"), QPushButton("Replace All")
        replace_layout.addWidget(self.replace_input, 1)
        replace_layout.addWidget(replace_button)
        replace_layout.addWidget(replace_all_button)
        layout.addWidget(self.replace_row)
        self.status = QLabel()
        layout.addWidget(self.status)
        self.find_input.returnPressed.connect(self.find_next)
        self.find_input.textChanged.connect(self.clear_status)
        next_button.clicked.connect(self.find_next)
        previous_button.clicked.connect(self.find_previous)
        count_button.clicked.connect(self.count)
        replace_button.clicked.connect(self.replace)
        replace_all_button.clicked.connect(self.replace_all)
        self.replace_input.returnPressed.connect(self.replace)
        close_button.clicked.connect(self.close_bar)
        self.setVisible(False)

    def show_bar(self, replacing):
        self.setVisible(True)
        self.replace_row.setVisible(replacing)
        editor = self.editor_getter()
        if editor is not None and editor.hasSelectedText() and "\n" not in editor.selectedText():
            self.find_input.setText(editor.selectedText())
        self.find_input.setFocus()
        self.find_input.selectAll()

    def close_bar(self):
        self.setVisible(False)
        self.closed.emit()

    def clear_status(self):
        self.status.setText("")

    def pattern_ok(self):
        if not self.regex.isChecked():
            return True
        try:
            re.compile(self.find_input.text())
        except re.error as error:
            set_hint(self.status, f"That regular expression doesn't work: {error}", "error")
            return False
        return True

    def find(self, forward=True, wrap=True):
        editor = self.editor_getter()
        text = self.find_input.text()
        if editor is None or not text or not self.pattern_ok():
            return False
        if not forward and editor.hasSelectedText():
            line, index, _, _ = editor.getSelection()  # Search backward from the start of what's found
        else:
            line, index = -1, -1
        found = editor.findFirst(text, self.regex.isChecked(), self.case.isChecked(), self.word.isChecked(), wrap,
                                 forward, line, index, True, False, True)
        if not found:
            set_hint(self.status, f"{text} isn't in it.", "warning")
        else:
            self.status.setText("")
        return found

    def find_next(self):
        return self.find(True)

    def find_previous(self):
        return self.find(False)

    def count(self):
        editor = self.editor_getter()
        if editor is None or not self.find_input.text() or not self.pattern_ok():
            return 0
        found = sum(1 for _ in self.python_pattern().finditer(editor.text()))
        set_hint(self.status, f"{found} match{'es' if found != 1 else ''}.", "info" if found else "warning")
        return found

    def python_pattern(self):
        flags = (0 if self.case.isChecked() else re.IGNORECASE) | re.MULTILINE
        pattern = self.find_input.text() if self.regex.isChecked() else re.escape(self.find_input.text())
        if self.word.isChecked():
            pattern = rf"\b(?:{pattern})\b"
        return re.compile(pattern, flags)

    def replacement(self):
        """What replaces a match: the text as typed, or (regular expression) with its \\1 groups."""
        text = self.replace_input.text()
        return text if self.regex.isChecked() else text.replace("\\", "\\\\")

    def replace(self):
        editor = self.editor_getter()
        if editor is None or editor.isReadOnly() or not self.find_input.text() or not self.pattern_ok():
            return
        if editor.hasSelectedText():
            selected = editor.selectedText()
            pattern = self.python_pattern()
            if pattern.fullmatch(selected):
                try:
                    editor.replaceSelectedText(pattern.sub(self.replacement(), selected, count=1))
                except re.error as error:
                    set_hint(self.status, f"The replacement doesn't work: {error}", "error")
                    return
        self.find_next()

    def replace_all(self):
        """Every match replaced, as one undo step."""
        editor = self.editor_getter()
        if editor is None or editor.isReadOnly() or not self.find_input.text() or not self.pattern_ok():
            return 0
        text = editor.text()
        try:
            changed, replaced = self.python_pattern().subn(self.replacement(), text)
        except re.error as error:
            set_hint(self.status, f"The replacement doesn't work: {error}", "error")
            return 0
        if replaced:
            line, index = editor.getCursorPosition()
            first = editor.firstVisibleLine()
            data = changed.encode("utf-8")
            editor.beginUndoAction()
            editor.SendScintilla(QsciScintilla.SCI_SETTARGETSTART, 0)
            editor.SendScintilla(QsciScintilla.SCI_SETTARGETEND, editor.SendScintilla(QsciScintilla.SCI_GETLENGTH))
            editor.SendScintilla(QsciScintilla.SCI_REPLACETARGET, len(data), data)
            editor.endUndoAction()
            editor.setFirstVisibleLine(first)
            editor.setCursorPosition(min(line, editor.lines() - 1), 0)
        set_hint(self.status, f"Replaced {replaced}.", "success" if replaced else "warning")
        return replaced
