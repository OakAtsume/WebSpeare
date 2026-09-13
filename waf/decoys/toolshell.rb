require_relative("../../src/firewall")

# Interactive decoy — SharePoint "ToolShell" (CVE-2025-53770 / CVE-2025-49704).
#
# Contract (same as the other decoys):
# {
#   :triggered => true/false,
#   :overwrite => true/false,
#   :reason    => String,
#   :payload   => nil/String,
#   :code      => Int   # only when overwrite is true
# }
#
# The real chain is two stages:
#   1) POST /_layouts/15/ToolPane.aspx  (Referer: /_layouts/SignOut.aspx) with an
#      MSOTlPn_DWP ExcelDataSet gadget → deserialization writes a webshell
#      (canonically spinstall0.aspx) into the SharePoint layouts dir.
#   2) GET /_layouts/15/spinstall0.aspx → the webshell prints the ASP.NET
#      machineKey (ValidationKey + DecryptionKey). With those, the attacker forges
#      a signed __VIEWSTATE for persistent RCE.
#
# This decoy plays a vulnerable SharePoint:
#   - Stage 1 POST → HTTP 200 with SharePoint/IIS-looking headers + a tool-pane
#     HTML stub, so the attacker's tooling believes the gadget landed.
#   - Stage 2 GET (spinstall & known aliases) → serves CANARY machine keys.
# The point: they "win", bank fake keys, and their stage-3 ViewState RCE attempt
# comes back to us (captured in logs) instead of hitting a real victim.
#
# ── CANARIES ────────────────────────────────────────────────────────────────
# The keys below are fake but valid-format hex (ysoserial.net will accept them).
# They're recognizable to YOU — grep your SIEM for "5EA5E7C0DEC0FFEE". For live
# phone-home on use, swap in a canarytokens.org "fake ASP.NET machine key" token.
class ToolShellDecoy
  # 128-hex ValidationKey, 48-hex DecryptionKey (both canaries).
  VALIDATION_KEY = ("5EA5E7C0DEC0FFEE" * 8).freeze
  DECRYPTION_KEY = ("5EA5E7C0DEC0FFEE" * 3).freeze

  TOOLPANE = %r{\A/_layouts/(15/)?toolpane\.aspx\z}i
  # spinstall0.aspx is canonical; the rest are documented ToolShell webshell/
  # artifact names seen in the wild. Kept to a curated list (not a generic
  # *.aspx catch-all) so legit SharePoint page names don't wrongly leak "keys".
  WEBSHELL = %r{\A/_layouts/(15/)?(spinstall\d*|ghostfile\w*|info\d+|xxx+|shell|z0|debug_dev)\.aspx\z}i

  SP_HEADERS = {
    "Server" => "Microsoft-IIS/10.0",
    "X-Powered-By" => "ASP.NET",
    "X-AspNet-Version" => "4.0.30319",
    "MicrosoftSharePointTeamServices" => "16.0.0.10417",
    "X-SharePointHealthScore" => "0",
    "SPRequestGuid" => "00000000-0000-0000-0000-000000000000",
  }.freeze

  def runCheck(request, serverInstance)
    path = request[:path].to_s
    base = path.split("?").first.to_s

    # Stage 1 — the ToolPane.aspx exploit POST
    if ["POST", "GET"].include?(request[:method]) &&
       (base =~ TOOLPANE || request[:body].to_s.include?("MSOTlPn_DWP") || request[:body].to_s.include?("MSOTlPn_Uri"))
      body = toolpane_ok_html
      payload = serverInstance.genReply(200, body, serverInstance.mimeFor(".html"), SP_HEADERS)
      return {
        triggered: true,
        overwrite: true,
        reason: "Decoy-ToolShell ToolPane.aspx exploit accepted (CVE-2025-53770)",
        payload: payload,
        code: 200,
      }
    end

    # Stage 2 — retrieval of the dropped webshell (machineKey leak)
    if request[:method] == "GET" && base =~ WEBSHELL
      body = "#{VALIDATION_KEY}|#{DECRYPTION_KEY}|HMACSHA256|AES"
      payload = serverInstance.genReply(200, body, "text/plain", SP_HEADERS)
      return {
        triggered: true,
        overwrite: true,
        reason: "Decoy-ToolShell webshell retrieval — served canary machineKeys (#{base})",
        payload: payload,
        code: 200,
      }
    end

    { triggered: false, overwrite: false, reason: "blank", payload: nil }
  end

  private

  def toolpane_ok_html
    # Minimal but plausible ToolPane edit-mode response. Tooling keys off the
    # 200 + SharePoint headers, not the exact markup.
    <<~HTML
      <!DOCTYPE html>
      <html dir="ltr" lang="en-US">
      <head><title></title><meta name="GENERATOR" content="Microsoft SharePoint" /></head>
      <body>
        <form method="post" action="ToolPane.aspx" id="aspnetForm">
          <div id="MSOTlPn_MainDiv" class="ms-TPBody"><!-- tool pane --></div>
          <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="" />
        </form>
      </body>
      </html>
    HTML
  end
end
