require_relative("../../src/firewall")
require "digest"

# This is a Decoy rule (interactive).
# Any Given Rule must reply with a hash of
# {
#   :triggered => true/false,
#   :overwrite => true/false,
#   :reason    => String,
#   :payload   => nil/String,
#   :code      => Int : Only if overwrite is true.
# }
#
# Target: PHPUnit "eval-stdin.php" Remote Code Execution probing (CVE-2017-9841)
# and the generic PHP-CGI / Laravel-Ignition style RCE confirmation probes.
#
# Mass scanners POST raw PHP to paths like:
#   /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
#   /lib/phpunit/.../eval-stdin.php   (+ dozens of prefix variants)
# with a confirmation body such as:
#   <?php echo(md5("Hello PHPUnit"));
#   <?php echo md5('phpunit_rce'); ?>
# If the host is vulnerable the PHP runs and the MD5 hex is echoed back. The
# scanner then knows the target is live and follows up with a real payload.
#
# This decoy plays along: it extracts the string inside md5("...") and returns
# its real digest, so the attacker believes they have code execution. Their
# follow-up payload then lands in our logs instead of on a real victim.
#
# NOTE: the existing RedTail decoy (priority 101) already answers the
# "Hello CVE-2024-4577" variant, so it short-circuits before this rule.
class PHPUnitRCEDecoy
  def initialize()
    # Capture the literal passed to a PHP md5() call: md5("X") or md5('X').
    @md5_call = /md5\(\s*["']([^"']{0,256})["']\s*\)/i
  end

  def runCheck(request, serverInstance)
    body = request[:body].to_s

    # Only engage when the body actually looks like injected PHP, so we don't
    # answer on incidental matches.
    looks_like_php = body.include?("<?php") || body.include?("<?=")

    if looks_like_php && (match = body.match(@md5_call))
      digest = Digest::MD5.hexdigest(match[1])

      reply = serverInstance.genReply(
        200,
        digest,
        serverInstance.mimeFor(".txt")
      )

      return {
        triggered: true,
        overwrite: true,
        reason: "Decoy-PHPUnit eval-stdin RCE (CVE-2017-9841) — echoed md5(#{match[1].inspect})",
        payload: reply,
        code: 200,
      }
    end

    return {
      triggered: false,
      overwrite: false,
      reason: "blank",
      payload: nil,
    }
  end
end
