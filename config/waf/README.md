# Mitsu-WaF
This is the built-in WaF (Web Application Firewall).

It uses a set of rules to identify and block malicious requests. </br>
In addition, it can be configured to block requests based on the user-agent, IP address, and other parameters.

## Configuration

The configuration file is located at `src/waf/rules.rb`.

The rules are defined as a hash, where the key is the rule name and the value is a regular expression.

## Example of a rule

```ruby
[
  {
    "name": "SQL Injection (A)",
    "level": "high",
    "section": ['agent','body','headers'],
    "regex": ["((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))"],
    "action": "drop"
  }
]

```

- `name`: Rule name
- `level`: Rule level (high, medium, low)
- `section`: Where the rule will be applied (agent, body, headers)
- `regex`: Regular expression to match the rule
- `action`: Action to be taken when the rule is matched (drop, blockpage,maskblock, log)

## Rule levels
- `high`: Rules that are very likely to be malicious | Or that can cause a lot of damage
- `medium`: Rules that are likely to be malicious | Or that can cause some damage
- `low`: Rules that are unlikely to be malicious | Or that can cause little damage

## Actions
- `drop`: Drops the request without any response (Kills the underlying connection)
- `blockpage`: Blocks the request and returns a block page (HTTP 403)
- `maskblock`: Blocks the request and returns a masked block page This is useful to avoid fingerprinting attacks / Bots that try to identify the WAF (HTTP 200)
- `log`: Logs the request and allows it to pass through

## Rule sections
- `agent`: User-Agent
- `body`: Request body
- `headers`: Request headers