require_relative("../../src/firewall")
require "json"

# Interactive decoy — App Config & Secret File harvesting.
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
# Target: the dominant web campaign that force-browses for framework config and
# secret files (/appsettings.json /.env /application.yml /web.config /settings.py
# /database.yml /secrets.yaml /credentials.json ...) hunting DB creds, cloud keys
# and SSH material.
#
# A real misconfigured server would return the file. This decoy plays along and
# serves a believable file whose secrets are ALL CANARIES. The scanner "wins",
# banks the creds, and their follow-up either lands back in our logs or trips an
# external canary. (Proven: the fake svc_app/Pr0d_Db!7f3a9c2e pair below has been
# replayed against our SSH sensor by 14+ IPs — confirmed harvest→reuse.)
#
# ── CANARY VALUES ────────────────────────────────────────────────────────────
# Values are loaded at startup from config/canary.json (gitignored — real token
# values must NOT be committed to a public repo, or the canary is burned). The
# hardcoded defaults below are placeholders / already-public fallbacks used only
# when canary.json is absent. See config/canary.json.example for the schema.
#
#  - aws.access_key_id / secret_access_key  → an "AWS keys" canarytoken
#    (canarytokens.org). Alerts the instant the key is USED anywhere against AWS.
class ConfigSecretsDecoy
  # already-public fallbacks (used only if config/canary.json is missing a value)
  DEFAULTS = {
    aws_key:     "AKIA5SPEARE7QH0NEYPT",
    aws_secret:  "wJal9SpEaReXhk/K7MDENG+bPxRfiCYHONEYcanaR",
    region:      "us-east-1",
    db_user:     "svc_app",
    db_pass:     "Pr0d_Db!7f3a9c2e",
    db_host:     "10.20.0.14",
    jwt:         "eyJprod-signing-9f2c1b7a4e6d8c05-do-not-share",
    api:         "sk_live_5speare_1c9f4a7be2d6089c3f5a1b",
    canary_host: "vault-internal.corp-metrics.net",
  }.freeze

  MATCHES = {
    "appsettings.json"       => :dotnet_appsettings,
    "web.config"             => :dotnet_webconfig,
    "application.yml"        => :spring_yaml,
    "application.yaml"       => :spring_yaml,
    "application.properties" => :spring_properties,
    "settings.py"            => :django_settings,
    "local_settings.py"      => :django_settings,
    ".env"                   => :dotenv,
    ".env.local"             => :dotenv,
    ".env.production"        => :dotenv,
    "database.yml"           => :rails_database,
    "secrets.yml"            => :rails_secrets,
    "secrets.yaml"           => :rails_secrets,
    "credentials.json"       => :gcp_credentials,
  }.freeze

  def initialize(config_path = "config/canary.json")
    cfg = {}
    begin
      cfg = JSON.parse(File.read(config_path)) if File.exist?(config_path)
    rescue => e
      warn "ConfigSecretsDecoy: could not parse #{config_path} (#{e.message}); using defaults"
    end
    aws = cfg["aws"] || {}
    db  = cfg["db"]  || {}

    @aws_key     = pick(aws["access_key_id"],     :aws_key)
    @aws_secret  = pick(aws["secret_access_key"], :aws_secret)
    @region      = present(aws["region"]) || DEFAULTS[:region]
    @db_user     = pick(db["user"], :db_user)
    @db_pass     = pick(db["pass"], :db_pass)
    @db_host     = pick(db["host"], :db_host)
    @jwt         = pick(cfg["jwt_secret"], :jwt)
    @api         = pick(cfg["api_token"], :api)
    @canary_host = pick(cfg["canary_host"], :canary_host)
  end

  def runCheck(request, serverInstance)
    return passthrough unless ["GET", "HEAD"].include?(request[:method])
    path = request[:path].to_s
    return passthrough if path.empty?

    base = path.split("?").first.to_s.split("/").last.to_s.downcase
    gen = MATCHES[base]
    gen ||= :dotnet_appsettings if base =~ /\Aappsettings\..+\.json\z/
    return passthrough unless gen

    body, ext = send(gen)
    payload = serverInstance.genReply(200, body, serverInstance.mimeFor(ext))
    {
      triggered: true,
      overwrite: true,
      reason: "Decoy-Config/Secret Harvest (served canaried #{base})",
      payload: payload,
      code: 200,
    }
  end

  private

  def present(v) = (v && !v.to_s.strip.empty?) ? v.to_s : nil
  def pick(v, key) = present(v) || DEFAULTS[key]

  def passthrough
    { triggered: false, overwrite: false, reason: "blank", payload: nil }
  end

  def dotnet_appsettings
    aws = { "Region" => @region, "AccessKey" => @aws_key, "SecretKey" => @aws_secret }
    body = JSON.pretty_generate({
      "Logging" => { "LogLevel" => { "Default" => "Information", "Microsoft.AspNetCore" => "Warning" } },
      "AllowedHosts" => "*",
      "ConnectionStrings" => {
        "DefaultConnection" => "Server=#{@db_host};Database=app_prod;User Id=#{@db_user};Password=#{@db_pass};TrustServerCertificate=True",
      },
      "Jwt" => { "Issuer" => "https://#{@canary_host}", "Key" => @jwt, "ExpireMinutes" => 60 },
      "AWS" => aws,
      "Stripe" => { "SecretKey" => @api },
    })
    [body, ".json"]
  end

  def dotnet_webconfig
    body = <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <configuration>
        <connectionStrings>
          <add name="DefaultConnection" connectionString="Server=#{@db_host};Database=app_prod;User Id=#{@db_user};Password=#{@db_pass};" providerName="System.Data.SqlClient" />
        </connectionStrings>
        <appSettings>
          <add key="AWSAccessKey" value="#{@aws_key}" />
          <add key="AWSSecretKey" value="#{@aws_secret}" />
          <add key="AWSRegion" value="#{@region}" />
          <add key="JwtSigningKey" value="#{@jwt}" />
        </appSettings>
      </configuration>
    XML
    [body, ".xml"]
  end

  def spring_yaml
    body = <<~YML
      spring:
        datasource:
          url: jdbc:mysql://#{@db_host}:3306/app_prod
          username: #{@db_user}
          password: #{@db_pass}
      cloud:
        aws:
          credentials:
            access-key: #{@aws_key}
            secret-key: #{@aws_secret}
          region:
            static: #{@region}
      jwt:
        secret: #{@jwt}
    YML
    [body, ".yml"]
  end

  def spring_properties
    body = +<<~PROPS
      spring.datasource.url=jdbc:mysql://#{@db_host}:3306/app_prod
      spring.datasource.username=#{@db_user}
      spring.datasource.password=#{@db_pass}
      cloud.aws.credentials.access-key=#{@aws_key}
      cloud.aws.credentials.secret-key=#{@aws_secret}
      cloud.aws.region.static=#{@region}
      jwt.secret=#{@jwt}
    PROPS
    [body, ".txt"]
  end

  def django_settings
    body = <<~PY
      # Django settings (production)
      import os

      SECRET_KEY = "#{@jwt}"
      DEBUG = False
      ALLOWED_HOSTS = ["#{@canary_host}"]

      DATABASES = {
          "default": {
              "ENGINE": "django.db.backends.postgresql",
              "NAME": "app_prod",
              "USER": "#{@db_user}",
              "PASSWORD": "#{@db_pass}",
              "HOST": "#{@db_host}",
              "PORT": "5432",
          }
      }

      AWS_ACCESS_KEY_ID = "#{@aws_key}"
      AWS_SECRET_ACCESS_KEY = "#{@aws_secret}"
      AWS_DEFAULT_REGION = "#{@region}"
      AWS_STORAGE_BUCKET_NAME = "app-prod-assets"
    PY
    [body, ".txt"]
  end

  def dotenv
    lines = [
      "APP_ENV=production",
      "APP_DEBUG=false",
      "APP_URL=https://#{@canary_host}",
      "DB_CONNECTION=mysql",
      "DB_HOST=#{@db_host}",
      "DB_PORT=3306",
      "DB_DATABASE=app_prod",
      "DB_USERNAME=#{@db_user}",
      "DB_PASSWORD=#{@db_pass}",
      "AWS_ACCESS_KEY_ID=#{@aws_key}",
      "AWS_SECRET_ACCESS_KEY=#{@aws_secret}",
      "AWS_DEFAULT_REGION=#{@region}",
      "JWT_SECRET=#{@jwt}",
      "STRIPE_SECRET=#{@api}",
    ]
    [lines.join("\n") + "\n", ".txt"]
  end

  def rails_database
    body = <<~YML
      production:
        adapter: postgresql
        encoding: unicode
        database: app_prod
        username: #{@db_user}
        password: #{@db_pass}
        host: #{@db_host}
        port: 5432
    YML
    [body, ".yml"]
  end

  def rails_secrets
    body = +<<~YML
      production:
        secret_key_base: #{@jwt}
        aws_access_key_id: #{@aws_key}
        aws_secret_access_key: #{@aws_secret}
        aws_region: #{@region}
    YML
    [body, ".yml"]
  end

  def gcp_credentials
    body = JSON.pretty_generate({
      "type" => "service_account",
      "project_id" => "app-prod-241807",
      "private_key_id" => "1c9f4a7be2d6089c3f5a1b0e8d4a2c6f9b3e7d15",
      "private_key" => "-----BEGIN PRIVATE KEY-----\\nMIIBVAIBADANBg...CANARY...redacted\\n-----END PRIVATE KEY-----\\n",
      "client_email" => "app-prod@app-prod-241807.iam.gserviceaccount.com",
      "token_uri" => "https://oauth2.googleapis.com/token",
    })
    [body, ".json"]
  end
end
