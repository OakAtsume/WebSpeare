require "socket"
require "openssl"
require "thread"
require "securerandom"
require "json"
require "uri"
require "time"
require_relative("../src/back") # HoneySet
require "maxmind/geoip2"
require "fileutils"

# ============================================================================
#  WebSpeare Attack Map  —  rebuilt 2026-06
#
#  Pipeline:   logs/json/*.json  ──tail──▶  parse/classify  ──▶  Hub
#                                                                  │
#                          SSE  /api/stream  ◀── broadcast ────────┤
#                          GET  /api/recent  ◀── ring buffer ──────┤
#                          GET  /api/stats   ◀── live aggregates ──┘
#
#  Self-contained: the frontend ships its own (vector) world map and pulls no
#  external CDNs, so the map runs on an isolated lab network with no internet.
# ============================================================================

# --- LogTailer -------------------------------------------------------------
# Efficiently reads appended lines from a log file; survives rotation/truncation.
class LogTailer
  def initialize(log_file_path)
    @log_file_path = log_file_path
    @file_handle = nil
    @last_pos = 0
    @last_inode = nil
    initial_file_setup
  end

  def initial_file_setup
    dir = File.dirname(@log_file_path)
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    FileUtils.touch(@log_file_path) unless File.exist?(@log_file_path)

    @file_handle.close if @file_handle && !@file_handle.closed?

    begin
      @file_handle = File.open(@log_file_path, "r")
      @file_handle.seek(0, IO::SEEK_END)
      @last_pos = @file_handle.pos
      @last_inode = File.stat(@log_file_path).ino
      puts "LogTailer: tailing '#{@log_file_path}' from byte #{@last_pos}"
    rescue Errno::ENOENT
      @file_handle = nil; @last_pos = 0; @last_inode = nil
      puts "LogTailer: '#{@log_file_path}' not found yet; will retry."
    rescue => e
      puts "LogTailer: setup error for '#{@log_file_path}': #{e.message}"
      @file_handle = nil; @last_pos = 0; @last_inode = nil
    end
  end

  def check_for_new_lines
    new_lines = []
    unless @file_handle && !@file_handle.closed?
      initial_file_setup
      return [] unless @file_handle
    end

    current_stat = (File.stat(@log_file_path) rescue nil)

    if current_stat.nil?
      @file_handle.close; @file_handle = nil; @last_pos = 0; @last_inode = nil
      return []
    elsif current_stat.ino != @last_inode
      puts "LogTailer: rotation detected; re-reading new file."
      initial_file_setup
      if @file_handle
        @file_handle.seek(0); @last_pos = 0
        read_lines_from_current_pos(new_lines)
      end
      return new_lines
    elsif current_stat.size < @last_pos
      @file_handle.seek(0); @last_pos = 0
    end

    read_lines_from_current_pos(new_lines) if current_stat.size > @last_pos
    new_lines
  rescue => e
    puts "LogTailer: read error: #{e.message}"
    @file_handle&.close
    @file_handle = nil; @last_pos = 0; @last_inode = nil
    []
  end

  def close
    @file_handle.close if @file_handle && !@file_handle.closed?
    @file_handle = nil
  end

  private

  def read_lines_from_current_pos(lines_array)
    while (line = @file_handle.gets)
      lines_array << line.strip
    end
    @last_pos = @file_handle.pos
  end
end

# --- Classification --------------------------------------------------------
module Classify
  SEVERITIES = %w[critical high medium low info].freeze

  # Reason strings emitted by the interactive decoys (src: waf/decoys/*.rb).
  DECOY_RX = /\bdecoy\b|react2shell|phpunit|cpanel|redtail|phpinfo|hello\.?world|
              CVE-2025-55182|CVE-2024-4577|CVE-2017-9841/ix

  module_function

  # Returns [severity, decoy?, cve] for a WAF rule name + optional level.
  def rule(name, level)
    cve   = name && name[/CVE-\d{4}-\d{3,7}/i]&.upcase
    decoy = !!(name =~ DECOY_RX)

    sev =
      if level && SEVERITIES.include?(level.to_s.downcase)
        level.to_s.downcase
      elsif decoy
        "high" # an attacker engaging a decoy is the highest-value event we see
      elsif name =~ /command injection|\brce\b|deserial|sql ?injection|\bsqli\b|traversal|upload|webshell|eval-stdin/i
        "critical"
      elsif name =~ /CVE-/i
        "high"
      elsif name =~ /enumerat|admin|wordpress|wp-|secret file|env\/git|backup|phpmyadmin/i
        "medium"
      elsif name =~ /anomal|non-standard|non-printable|control char|long request|options probe|asterisk/i
        "low"
      else
        "medium"
      end

    [sev, decoy, cve]
  end
end

# --- Geolocation -----------------------------------------------------------
module Geo
  module_function

  def private?(ip)
    return true if ip.nil? || ip.empty? || ip == "unknown"
    return true if ip =~ /\A127\.|\A10\.|\A192\.168\.|\A169\.254\./
    return true if ip =~ /\A172\.(1[6-9]|2\d|3[01])\./
    return true if ip == "::1" || ip =~ /\Afe80|\Afc|\Afd/i
    false
  end

  # Deterministic pseudo-location so a given lab IP always lands on the same dot.
  def scatter(ip)
    h = ip.to_s.each_byte.reduce(0) { |a, b| (a * 31 + b) & 0xffffffff }
    {
      lat: (((h % 12000) / 100.0) - 60.0).round(3),
      lon: ((((h >> 11) % 36000) / 100.0) - 180.0).round(3),
      country: "LAB", country_name: "Lab Network", city: "synthetic", lab: true,
    }
  end

  def locate(ip, reader, lab_mode)
    if private?(ip)
      return lab_mode ? scatter(ip) : nil
    end
    begin
      rec = reader.city(ip)
      return (lab_mode ? scatter(ip) : nil) unless rec.location.latitude
      {
        lat: rec.location.latitude, lon: rec.location.longitude,
        country: rec.country.iso_code, country_name: rec.country.name,
        city: rec.city.name, lab: false,
      }
    rescue MaxMind::GeoIP2::AddressNotFoundError
      lab_mode ? scatter(ip) : nil
    rescue => e
      puts "GeoIP error for #{ip}: #{e.message}"
      nil
    end
  end
end

# --- Timestamps ------------------------------------------------------------
# Logs have carried three shapes over time: int epoch, ISO-8601, and
# "YYYY-MM-DD HH:MM:SS ±ZZZZ". Normalize all of them to a UTC Time.
def normalize_time(ts)
  case ts
  when Numeric
    Time.at(ts).utc
  when String
    if ts =~ /\A\d{9,}\z/ then Time.at(ts.to_i).utc else Time.parse(ts).utc end
  else
    Time.now.utc
  end
rescue
  Time.now.utc
end

# Convert a raw honeypot log entry into a frontend-ready attack, or nil to skip.
def parse_entry(entry, reader, lab_mode)
  return nil unless entry.is_a?(Hash) && entry["host"]

  ip  = entry["host"]
  geo = Geo.locate(ip, reader, lab_mode)
  return nil unless geo # not locatable and lab mode off

  rule = entry["wafRule"]
  rule_name = case rule
              when Hash   then rule["name"]
              when String then rule
              end
  level     = rule.is_a?(Hash) ? rule["level"] : nil
  malformed = entry["malformed"] ? true : false

  if entry["waf"] && rule_name && !rule_name.empty?
    severity, decoy, cve = Classify.rule(rule_name, level)
    type = rule_name
  elsif malformed
    severity, decoy, cve = "low", false, nil
    type = entry["method"].to_s.include?("MALFORMED") ? "Malformed / Binary Payload" : "Malformed Request"
  else
    severity, decoy, cve = "info", false, nil
    type = "Web Request"
  end

  method = entry["method"].to_s
  path   = entry["path"].to_s
  path   = "/" if path.empty? && !malformed

  {
    ts: normalize_time(entry["timestamp"]).iso8601,
    ip: ip,
    lat: geo[:lat], lon: geo[:lon],
    country: geo[:country], country_name: geo[:country_name], city: geo[:city],
    lab: geo[:lab],
    severity: severity, decoy: decoy, cve: cve, malformed: malformed,
    type: type, method: method, path: path,
  }
end

# --- Hub: ring buffer + live stats + SSE fan-out ---------------------------
class Hub
  def initialize(ring_size:, origin:)
    @mutex   = Mutex.new
    @subs    = []           # open SSE sockets
    @ring    = []           # recent attacks (capped)
    @ring_sz = ring_size
    @origin  = origin
    @next_id = 0
    @stats = {
      total: 0, malformed: 0, decoys: 0, lab: 0,
      severity: Hash.new(0), countries: Hash.new(0),
      rules: Hash.new(0), cves: Hash.new(0),
    }
  end

  attr_reader :origin

  def record(attack, broadcast: true)
    @mutex.synchronize do
      @next_id += 1
      attack[:id] = @next_id
      @ring << attack
      @ring.shift while @ring.length > @ring_sz

      s = @stats
      s[:total]    += 1
      s[:malformed] += 1 if attack[:malformed]
      s[:decoys]   += 1 if attack[:decoy]
      s[:lab]      += 1 if attack[:lab]
      s[:severity][attack[:severity]] += 1
      s[:countries][attack[:country_name] || attack[:country] || "Unknown"] += 1
      s[:rules][attack[:type]] += 1 if attack[:type]
      s[:cves][attack[:cve]]   += 1 if attack[:cve]
    end
    broadcast("attack", attack) if broadcast
  end

  def recent_payload
    @mutex.synchronize do
      { origin: @origin, attacks: @ring.dup, stats: stats_unlocked }
    end
  end

  def stats_payload
    @mutex.synchronize { stats_unlocked }
  end

  def subscribe(socket)
    @mutex.synchronize { @subs << socket }
  end

  def unsubscribe(socket)
    @mutex.synchronize { @subs.delete(socket) }
  end

  def subscriber?(socket)
    @mutex.synchronize { @subs.include?(socket) }
  end

  def broadcast(event, data)
    frame = "event: #{event}\ndata: #{JSON.generate(data)}\n\n"
    dead = []
    targets = @mutex.synchronize { @subs.dup }
    targets.each do |s|
      begin
        s.write(frame)
      rescue
        dead << s
      end
    end
    unless dead.empty?
      @mutex.synchronize { dead.each { |s| @subs.delete(s) } }
      dead.each { |s| s.close rescue nil }
    end
  end

  def broadcast_stats
    broadcast("stats", stats_payload)
  end

  private

  # Caller must hold @mutex.
  def stats_unlocked
    {
      total: @stats[:total],
      malformed: @stats[:malformed],
      decoys: @stats[:decoys],
      lab: @stats[:lab],
      subscribers: @subs.length,
      severity: @stats[:severity],
      topCountries: top(@stats[:countries], 8),
      topRules: top(@stats[:rules], 8),
      topCves: top(@stats[:cves], 6),
    }
  end

  def top(hash, n)
    hash.sort_by { |_, v| -v }.first(n).map { |k, v| { name: k, count: v } }
  end
end

# ============================================================================
#  Boot
# ============================================================================
config    = JSON.parse(File.read("config.json"))
lab_mode  = config.fetch("labMode", true)
ring_size = config.fetch("ringBuffer", 750)
backfill  = config.fetch("backfill", 300)
stats_int = config.fetch("statsIntervalSeconds", 3)

reader = MaxMind::GeoIP2::Reader.new(database: "GeoLite2-City.mmdb")

origin = {
  lat:   config.dig("honeypot", "lat") || 40.7608,
  lon:   config.dig("honeypot", "lon") || -111.891,
  label: config.dig("honeypot", "label") || "WebSpeare honeypot",
}

hub = Hub.new(ring_size: ring_size, origin: origin)

server = HoneySet.new(
  host: config["server"]["host"],
  port: config["server"]["port"],
  reverseProxy: false,
  # back.rb's parser reaches into configs["redactPublicIP"]; give it a real
  # (disabled) entry so request parsing doesn't fault on every header.
  configs: { "redactPublicIP" => { "enabled" => false } },
)

html        = File.read("web/attack-map.html")
world_json  = File.read("web/world.json")

# --- Backfill: seed the ring buffer from recent log history (no broadcast) ---
def seed_files(logs_dir, fileformat)
  today = "#{logs_dir}/#{Time.now.strftime(fileformat)}.json"
  files = Dir.glob("#{logs_dir}/*.json").sort
  # Prefer today's file; fall back to the most recent ones so a fresh start
  # still shows context.
  picked = []
  picked << today if File.exist?(today)
  (files - picked).last(2).each { |f| picked.unshift(f) }
  picked.uniq
end

seeded = 0
seed_files(config["logs"], config["fileformat"]).each do |file|
  next unless File.exist?(file)
  lines = File.readlines(file).last(backfill)
  lines.each do |line|
    begin
      attack = parse_entry(JSON.parse(line), reader, lab_mode)
      next unless attack
      hub.record(attack, broadcast: false)
      seeded += 1
    rescue JSON::ParserError
      # skip partial/garbled line
    rescue => e
      puts "Backfill: #{e.message}"
    end
  end
end
puts "Backfill: seeded #{seeded} historical events."

# --- Live tailer thread ----------------------------------------------------
tailer = nil
current_date = nil

tail_thread = Thread.new do
  loop do
    date_str = Time.now.strftime(config["fileformat"])
    file = "#{config["logs"]}/#{date_str}.json"
    if tailer.nil? || current_date != date_str
      tailer&.close
      tailer = LogTailer.new(file)
      current_date = date_str
    end

    lines = tailer.check_for_new_lines
    if lines.empty?
      sleep 0.4
    else
      lines.each do |line|
        begin
          attack = parse_entry(JSON.parse(line), reader, lab_mode)
          hub.record(attack) if attack
        rescue JSON::ParserError
          # ignore
        rescue => e
          puts "Tail parse error: #{e.message}"
        end
      end
    end
  end
rescue => e
  puts "Tailer thread died: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
ensure
  tailer&.close
end
tail_thread.abort_on_exception = true

# --- Stats / heartbeat thread (also keeps SSE connections alive) -----------
stats_thread = Thread.new do
  loop do
    sleep stats_int
    begin
      hub.broadcast_stats
    rescue => e
      puts "Stats broadcast error: #{e.message}"
    end
  end
end
stats_thread.abort_on_exception = true

at_exit do
  tail_thread.exit
  stats_thread.exit
  tailer&.close
end

# --- HTTP routing ----------------------------------------------------------
SSE_HEADERS =
  "HTTP/1.1 200 OK\r\n" \
  "Content-Type: text/event-stream\r\n" \
  "Cache-Control: no-cache\r\n" \
  "Connection: keep-alive\r\n" \
  "X-Accel-Buffering: no\r\n" \
  "\r\n"

server.on(:request) do |id, socket, request|
  path = request[:path].to_s

  case
  when path == "/" || path.include?("index")
    socket.write(server.genReply(200, html, server.mimeFor(".html")))
    socket.close

  when path == "/world.json"
    socket.write(server.genReply(200, world_json, "application/json"))
    socket.close

  when path == "/api/recent"
    socket.write(server.genReply(200, hub.recent_payload.to_json, "application/json"))
    socket.close

  when path == "/api/stats"
    socket.write(server.genReply(200, hub.stats_payload.to_json, "application/json"))
    socket.close

  when path == "/api/stream"
    # Server-Sent Events: keep the socket open and let the Hub fan out to it.
    socket.write(SSE_HEADERS)
    socket.write(": connected\n\n")
    socket.write("event: recent\ndata: #{hub.recent_payload.to_json}\n\n")
    hub.subscribe(socket)
    # Do NOT close — HoneySet's connection loop will detect disconnect and the
    # on(:close) handler unsubscribes us.

  else
    socket.write(server.genReply(404, %({"error":"not found"}), "application/json"))
    socket.close
  end
end

server.on(:close) do |id, socket, *_|
  hub.unsubscribe(socket) if hub.subscriber?(socket)
end

server.on(:error) do |id, socket, error|
  hub.unsubscribe(socket) if socket && hub.subscriber?(socket)
  msg = error.respond_to?(:message) ? error.message : error.to_s
  puts "Server error (id #{id}): #{msg}"
end

puts "Attack map live on http://#{config["server"]["host"]}:#{config["server"]["port"]}"
puts "  lab mode: #{lab_mode} | ring: #{ring_size} | origin: #{origin[:label]}"
server.attach
