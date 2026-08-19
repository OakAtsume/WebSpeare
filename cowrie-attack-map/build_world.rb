# build_world.rb — one-shot build step.
# Turns a full Natural Earth 110m countries GeoJSON into a tiny, geometry-only
# polygon list that the attack-map canvas renderer can draw directly.
#
# Output (web/world.json) is a flat array of rings:
#   [ [[lng,lat],[lng,lat],...], [...], ... ]
# Coordinates are rounded to 2 decimals (~1km at the equator) which is plenty
# for a world-scale map and keeps the file small enough to ship locally.
#
# Usage:  ruby build_world.rb path/to/source.geojson
require "json"

src = ARGV[0] || "world.geojson"
abort("source not found: #{src}") unless File.exist?(src)

data = JSON.parse(File.read(src))
rings = []

round = ->(coord) { [coord[0].round(2), coord[1].round(2)] }

# Drop consecutive duplicate points created by rounding.
dedup = lambda do |ring|
  out = []
  ring.each do |pt|
    out << pt unless out.last == pt
  end
  out
end

emit_polygon = lambda do |polygon|
  # polygon = array of rings (first = outer, rest = holes). We only draw outlines,
  # so every ring is treated the same — holes still read fine as thin outlines.
  polygon.each do |ring|
    simplified = dedup.call(ring.map { |c| round.call(c) })
    rings << simplified if simplified.length >= 3
  end
end

data["features"].each do |feature|
  geom = feature["geometry"]
  next unless geom
  case geom["type"]
  when "Polygon"
    emit_polygon.call(geom["coordinates"])
  when "MultiPolygon"
    geom["coordinates"].each { |poly| emit_polygon.call(poly) }
  end
end

out = "web/world.json"
File.write(out, JSON.generate(rings))
puts "Wrote #{out}: #{rings.length} rings, #{File.size(out)} bytes"
