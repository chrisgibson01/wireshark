bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

bsv_protocol.fields = {}

function bsv_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = bsv_protocol.name

  local subtree = tree:add(bsv_protocol, buffer(), "Bitcoin SV Protocol Data")
end

local bitcoin_port = DissectorTable.get("tcp.port")
bitcoin_port:add(8333, bsv_protocol)
