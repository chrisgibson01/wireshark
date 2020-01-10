bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

bsv_protocol.fields = {}

function bsv_protocol.dissector(buffer, pinfo, tree)
    assert(false)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = bsv_protocol.name

  local subtree = tree:add(bsv_protocol, buffer(), "Bitcoin SV Protocol Data")
end

--local tx_out_script_dissector = DissectorTable.get("bitcoin.tx.out.script")
--tx_out_script_dissector:add(8333, bsv_protocol)

local bitcoin_dissector = Dissector.get("bitcoin")
assert(bitcoin_dissector)

local bitcoin_dissector_table = DissectorTable.get("bitcoin.tx")
assert(bitcoin_dissector_table)
bitcoin_dissector_table:remove("bitcoin.tx.out.script")
bitcoin_dissector_table:add("bitcoin.tx.out.script", bsv_protocol)
