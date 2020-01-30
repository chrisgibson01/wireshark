--dbg = require('debug')

bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

local fields = {}
fields.magic = ProtoField.uint32("bsv.header.magic", "Magic", base.HEX)
fields.cmd = ProtoField.string("bsv.header.cmd", "Command")
fields.length = ProtoField.uint32("bsv.header.length", "Length")
fields.checksum = ProtoField.bytes("bsv.header.checksum", "Checksum")
fields.inv_count = ProtoField.uint8("bsv.inv.count", "Count")
fields.inv_type = ProtoField.uint32("bsv.inv.type", "Type")
fields.inv_hash = ProtoField.bytes("bsv.inv.hash", "Hash")

bsv_protocol.fields = fields 

function get_msg_length(tvb)
    local len = tvb:le_uint()
    debug('length ' .. len)
    return len 
end

msg_dissectors = {}

function dissect_header(tvb, pinfo, tree)
    local length = tvb:len()
    assert(length >= 24)
    
    local subtree = tree:add("Header")
    subtree:add(fields.magic, tvb(0, 4))
    subtree:add(fields.cmd, tvb(4, 12))
    subtree:add_le(fields.length, tvb(16, 4))
    subtree:add(fields.checksum, tvb(20, 4))

    local cmd = tvb:range(4, 12):stringz() 
    print(cmd)
    if cmd ~= nil then
        msg_dissectors[cmd](tvb(24), pinfo, tree)
    else
       -- print(cmd .. ' dissector missing')
       -- msg_dissectors.default(cmd)
    end
end

msg_dissectors.inv = function (tvb, pinfo, tree)

    local count = tvb(0, 1):uint()
    tree:add(fields.inv_count, tvb(0, 1))

    local subtree = tree:add("Inventory Vectors")
    print(count)
    for i=1, 1, 12 do 
        subtree:add_le(fields.inv_type, tvb(i, 4))
        subtree:add(fields.inv_hash, tvb(i+4, 8))
    end

end

msg_dissectors.ping = function(tvb, pinfo, tree) end
msg_dissectors.pong = function(tvb, pinfo, tree) end
msg_dissectors.getheaders = function(tvb, pinfo, tree) end
msg_dissectors.headers = function(tvb, pinfo, tree) end

msg_dissectors.block = function (tvb, pinfo, tree)
    print('*** block dissector ****')
end

msg_dissectors.version = function(tvb, pinfo, tree)
    print('*** version dissector ***')
end

msg_dissectors.default = function(cmd)
    print('*** unknown dissector ' .. cmd .. ' ***')
end


function dissect_inventory_vector(tvb, pinfo, tree)
    
end

function bsv_protocol.dissector(tvb, pinfo, tree)
    seg_len = tvb:len()
    if seg_len < 24 then 
        return 
    end

    print('\n**** dissecting ****')
    
    local msg_len = get_msg_length(tvb(16, 4)) 
    print('msg_len: ' .. msg_len)
    print('seg_len: ' .. seg_len)
    if(msg_len > seg_len) then
        pinfo.desegment_len = msg_len - seg_len;
        print('pinfo.desegment_len: ' .. pinfo.desegment_len)
        pinfo.desegment_offset = 0 
        return
    end

    pinfo.cols.protocol = bsv_protocol.name

    local subtree = tree:add(bsv_protocol, tvb(), "Bitcoin SV")
    dissect_header(tvb, pinfo, subtree)

end

local tcp_port_dissector = DissectorTable.get("tcp.port")

tcp_port_dissector:add(8333, bsv_protocol)

