--dbg = require('debug')

bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

local fields = {}
fields.magic = ProtoField.uint32("bsv.header.magic", "Magic", base.HEX)
fields.cmd = ProtoField.string("bsv.header.cmd", "Command")
fields.length = ProtoField.uint32("bsv.header.length", "Length")
fields.checksum = ProtoField.bytes("bsv.header.checksum", "Checksum")
fields.inv_count = ProtoField.uint8("bsv.inv.count", "Count")
fields.inv_type = ProtoField.uint32("bsv.inv.type", "Type")
fields.hash = ProtoField.bytes("bsv.hash", "Hash")
fields.getheaders_version = ProtoField.uint32("bsv.getheaders.version", "Version")
fields.var_int1 = ProtoField.uint8("bsv.var_int", "var_int")

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

    cmd = tvb:range(4, 12):stringz() 
    local cmd_dissector = msg_dissectors[cmd]
    if cmd_dissector ~= nil then
        cmd_dissector(tvb(24), pinfo, tree)
    else
       msg_dissectors.default(cmd)
    end
end

msg_dissectors.inv = function (tvb, pinfo, tree)
    pinfo.cols.info = 'inv'

    local count = tvb(0, 1):uint()
    tree:add(fields.inv_count, tvb(0, 1))

    local subtree = tree:add("Inventory Vectors")
    print(count)
    for i=1, 1, 12 do 
        subtree:add_le(fields.inv_type, tvb(i, 4))
        subtree:add(fields.hash, tvb(i+4, 8))
    end

end

function var_int(tvb)
    return 1
--  cjg
--    local n = tvb(0, 1):int()
--    if n < 0xfd then
--        return 1
----    elseif n <= 0xfe then 
----        return tvb(0, 3)
--    else
--        assert(false)
--        return 3
end

msg_dissectors.getheaders = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'getheaders'

    local subtree = tree:add("getheaders")
    subtree:add_le(fields.getheaders_version, tvb(0, 4)) 
    local len = var_int(tvb(4, 9))
    print(len)
    subtree:add(fields.var_int1, tvb(4, len))

    local count = tvb(4, len):uint()
    for i=1, count*32, 32 do
        subtree:add(fields.hash, tvb(4 + i, 32))
    end
end

msg_dissectors.ping = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'ping'
end
msg_dissectors.pong = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'pong'
end
msg_dissectors.headers = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'headers'
end

msg_dissectors.block = function (tvb, pinfo, tree)
    pinfo.cols.info = 'block'
    print('*** block dissector ****')
end

msg_dissectors.version = function(tvb, pinfo, tree)
    pinfo.cols.info = 'version'
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

