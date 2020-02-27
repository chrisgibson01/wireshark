--dbg = require('debug')

bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

local fields = {}

fields.ping_nonce = ProtoField.uint64("bsv.ping.nonce", "Random Nonce")
fields.pong_nonce = ProtoField.uint64("bsv.pong.nonce", "Reply Nonce")

fields.magic = ProtoField.uint32("bsv.header.magic", "Magic", base.HEX)
fields.cmd = ProtoField.string("bsv.header.cmd", "Command")
fields.length = ProtoField.uint32("bsv.header.length", "Length")
fields.checksum = ProtoField.bytes("bsv.header.checksum", "Checksum")
fields.inv_count = ProtoField.uint8("bsv.inv.count", "Count")
fields.inv_type = ProtoField.uint32("bsv.inv.type", "Type")
fields.hash = ProtoField.bytes("bsv.hash", "Hash")

fields.getheaders_version = ProtoField.uint32("bsv.getheaders.version", "Version")

fields.var_int1 = ProtoField.uint8("bsv.var_int_1", "var_int")
fields.var_int2 = ProtoField.uint16("bsv.var_int_2", "var_int")
fields.var_int4 = ProtoField.uint32("bsv.var_int_4", "var_int")
fields.var_int8 = ProtoField.uint64("bsv.var_int_8", "var_int")

fields.out_point_index = ProtoField.uint32("bsv.out_point.index", "Index")

fields.tx_in_signature_script = ProtoField.string("bsv.tx_in_signature_script", "Signature Script")
fields.tx_in_sequence = ProtoField.uint32("bsv.tx_in_sequence", "Sequence")

fields.tx_out_value = ProtoField.int64("bsv.tx_out.value", "Value")
fields.tx_out_script = ProtoField.string("bsv.tx_out.script", "Public Key Script")
fields.tx_lock_time = ProtoField.absolute_time("bsv.tx_out.lock_time", "Lock Time")
fields.tx_lock_block = ProtoField.uint32("bsv.tx_out.lock_block", "Lock Time Block")

fields.block_version = ProtoField.uint32("bsv.block.version", "Version")
fields.block_prev_block = ProtoField.bytes("bsv.block.pre_block", "Prev Block")
fields.block_merkle_root = ProtoField.bytes("bsv.block.merkle_root", "Merkle Root")
fields.block_timestamp = ProtoField.absolute_time("bsv.block.timestamp", "Timestamp", base.UTC)
fields.block_difficulty = ProtoField.uint32("bsv.block.difficulty", "Difficulty")  -- cjg bits
fields.block_nonce = ProtoField.uint32("bsv.block.nonce", "Nonce")

fields.addr_timestamp = ProtoField.absolute_time("bsv.addr.timestamp", "Timestamp")

fields.tx_version = ProtoField.int32("bsv.tx_version", "Version")

fields.version_version = ProtoField.int32("bsv.version.version", "Version")
fields.version_services = ProtoField.bytes("bsv.version.services", "Services")
fields.version_timestamp = ProtoField.absolute_time("bsv.version.timestamp", "Timestamp", base.UTC)
fields.version_nonce = ProtoField.uint64("bsv.version.nonce", "Nonce")
fields.version_user_agent = ProtoField.string("bsv.version.user_agent", "User Agent")
fields.version_block_height = ProtoField.uint32("bsv.version.block_height", "Block Height")
fields.version_relay = ProtoField.bool("bsv.version.relay", "Relay")

fields.network_address_version = ProtoField.uint32("bsv.network_addr.version", "Version")
fields.network_address_port = ProtoField.uint16("bsv.network_addr.port", "Port")
fields.network_address_services = ProtoField.bytes("bsv.network_addr.services", "Services")
fields.network_address_ip = ProtoField.ipv6("bsv.network_addr.ip", "IP Address")

msg_dissectors = {}

bsv_protocol.fields = fields

local header_len = 24

function var_int(tvb)
    local n = tvb(0, 1):uint()
    if n < 0xfd then
        return 1, n
    elseif n == 0xfd then 
        return 3, tvb(1, 2):le_uint()
    elseif n == 0xfe then 
        return 5, tvb(1, 4):le_uint()
    elseif n == 0xff then 
        return 9, tvb(1, 8):le_uint64()
    else
        assert(false)
    end
end

function tofan(tvb, tree)
    local len, n = var_int(tvb)
    if len == 1 then
        tree:add(fields.var_int1, tvb(0, len))
    elseif len == 3 then
        tree:add_le(fields.var_int2, tvb(1, len-1))
    elseif len == 5 then
        tree:add_le(fields.var_int4, tvb(1, len-1))
    elseif len == 9 then
        tree:add_le(fields.var_int8, tvb(1, len-1))
    else
        assert(false)
    end    
    return len, n 
end

function dissect_network_addr(tvb, pinfo, tree)
    local subtree = tree:add('Network Address')
    subtree:add(fields.network_address_services, tvb(0, 8))
    subtree:add(fields.network_address_ip, tvb(8, 16))
    subtree:add(fields.network_address_port, tvb(24, 2)) 
end

msg_dissectors.version = function(tvb, pinfo, tree)
    pinfo.cols.info = 'version'
    local subtree = tree:add('Version')
    subtree:add_le(fields.version_version, tvb(0, 4))
    subtree:add(fields.version_services, tvb(4, 8))
    subtree:add_le(fields.version_timestamp, tvb(12, 8))
    
    dissect_network_addr(tvb(20), pinfo, subtree)
    dissect_network_addr(tvb(46), pinfo, subtree)
    
    subtree:add(fields.version_nonce, tvb(72, 8))
    
    local len, n  = var_int(tvb(80))
    local user_agent_start = 80+len
    subtree:add(fields.version_user_agent, tvb(user_agent_start, n))
    subtree:add_le(fields.version_block_height, tvb(user_agent_start+n, 4))
    subtree:add(fields.version_relay, tvb(user_agent_start+n+4, 1))
end
    
msg_dissectors.addr = function(tvb, pinfo, tree)
    
    pinfo.cols.info = 'addr'

    local subtree = tree:add('addr')
    
    local len, n = tofan(tvb, subtree)
    local start = len 
    for i=0, n-1 do 
        subtree:add_le(fields.addr_timestamp, tvb(start, 4))
        dissect_network_addr(tvb(start + 4, 26), pinfo, subtree) 
        start = start + 30
    end
end

function dissect_out_point(tvb, tree) 
    local subtree = tree:add('OutPoint')
    subtree:add(fields.hash, tvb(0, 32))
    subtree:add_le(fields.out_point_index, tvb(32, 4))
    return 36
end

function dissect_tx_in(tvb, tree, index) 
    local subtree = tree:add('TxIn ' .. index)
    local offset = dissect_out_point(tvb(0, 36), subtree)
    
    local len, n = tofan(tvb(offset), subtree)
    offset = offset + len 
    subtree:add(fields.tx_in_signature_script, tvb(offset, n)) 
    subtree:add(fields.tx_in_sequence, tvb(offset + n, 4))
    return offset + n + 4 
end

local opcodes = {
    [0x76] = 'OP_DUP',
    [0xac] = 'OP_CHECKSIG',
    [0xb0] = 'OP_NOP1',
    }

function dissect_tx_out(tvb, tree, index) 
    local subtree = tree:add('TxOut ' .. index)

    subtree:add_le(fields.tx_out_value, tvb(0, 8))

    local len, n = tofan(tvb(8), subtree)
    subtree:add(fields.tx_out_script, tvb(8 + len, n)) 

    local bytes = tvb(8+len, n):bytes()
    for i=0, n-1 do 
        print(opcodes[bytes:get_index(i)])
        print(bytes:get_index(i))
        print('\n')
    end


    return 8 + len + n
end

function dissect_tx(tvb, tree, index)
    local subtree = tree:add('Tx ' .. index)
    subtree:add_le(fields.tx_version, tvb(0, 4))
    local offset = 4
    local len, n = tofan(tvb(4), subtree)
    offset = offset + len
    for i=0, n-1 do 
        offset = offset + dissect_tx_in(tvb(offset), subtree, i) 
    end

    len, n = tofan(tvb(offset), subtree)
    offset = offset + len
    for i = 0, n-1 do
        offset = offset + dissect_tx_out(tvb(offset), subtree, i)
    end

    if tvb(offset, 4):le_uint() < 500000000 then
        subtree:add_le(fields.tx_lock_block, tvb(offset, 4))
    else
        subtree:add_le(fields.tx_lock_time, tvb(offset, 4))
    end

    return offset + 4
end

msg_dissectors.block = function (tvb, pinfo, tree)
    pinfo.cols.info = 'block'

    local subtree = tree:add("block")
    subtree:add_le(fields.block_version, tvb(0, 4))
    subtree:add(fields.block_prev_block, tvb(4, 32))
    subtree:add(fields.block_merkle_root, tvb(36, 32))
    subtree:add_le(fields.block_timestamp, tvb(68, 4))
    subtree:add_le(fields.block_difficulty, tvb(72, 4))
    subtree:add_le(fields.block_nonce, tvb(76, 4))
    
    local len, count = tofan(tvb(80), subtree) 
    local tx_start = 80 + len 
    for i = 0, count-1 do
        tx_start = tx_start + dissect_tx(tvb(tx_start), subtree, i) 
    end
end

function dissect_header(tvb, pinfo, tree)
    local length = tvb:len()
    assert(length >= header_len)
    
    local subtree = tree:add("Header")
    subtree:add(fields.magic, tvb(0, 4))
    subtree:add(fields.cmd, tvb(4, 12))
    subtree:add_le(fields.length, tvb(16, 4))
    subtree:add(fields.checksum, tvb(20, 4))

    cmd = tvb:range(4, 12):stringz() 
    return cmd
end

msg_dissectors.inv = function (tvb, pinfo, tree)
    pinfo.cols.info = 'inv'

    local count = var_int(tvb) 
    tree:add(fields.inv_count, tvb(0, 1))

    local subtree = tree:add("Inventory Vectors")
    for i=1, count*36, 36 do 
        subtree:add_le(fields.inv_type, tvb(i, 4))
        subtree:add(fields.hash, tvb(i+4, 32))
    end
end

msg_dissectors.getdata = function (tvb, pinfo, tree)
    pinfo.cols.info = 'getdata'
    
    local len, n = tofan(tvb, tree)
    local offset = len 
    local subtree = tree:add("Inventory Vectors")
    for i=0, n-1 do 
        subtree:add_le(fields.inv_type, tvb(offset, 4))
        subtree:add(fields.hash, tvb(offset+4, 32))
        offset = offset + 36
    end
end

msg_dissectors.getheaders = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'getheaders'

    local subtree = tree:add("getheaders")
    subtree:add_le(fields.getheaders_version, tvb(0, 4)) 
    local len, n  = var_int(tvb(4))
    subtree:add(fields.var_int1, tvb(4, len))

    local count = tvb(4, len):uint()
    for i=1, count*32, 32 do
        subtree:add(fields.hash, tvb(4 + i, 32))
    end
    
    -- hash stop cjg
    subtree:add(fields.hash, tvb(5 + (count*32), 32))
end

msg_dissectors.headers = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'headers'

    local subtree = tree:add("headers")
    local len, n = var_int(tvb)
    subtree:add_le(fields.var_int2, tvb(1, len))
    
end

msg_dissectors.ping = function(tvb, pinfo, tree) 
    pinfo.cols.info = 'ping'
    tree:add(fields.ping_nonce, tvb(0, 8))
end
msg_dissectors.pong = function(tvb, pinfo, tree) 
    tree:add(fields.pong_nonce, tvb(0, 8))
    pinfo.cols.info = 'pong'
end

msg_dissectors.protoconf = function (tvb, pinfo, tree)
    pinfo.cols.info = 'protoconf'
end

msg_dissectors.sendcmpct = function (tvb, pinfo, tree)
    pinfo.cols.info = 'sendcmpct'
end

msg_dissectors.feefilter = function (tvb, pinfo, tree)
    pinfo.cols.info = 'feefilter'
end

msg_dissectors.default = function(cmd, pinfo)
    pinfo.cols.info = cmd
end

msg_dissectors.unknown = function(cmd)
    print('*** unknown dissector ' .. cmd .. ' ***')
end

function dissect_inventory_vector(tvb, pinfo, tree)
    
end

function get_payload_length(tvb)
    return tvb:le_uint()
end

function bsv_protocol.dissector(tvb, pinfo, tree)
    seg_len = tvb:len()
    if seg_len < header_len then 
        return 
    end

    local payload_len = get_payload_length(tvb(16, 4)) 
    local msg_len = header_len + payload_len
    if(msg_len > seg_len) then
        pinfo.desegment_len = msg_len - seg_len;
        pinfo.desegment_offset = 0 
        return
    end

    pinfo.cols.protocol = bsv_protocol.name

    local subtree = tree:add(bsv_protocol, tvb(), "Bitcoin SV")
    cmd = dissect_header(tvb, pinfo, subtree)

    if payload_len > 0 then
        local cmd_dissector = msg_dissectors[cmd]
        if cmd_dissector ~= nil then
            cmd_dissector(tvb(header_len), pinfo, subtree)
        else
            msg_dissectors.unknown(cmd)
        end
    else
        msg_dissectors.default(cmd, pinfo)
    end
end

local tcp_port_dissector = DissectorTable.get("tcp.port")

tcp_port_dissector:add(8333, bsv_protocol)

