--dbg = require('debug')

bsv_protocol = Proto("BSV",  "Bitcoin SV Protocol")

local opcode = 
{
    -- push value,
    [0x0] = 'OP_0',
    [0x0] = 'OP_FALSE',

    [0x4c] = 'OP_PUSHDATA1',
    [0x4d] = 'OP_PUSHDATA2',
    [0x4e] = 'OP_PUSHDATA4',
    [0x4f] = 'OP_1NEGATE',
    [0x50] = 'OP_RESERVED',

    [0x51] = 'OP_1',
    --[0x51] = 'OP_TRUE',
    [0x52] = 'OP_2',
    [0x53] = 'OP_3',
    [0x54] = 'OP_4',
    [0x55] = 'OP_5',
    [0x56] = 'OP_6',
    [0x57] = 'OP_7',
    [0x58] = 'OP_8',
    [0x59] = 'OP_9',
    [0x5a] = 'OP_10',
    [0x5b] = 'OP_11',
    [0x5c] = 'OP_12',
    [0x5d] = 'OP_13',
    [0x5e] = 'OP_14',
    [0x5f] = 'OP_15',
    [0x60] = 'OP_16',

    -- control,
    [0x61] = 'OP_NOP',
    [0x62] = 'OP_VER',
    [0x63] = 'OP_IF',
    [0x64] = 'OP_NOTIF',
    [0x65] = 'OP_VERIF',
    [0x66] = 'OP_VERNOTIF',
    [0x67] = 'OP_ELSE',
    [0x68] = 'OP_ENDIF',
    [0x69] = 'OP_VERIFY',
    [0x6a] = 'OP_RETURN',

    -- stack ops',
    [0x6b] = 'OP_TOALTSTACK',
    [0x6c] = 'OP_FROMALTSTACK',
    [0x6d] = 'OP_2DROP',
    [0x6e] = 'OP_2DUP',
    [0x6f] = 'OP_3DUP',
    [0x70] = 'OP_2OVER',
    [0x71] = 'OP_2ROT',
    [0x72] = 'OP_2SWAP',
    [0x73] = 'OP_IFDUP',
    [0x74] = 'OP_DEPTH',
    [0x75] = 'OP_DROP',
    [0x76] = 'OP_DUP',
    [0x77] = 'OP_NIP',
    [0x78] = 'OP_OVER',
    [0x79] = 'OP_PICK',
    [0x7a] = 'OP_ROLL',
    [0x7b] = 'OP_ROT',
    [0x7c] = 'OP_SWAP',
    [0x7d] = 'OP_TUCK',

    -- splice ops,
    [0x7e] = 'OP_CAT',
    [0x7f] = '   -- after monolith upgrade (May 2018)OP_SPLIT',
    [0x80] = ' -- after monolith upgrade (May 2018)OP_NUM2BIN',
    [0x81] = ' -- after monolith upgrade (May 2018)OP_BIN2NUM',
    [0x82] = 'OP_SIZE',

    -- bit logic,
    [0x83] = 'OP_INVERT',
    [0x84] = 'OP_AND',
    [0x85] = 'OP_OR',
    [0x86] = 'OP_XOR',
    [0x87] = 'OP_EQUAL',
    [0x88] = 'OP_EQUALVERIFY',
    [0x89] = 'OP_RESERVED1',
    [0x8a] = 'OP_RESERVED2',

    -- numeric',
    [0x8b] = 'OP_1ADD',
    [0x8c] = 'OP_1SUB',
    [0x8d] = 'OP_2MUL',
    [0x8e] = 'OP_2DIV',
    [0x8f] = 'OP_NEGATE',
    [0x90] = 'OP_ABS',
    [0x91] = 'OP_NOT',
    [0x92] = 'OP_0NOTEQUAL',

    [0x93] = 'OP_ADD',
    [0x94] = 'OP_SUB',
    [0x95] = 'OP_MUL',
    [0x96] = 'OP_DIV',
    [0x97] = 'OP_MOD',
    [0x98] = 'OP_LSHIFT',
    [0x99] = 'OP_RSHIFT',

    [0x9a] = 'OP_BOOLAND',
    [0x9b] = 'OP_BOOLOR',
    [0x9c] = 'OP_NUMEQUAL',
    [0x9d] = 'OP_NUMEQUALVERIFY',
    [0x9e] = 'OP_NUMNOTEQUAL',
    [0x9f] = 'OP_LESSTHAN',
    [0xa0] = 'OP_GREATERTHAN',
    [0xa1] = 'OP_LESSTHANOREQUAL',
    [0xa2] = 'OP_GREATERTHANOREQUAL',
    [0xa3] = 'OP_MIN',
    [0xa4] = 'OP_MAX',

    [0xa5] = 'OP_WITHIN',

    -- crypto',
    [0xa6] = 'OP_RIPEMD160',
    [0xa7] = 'OP_SHA1',
    [0xa8] = 'OP_SHA256',
    [0xa9] = 'OP_HASH160',
    [0xaa] = 'OP_HASH256',
    [0xab] = 'OP_CODESEPARATOR',
    [0xac] = 'OP_CHECKSIG',
    [0xad] = 'OP_CHECKSIGVERIFY',
    [0xae] = 'OP_CHECKMULTISIG',
    [0xaf] = 'OP_CHECKMULTISIGVERIFY',

    -- expansion',
    [0xb0] = 'OP_NOP1',
    [0xb1] = 'OP_CHECKLOCKTIMEVERIFY',
    --[OP_CHECKLOCKTIMEVERIFY] = 'OP_NOP2',
    [0xb2] = 'OP_CHECKSEQUENCEVERIFY',
    --[OP_CHECKSEQUENCEVERIFY] = 'OP_NOP3',
    [0xb3] = 'OP_NOP4',
    [0xb4] = 'OP_NOP5',
    [0xb5] = 'OP_NOP6',
    [0xb6] = 'OP_NOP7',
    [0xb7] = 'OP_NOP8',
    [0xb8] = 'OP_NOP9',
    [0xb9] = 'OP_NOP10',

    -- The first op_code value after all defined opcodes',
    --[FIRST_UNDEFINED_]OP_VALUE',

    -- template matching params',
    [0xfa] = 'OP_SMALLINTEGER',
    [0xfb] = 'OP_PUBKEYS',
    [0xfd] = 'OP_PUBKEYHASH',
    [0xfe] = 'OP_PUBKEY',

    [0xff] = 'OP_INVALIDOPCODE',
}

local fields = {}

fields.ping_nonce = ProtoField.uint64("bsv.ping.nonce", "Random Nonce")
fields.pong_nonce = ProtoField.uint64("bsv.pong.nonce", "Reply Nonce")

fields.magic = ProtoField.uint32("bsv.header.magic", "Magic", base.HEX)
fields.cmd = ProtoField.string("bsv.header.cmd", "Command")
fields.length = ProtoField.uint32("bsv.header.length", "Length")
fields.checksum = ProtoField.bytes("bsv.header.checksum", "Checksum")
fields.inv_type = ProtoField.uint32("bsv.inv.type", "Type")
fields.hash = ProtoField.bytes("bsv.hash", "Hash")

fields.getheaders_version = ProtoField.uint32("bsv.getheaders.version", "Version")

fields.var_int1 = ProtoField.uint8("bsv.var_int_1", "var_int")
fields.var_int2 = ProtoField.uint16("bsv.var_int_2", "var_int")
fields.var_int4 = ProtoField.uint32("bsv.var_int_4", "var_int")
fields.var_int8 = ProtoField.uint64("bsv.var_int_8", "var_int")

fields.out_point_index = ProtoField.uint32("bsv.out_point.index", "Index", base.HEX)

fields.tx_in_signature_script = ProtoField.string("bsv.tx_in_signature_script", "Signature Script")
fields.tx_in_block_height = ProtoField.uint32("bsv.tx_in_block_height", "Block Height")
fields.tx_in_extra_nonce = ProtoField.bytes("bsv.tx_in_extra_nonce", "Extra Nonce")
fields.tx_in_miner_data = ProtoField.string("bsv.tx_in_miner_data", "Miner Data")

fields.tx_in_sequence = ProtoField.uint32("bsv.tx_in_sequence", "Sequence", base.HEX)

fields.tx_out_value = ProtoField.int64("bsv.tx_out.value", "Value")
fields.tx_out_script = ProtoField.uint8("bsv.tx_out.script", " ", base.HEX, opcode)
fields.tx_out_data = ProtoField.bytes("bsv.tx_out.data", "Data")
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

function dissect_var_int(tvb, tree) -- cjg rename this adds a var_int to a tree
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
    
    local len, n = dissect_var_int(tvb, subtree)
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

function dissect_script(tvb, tree)
    local len, n = dissect_var_int(tvb, tree)
    local offset = len
    while offset < len + n do 

        local opcode = tvb(offset, 1):uint()
        if opcode <= 75 and opcode >= 1 then
            tree:add(fields.tx_out_data, tvb(offset+1, opcode)) 
            offset = offset + 1 + opcode
        else
            tree:add(fields.tx_out_script, tvb(offset, 1)) 
            offset = offset + 1
        end
    end
    return len + n
end

function dissect_coinbase_data(tvb, pinfo, tree)
    local cbtree = tree:add('Coinbase Data')
    
    local len, n = dissect_var_int(tvb(offset), cbtree)
    local opcode = tvb(len, 1):uint()
    assert(opcode <=75)
    assert(opcode >=1)
    local offset = len + 1

    -- BIP-34 specifies block height in > version 2
    local block_height = tvb(offset, opcode):le_int()
    pinfo.cols.info:append(' ' .. tostring(block_height))
    cbtree:add_le(fields.tx_in_block_height, tvb(offset, opcode)) 
    offset = offset + opcode

    while offset < n do
        local extra_nonce_len = tvb(offset, 1):uint()
        offset = offset + 1
        cbtree:add(fields.tx_in_extra_nonce, tvb(offset,  extra_nonce_len))
        offset = offset + extra_nonce_len
    end
    
    return len + n
end

function tofan(tvb, pinfo, tree)
    local subtree = tree:add('Signature Script')
    local tmp =  dissect_script(tvb, subtree)
    return tmp
end

function dissect_tx_in(tvb, pinfo, tree, index) 
    local subtree = tree:add('TxIn ' .. index)
    local offset = dissect_out_point(tvb(0, 36), subtree)
    
    if index == 0 then
        offset = offset + dissect_coinbase_data(tvb(offset), pinfo, subtree) 
    else
        offset = offset + tofan(tvb(offset), pinfo, subtree)
    end

    subtree:add(fields.tx_in_sequence, tvb(offset, 4))
    return offset + 4 
end
    
function dissect_tx_out(tvb, tree, index) 
    local subtree = tree:add('TxOut ' .. index)

    subtree:add_le(fields.tx_out_value, tvb(0, 8))

    local pub_key_tree = subtree:add('Script Pub Key')

    local n = dissect_script(tvb(8), pub_key_tree)
    return 8 + n
end

function dissect_tx(tvb, pinfo, tree, index)
    local subtree = tree:add('Tx ' .. index)
    subtree:add_le(fields.tx_version, tvb(0, 4))
    local offset = 4
    local len, n = dissect_var_int(tvb(4), subtree)
    offset = offset + len

    for i=0, n-1 do 
        offset = offset + dissect_tx_in(tvb(offset), pinfo, subtree, index) 
    end

    len, n = dissect_var_int(tvb(offset), subtree)
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
    
    local len, count = dissect_var_int(tvb(80), subtree) 
    local tx_start = 80 + len 
    for i = 0, count-1 do
        tx_start = tx_start + dissect_tx(tvb(tx_start), pinfo, subtree, i) 
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
    
    local subtree = tree:add("Inventory Vectors")

    local len, n = dissect_var_int(tvb, subtree) 

    local offset = len
    for i=0, n-1 do 
        subtree:add_le(fields.inv_type, tvb(offset, 4))
        offset = offset + 4
        subtree:add(fields.hash, tvb(offset, 32))
        offset = offset + 32
    end
end

msg_dissectors.getdata = function (tvb, pinfo, tree)
    pinfo.cols.info = 'getdata'
    
    local len, n = dissect_var_int(tvb, tree)
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
    local len, n  = dissect_var_int(tvb(4), subtree)
    local offset = 4 + len
    for i=0, n-1 do
        subtree:add(fields.hash, tvb(offset, 32))
        offset = offset + 32
    end
    
    -- hash stop 
    subtree:add(fields.hash, tvb(offset, 32))
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

