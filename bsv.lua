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

for i = 0x1, 0x4b do
    opcode[i] = 'Data Length'
end

local inv_type =
{
    [0] = 'error',
    [1] = 'tx',
    [2] = 'block',
    [3] = 'filtered block',
    [4] = 'cmpct block'
}

local fields = {}

fields.block_tx_request_block_hash = ProtoField.bytes("bsv.block_tx_request", "Block Tx Request")
fields.block_txs_block_hash = ProtoField.bytes("bsv.block_txs", "Block Txs")

fields.var_int1 = ProtoField.uint8("bsv.var_int_1", "var_int")
fields.var_int2 = ProtoField.uint16("bsv.var_int_2", "var_int")
fields.var_int4 = ProtoField.uint32("bsv.var_int_4", "var_int")
fields.var_int8 = ProtoField.uint64("bsv.var_int_8", "var_int")

fields.ping_nonce = ProtoField.uint64("bsv.ping.nonce", "Random Nonce")
fields.pong_nonce = ProtoField.uint64("bsv.pong.nonce", "Reply Nonce")

local magic =
{
    [0xe3e1f3e8] = 'mainnet',
    [0xdab5bffa] = 'regtest',
    [0xf4e5f3f4] = 'testnet',
    [0xfbcec4f9] = 'stn'
}

fields.magic = ProtoField.uint32("bsv.header.magic", "Magic", base.HEX, magic)
fields.cmd = ProtoField.string("bsv.header.cmd", "Command")
fields.length = ProtoField.uint32("bsv.header.length", "Length")
fields.checksum = ProtoField.bytes("bsv.header.checksum", "Checksum")
fields.ext_cmd = ProtoField.string("bsv.header.ext_cmd", "Extended Command")
fields.ext_length = ProtoField.uint64("bsv.header.ext_length", "Extended Length")

fields.hash = ProtoField.bytes("bsv.hash", "Hash")

fields.inv_type = ProtoField.uint32("bsv.inv.type", "Type", base.HEX, inv_type)
fields.inv_hash = ProtoField.bytes("bsv.inv.hash", "Hash")

fields.getheaders_version = ProtoField.uint32("bsv.getheaders.version", "Version")

fields.out_point_index = ProtoField.uint32("bsv.out_point.index", "Index", base.HEX)

fields.txid = ProtoField.bytes("bsv.txid", "TxId")
fields.tx_in_block_height = ProtoField.uint32("bsv.tx_in_block_height", "Block Height")
fields.tx_in_extra_nonce = ProtoField.bytes("bsv.tx_in_extra_nonce", "Extra Nonce")
fields.tx_in_miner_data = ProtoField.string("bsv.tx_in_miner_data", "Miner Data")

fields.tx_in_sequence = ProtoField.uint32("bsv.tx_in_sequence", "Sequence", base.HEX)

fields.tx_out_value = ProtoField.int64("bsv.tx_out.value", "Value")
fields.tx_script_opcode = ProtoField.uint8("bsv.tx.script.opcode", "Opcode", base.HEX, opcode)
fields.tx_script_public_key = ProtoField.bytes("bsv.tx.script.public_key", "Data")
fields.tx_script_public_key_hash = ProtoField.bytes("bsv.tx.script.public_key_hash", "Data")
fields.tx_script_data = ProtoField.bytes("bsv.tx.script.data", "Data")
fields.tx_script_data_len = ProtoField.uint8("bsv.tx.script.data.len", "Length")
fields.tx_script_der_start = ProtoField.uint8("bsv.tx.script.der.start", "Start")
fields.tx_script_der_len = ProtoField.uint8("bsv.tx.script.der.len", "Length")
fields.tx_script_der_type = ProtoField.uint8("bsv.tx.script.der.type", "Type")
fields.tx_script_der_r = ProtoField.bytes("bsv.tx.script.der.r", "R")
fields.tx_script_der_s = ProtoField.bytes("bsv.tx.script.der.s", "S")

local sig_hash =
{
    [0x1] = 'ALL = (all inputs, all outputs)',
    [0x2] = 'NONE = (all inputs, no outputs)',
    [0x3] = 'SINGLE (all inputs, this output)',
    [0x41] = 'FORKID | ALL = (all inputs, all outputs)',
    [0x42] = 'FORKID | NONE = (all inputs, no outputs)',
    [0x43] = 'FORKID | SINGLE (all inputs, this output)',
    [0x81] = 'ANYONECANPAY | ALL (this input, all outputs)',
    [0x82] = 'ANYONECANPAY | NONE (this input, no outputs)',
    [0x83] = 'ANYONECANPAY | SINGLE (this input, this output)',
    [0xc1] = 'ANYONECANPAY | FORKID | ALL (this input, all outputs)',
    [0xc2] = 'ANYONECANPAY | FORKID | NONE (this input, no outputs)',
    [0xc3] = 'ANYONECANPAY | FORKID | SINGLE (this input, this output)',
}
fields.tx_script_sighash = ProtoField.uint8("bsv.tx.script.sighash", 
                                            "Signature Hash",
                                            base.HEX, 
                                            sig_hash)
fields.tx_lock_time = ProtoField.absolute_time("bsv.tx_out.lock_time", "Lock Time")
fields.tx_lock_block = ProtoField.uint32("bsv.tx_out.lock_block", "Lock Time Block")

fields.block_version = ProtoField.uint32("bsv.block.version", "Version", base.HEX)
fields.block_prev_block = ProtoField.bytes("bsv.block.pre_block", "Prev Block")
fields.block_merkle_root = ProtoField.bytes("bsv.block.merkle_root", "Merkle Root")
fields.block_timestamp = ProtoField.absolute_time("bsv.block.timestamp", "Timestamp", base.UTC)
fields.block_target_exponent = ProtoField.uint8("bsv.block.target.exponent", "Exponent", base.HEX)
fields.block_target_mantissa = ProtoField.uint24("bsv.block.target.mantissa", "Mantissa", base.HEX)
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

fields.sendcmpct_on = ProtoField.uint8("bsv.sendcmpct.on", "High Bandwidth Relaying")
fields.sendcmpct_version = ProtoField.uint64("bsv.sendcmpct.version", "Version")

fields.satoshis_per_kb = ProtoField.int64("bsv.feefilter", "Minimum Satoshis/kb")

fields.hasids_nonce = ProtoField.uint64("bsv.header_and_short_ids.nonce", "Nonce")

fields.dsdetected_version = ProtoField.uint16("bsv.dsdetected.version", "Version")
fields.dsdetected_mp_flags = ProtoField.uint8("bsv.dsdetected.merkle_proof.flags", "Flags")
fields.dsdetected_mp_tx = ProtoField.bytes("bsv.dsdetected.merkle_proof.tx", "Tx")
fields.dsdetected_mp_merkle_root = ProtoField.bytes("bsv.dsdetected.merkle_proof.merkle_root", "Merkle Root")
fields.dsdetected_mp_node_type = ProtoField.uint8("bsv.dsdetected.merkle_proof.node.type", "Type")
fields.dsdetected_mp_node_value = ProtoField.bytes("bsv.dsdetected.merkle_proof.node.value", "Value")
   
fields.merkle_proof_txid = ProtoField.bytes("bsv.mp.txid", "txid")
fields.merkle_proof_target = ProtoField.bytes("bsv.mp.target", "target")

fields.createstrm_assoc_id = ProtoField.bytes("bsv.createstrm.assoc_id", "Assoc. ID")
local stream_type =
{
    [0] = 'UNKNOWN',
    [1] = 'GENERAL',
    [2] = 'DATA1',
    [3] = 'DATA2',
    [4] = 'DATA3',
    [5] = 'DATA4'
}
fields.createstrm_stream_type = ProtoField.uint8("bsv.createstrm.assoc_id", "Assoc. stream type", base.HEX, stream_type)
fields.createstrm_stream_policy = ProtoField.string("bsv.createstrm.policy", "Assoc. stream policy")

fields.hdrsen_no_more_headers = ProtoField.bytes("bsv.hdrsen.no_more_headers", "no_more_headers")
fields.hdrsen_has_coinbase_data = ProtoField.bytes("bsv.hdrsen.has_coinbase_data", "has_coinbase_data")

msg_dissectors = {}

bsv_protocol.fields = fields

local min_header_len = 24

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

function dissect_var_int(tvb, tree) -- cjg rename, adds a var_int to a tree
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

function update_info_col(pinfo, msg)
    pinfo.cols.info:append(' ' .. msg)
end

function dissect_network_addr(tvb, pinfo, tree)
    local subtree = tree:add('Network Address')
    subtree:add(fields.network_address_services, tvb(0, 8))
    subtree:add(fields.network_address_ip, tvb(8, 16))
    subtree:add(fields.network_address_port, tvb(24, 2)) 
end

msg_dissectors.version = function(tvb, pinfo, tree)
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
    subtree:add(fields.txid, tvb(0, 32))
    subtree:add_le(fields.out_point_index, tvb(32, 4))
    return 36
end

-- see BIP_0062
function dissect_digital_signature(tvb, tree)
    local subtree = tree:add('Digital Signature')
    local der_tree = subtree:add('Distinguished Encoding Rules (DER)')
    local offset = 0
    der_tree:add(fields.tx_script_der_start, tvb(offset, 1))
    offset = offset + 1
    der_tree:add(fields.tx_script_der_len, tvb(offset, 1))
    offset = offset + 1
    der_tree:add(fields.tx_script_der_type, tvb(offset, 1))
    offset = offset + 1
    local len = tvb(offset, 1):uint()
    der_tree:add(fields.tx_script_der_len, tvb(offset, 1))
    offset = offset + 1
    der_tree:add(fields.tx_script_der_r, tvb(offset, len)) 
    offset = offset + len
    der_tree:add(fields.tx_script_der_type, tvb(offset, 1))
    offset = offset + 1
    len = tvb(offset, 1):uint()
    der_tree:add(fields.tx_script_der_len, tvb(offset, 1))
    offset = offset + 1
    der_tree:add(fields.tx_script_der_s, tvb(offset, len)) 
    offset = offset + len

    subtree:add(fields.tx_script_sighash, tvb(offset, 1)) 
end

function dissect_public_key(tvb, tree) 
    assert(tvb:len() == 0x21) 
    local subtree = tree:add('Public Key')
    subtree:add(fields.tx_script_public_key, tvb) 
end

function dissect_public_key_hash(tvb, tree)
    assert(tvb:len() == 0x14)
    local subtree = tree:add('Public Key Hash')
    subtree:add(fields.tx_script_public_key_hash, tvb) 
end

function dissect_data(tvb, tree)
    local len = tvb:len()
    local start = tvb(0, 1):uint()

    if len < 20 then
        tree:add(fields.tx_script_data, tvb) -- cjg
    elseif len == 20 then 
        dissect_public_key_hash(tvb, tree)
    elseif len == 33 then --cjg
        dissect_public_key(tvb, tree)
    elseif len <= 72 and start == 0x30 then -- assume digital signature see BIP_0062
        dissect_digital_signature(tvb, tree) 
    else
        tree:add(fields.tx_script_data, tvb) -- cjg public key hash
    end
end

function dissect_data2(tvb, tree)
    local len = tvb:len()
    tree:add(fields.tx_script_data, tvb)
end

function dissect_script(tvb, tree)
    local len, n = dissect_var_int(tvb, tree)
    local offset = len
    while offset < len + n do 

        local opcode = tvb(offset, 1):uint()
        if opcode <= 75 and opcode >= 1 then
            tree:add(fields.tx_script_opcode, tvb(offset, 1)) 
            offset = offset + 1  
            dissect_data(tvb(offset, opcode), tree) 
            offset = offset + opcode
        elseif opcode == 0x4c then -- 0x4c == OP_PUSHDATA1
            tree:add(fields.tx_script_opcode, tvb(offset, 1)) 
            offset = offset + 1  
            local len = tvb(offset, 1):uint()
            tree:add(fields.tx_script_data_len, tvb(offset, 1)) 
            offset = offset + 1  
            dissect_data(tvb(offset, len), tree) 
            offset = offset + len
        elseif opcode == 0x4d then
            tree:add(fields.tx_script_opcode, tvb(offset, 1)) 
            offset = offset + 1  
            local len = tvb(offset, 2):uint()
            offset = offset + len
        elseif opcode == 0x4e then
            tree:add(fields.tx_script_opcode, tvb(offset, 1)) 
            offset = offset + 1  
            local len = tvb(offset, 4):uint()
            offset = offset + len
        elseif opcode == 0x6a then -- 0x6a == OP_RETURN
            dissect_data2(tvb(offset), tree)
            break
        else
            tree:add(fields.tx_script_opcode, tvb(offset, 1)) 
            offset = offset + 1
        end
    end
    return len + n
end

function dissect_coinbase_data(tvb, pinfo, tree)
    local subtree = tree:add('Coinbase Data')
    
    local len, n = dissect_var_int(tvb(offset), subtree)

    -- BIP-34 specifies block height in block.version >= 2
    local offset = len 
    subtree:add(fields.tx_script_opcode, tvb(offset, 1)) 
    local opcode = tvb(offset, 1):uint()
    assert(opcode <=75)
    assert(opcode >=1)
    offset = offset + 1

    local block_height = tvb(offset, opcode):le_int()
    update_info_col(pinfo, tostring(block_height))
    subtree:add_le(fields.tx_in_block_height, tvb(offset, opcode)) 
    offset = offset + opcode

-- cjg
--    while offset < n do
--        local extra_nonce_len = tvb(offset, 1):uint()
--        offset = offset + 1
--        subtree:add(fields.tx_in_extra_nonce, tvb(offset,  extra_nonce_len))
--        offset = offset + extra_nonce_len
--    end
    
    return len + n
end

function dissect_unlocking_script(tvb, pinfo, tree)
    local subtree = tree:add('Unlocking Script/scriptSig/witness')
    return dissect_script(tvb, subtree)
end

function dissect_tx_in(tvb, pinfo, tree, block_version, iTx, iInput) 
    local subtree = tree:add('Input ' .. iInput)
    local offset = dissect_out_point(tvb(0, 36), subtree)
    
    local is_coinbase_tx = block_version >= 2 and 
                           block_version ~= 0x20000000 and 
                           iTx == 0 
    if is_coinbase_tx and iInput == 0 then
        offset = offset + dissect_coinbase_data(tvb(offset), pinfo, subtree) 
    else
        offset = offset + dissect_unlocking_script(tvb(offset), pinfo, subtree)
    end

    subtree:add(fields.tx_in_sequence, tvb(offset, 4))
    return offset + 4 
end
    
function dissect_tx_out(tvb, tree, index) 
    local subtree = tree:add('Output ' .. index)

    subtree:add_le(fields.tx_out_value, tvb(0, 8))

    local pub_key_tree = subtree:add('Locking Script/scriptPubKey/Witness Script')

    local n = dissect_script(tvb(8), pub_key_tree)
    return 8 + n
end

function dissect_tx(tvb, pinfo, tree, block_version, iTx)
    tree:add_le(fields.tx_version, tvb(0, 4))
    local offset = 4
    local len, n = dissect_var_int(tvb(4), tree)
    offset = offset + len


    for i=0, n-1 do 
        offset = offset + dissect_tx_in(tvb(offset), pinfo, tree, block_version, iTx, i) 
    end

    len, n = dissect_var_int(tvb(offset), tree)
    offset = offset + len
    for i = 0, n-1 do
        offset = offset + dissect_tx_out(tvb(offset), tree, i)
    end

    if tvb(offset, 4):le_uint() < 500000000 then
        tree:add_le(fields.tx_lock_block, tvb(offset, 4))
    else
        tree:add_le(fields.tx_lock_time, tvb(offset, 4))
    end

    return offset + 4
end

msg_dissectors.tx = function(tvb, pinfo, tree)
    local subtree = tree:add('Tx')
    local block_version = 0
    local iTx = 0
    dissect_tx(tvb, pinfo, subtree, block_version, iTx)
end

function dissect_target(tvb, tree)
    local length = tvb:len()
    assert(length == 4)
    local subtree = tree:add("target")
    subtree:add_le(fields.block_target_mantissa, tvb(0, 3))
    subtree:add(fields.block_target_exponent, tvb(3, 1))
end

function dissect_block_header(tvb, tree)
    local subtree = tree:add("block header")
    subtree:add_le(fields.block_version, tvb(0, 4))
    local block_version = tvb(0, 4):le_int()
    subtree:add(fields.block_prev_block, tvb(4, 32))
    subtree:add(fields.block_merkle_root, tvb(36, 32))
    subtree:add_le(fields.block_timestamp, tvb(68, 4))
    dissect_target(tvb(72, 4), subtree)
    subtree:add_le(fields.block_nonce, tvb(76, 4))
    return 80, block_version
end

msg_dissectors.getblocktxn = function(tvb, pinfo, tree)

    local subtree = tree:add("block transactions request")
    local offset = 0
    subtree:add(fields.block_tx_request_block_hash, tvb(offset, 32))
    offset = 32
    local len, n = dissect_var_int(tvb(offset), subtree)
    offset = offset + len

    for i = 1, n do
        local len, n = dissect_var_int(tvb(offset), subtree)
        offset = offset + len
    end
end

msg_dissectors.blocktxn = function(tvb, pinfo, tree)

    local subtree = tree:add("block transactions")
    local offset = 0
    subtree:add(fields.block_txs_block_hash, tvb(offset, 32))
    offset = offset + 32
    local len, n = dissect_var_int(tvb(offset), subtree)
    offset = offset + len
    for i = 1, n do
        offset = offset + dissect_tx(tvb(offset), pinfo, subtree, 0, 0)
    end

end

msg_dissectors.createstrm = function(tvb, pinfo, tree)
    local subtree = tree:add("createstream")
    local offset, n = dissect_var_int(tvb, subtree)

    subtree:add(fields.createstrm_assoc_id, tvb(offset, n))
    offset = offset + n
    subtree:add(fields.createstrm_stream_type, tvb(offset, 1))
    offset = offset + 1
    local len, m = dissect_var_int(tvb(offset), subtree)
    offset = offset + len
    subtree:add(fields.createstrm_stream_policy, tvb(offset, m))
end

msg_dissectors.streamack = function(tvb, pinfo, tree)
    local subtree = tree:add("streamack")
    local offset, n = dissect_var_int(tvb, subtree)

    subtree:add(fields.createstrm_assoc_id, tvb(offset, n))
    offset = offset + n
    subtree:add(fields.createstrm_stream_type, tvb(offset, 1))
end

msg_dissectors.block = function(tvb, pinfo, tree)
    local block_tree = tree:add("block")

    local _, block_version = dissect_block_header(tvb(0, 80), block_tree)
    local len, tx_count = dissect_var_int(tvb(80), block_tree) 
    local tx_start = 80 + len 
    for iTx = 0, tx_count-1 do
        local tx_tree = block_tree:add('Tx ' .. iTx)
        tx_start = tx_start + dissect_tx(tvb(tx_start), 
                                         pinfo, 
                                         tx_tree, 
                                         block_version,
                                         iTx) 
    end
end

function is_ext_header(tvb)
    return tvb(16, 4):le_uint() == 0xffffffff 
end

function dissect_header(tvb, pinfo, tree)
    local length = tvb:len()
    assert(length >= min_header_len)
    
    local subtree = tree:add("Header")
    subtree:add(fields.magic, tvb(0, 4))
    subtree:add(fields.cmd, tvb(4, 12))
    subtree:add_le(fields.length, tvb(16, 4))
    subtree:add(fields.checksum, tvb(20, 4))

    local cmd = tvb:range(4, 12):stringz() 

    if is_ext_header(tvb) then
        subtree:add(fields.ext_cmd, tvb(24, 12))
        subtree:add_le(fields.ext_length, tvb(36, 8))
        cmd = tvb:range(24, 12):stringz() .. ' (Ext. Msg.)'
    end
    
    update_info_col(pinfo, cmd)
    return cmd
end

msg_dissectors.inv = function (tvb, pinfo, tree)

    local subtree = tree:add("Inventory Vectors")

    local len, n = dissect_var_int(tvb, subtree) 

    local offset = len
    for i=0, n-1 do 
        subtree:add_le(fields.inv_type, tvb(offset, 4))
        offset = offset + 4
        subtree:add(fields.inv_hash, tvb(offset, 32))
        offset = offset + 32
    end
end

msg_dissectors.getdata = function (tvb, pinfo, tree)
    
    local len, n = dissect_var_int(tvb, tree)
    local offset = len 
    local subtree = tree:add("Inventory Vectors")
    for i=0, n-1 do 
        subtree:add_le(fields.inv_type, tvb(offset, 4))
        subtree:add(fields.hash, tvb(offset+4, 32))
        offset = offset + 36
    end
end

function dissect_getheaders_impl(tvb, pinfo, tree)
    tree:add_le(fields.getheaders_version, tvb(0, 4)) 
    
    local len, n  = dissect_var_int(tvb(4), tree)
    local offset = 4 + len
    for i=0, n-1 do
        tree:add(fields.hash, tvb(offset, 32))
        offset = offset + 32
    end
    
    -- hash stop 
    tree:add(fields.hash, tvb(offset, 32))
end

msg_dissectors.getheaders = function(tvb, pinfo, tree) 

    local subtree = tree:add("getheaders")
    dissect_getheaders_impl(tvb, pinfo, subtree)
end

msg_dissectors.gethdrsen = function(tvb, pinfo, tree) 

    local subtree = tree:add("gethdrsen")
    dissect_getheaders_impl(tvb, pinfo, subtree)
end

msg_dissectors.headers = function(tvb, pinfo, tree) 
    
    local subtree = tree:add("Block Headers")
    local len, n = dissect_var_int(tvb, subtree)
    local offset = len
    for i=0, n-1 do
        local blockTree = subtree:add('Block Header: ' .. i)
        offset = offset + dissect_block_header(tvb(offset), blockTree)
        offset = offset + dissect_var_int(tvb(offset), blockTree)
    end
    return offset
end

msg_dissectors.hdrsen = function(tvb, pinfo, tree) 

    local subtree = tree:add("Enhanced Block Headers")
    local len, n = dissect_var_int(tvb, subtree)
    local offset = len
    for i=0, n-1 do
        local blockTree = subtree:add('Enhanced Block Header: ' .. i)
        offset = offset + dissect_block_header(tvb(offset), blockTree)
        offset = offset + dissect_var_int(tvb(offset), blockTree)
    
        blockTree:add(fields.hdrsen_no_more_headers, tvb(offset, 1)) 
        offset = offset + 1
        blockTree:add(fields.hdrsen_has_coinbase_data, tvb(offset, 1)) 
        local has_coinbase_data = tvb(offset, 1):uint()
        offset = offset + 1
       
        if has_coinbase_data ~= 0 then
            offset = offset + dissect_merkle_proof2(tvb(offset), blockTree)

            local block_version = 0
            local iTx = 0
            local txTree = blockTree:add('Tx')
            offset = offset + dissect_tx(tvb(offset), pinfo, txTree, block_version, iTx)
        end
    end
    return offset

end

msg_dissectors.ping = function(tvb, pinfo, tree) 
    tree:add(fields.ping_nonce, tvb(0, 8))
end

msg_dissectors.pong = function(tvb, pinfo, tree) 
    tree:add(fields.pong_nonce, tvb(0, 8))
end

msg_dissectors.protoconf = function (tvb, pinfo, tree)

    len, n = dissect_var_int(tvb, tree)
    -- cjg
    -- http://github.com/bitcoin-sv-specs/protocol/blob/master/p2p/protoconf.md
    -- len, n = dissect_var_int(tvb(len), tree)
end

msg_dissectors.sendcmpct = function (tvb, pinfo, tree)
    local subtree = tree:add("Send Compact Blocks")
    subtree:add(fields.sendcmpct_on, tvb(0, 1))
    subtree:add_le(fields.sendcmpct_version, tvb(1, 8))
end

function dissect_prefilled_tx(tvb, pinfo, tree, block_version)
    local subtree = tree:add('Prefilled Tx')
    local len, n = dissect_var_int(tvb, subtree)
    local iTx = 0
    return dissect_tx(tvb(n+len), pinfo, subtree, block_version, iTx)
end

msg_dissectors.cmpctblock = function (tvb, pinfo, tree)
    local subtree = tree:add("Compact Block")
    local hasi_tree = subtree:add("HeaderAndShortIDs")

    local offset, block_version = dissect_block_header(tvb, hasi_tree)

    hasi_tree:add_le(fields.hasids_nonce, tvb(offset, 8))
    offset = offset + 8
    local len, n = dissect_var_int(tvb(offset), hasi_tree)
    offset = offset + len
    for i=0, n-1 do 
       offset = offset + 6 
    end

    len, n = dissect_var_int(tvb(offset), hasi_tree)
    offset = offset + len
    for i=0, n-1 do 
       len = dissect_prefilled_tx(tvb(offset), pinfo, hasi_tree, block_version, 0)
       offset = offset + len 
    end
end

msg_dissectors.feefilter = function (tvb, pinfo, tree)
    tree:add_le(fields.satoshis_per_kb, tvb(0, 8))
end

function dissect_header_list(tvb, tree)
    local subtree = tree:add('Header List')
    local offset, n = dissect_var_int(tvb, subtree)
    for i=0, n-1 do
        local len, _ = dissect_block_header(tvb(offset), subtree)
        offset = offset + len
    end
    return offset
end

function dissect_merkle_proof(tvb, tree)
    local subtree = tree:add('Merkle Proof')
    subtree:add(fields.dsdetected_mp_flags, tvb(0, 1))
    
    local offset = 1
    local len, tx_index = var_int(tvb(offset))
    offset = offset + len
    subtree:add('Tx Index', tx_index)
    
    local len2, tx_len = var_int(tvb(offset))
    offset = offset + len2
    subtree:add('Tx Length', tx_len)
   
    subtree:add(fields.dsdetected_mp_tx, tvb(offset, tx_len))
    offset = offset + tx_len
    subtree:add(fields.dsdetected_mp_merkle_root, tvb(offset, 32))
    offset = offset + 32

    local len3, node_count = var_int(tvb(offset))
    offset = offset + len3
    subtree:add('Node Count', node_count)

    for i=0, node_count-1 do
        subtree:add(fields.dsdetected_mp_node_type, tvb(offset, 1))
        offset = offset + 1
        -- assume type 0 i.e. 32 byte value
        subtree:add(fields.dsdetected_mp_node_value, tvb(offset, 32))
        offset = offset + 32 
    end
    return offset
end

function dissect_merkle_proof2(tvb, tree)
    local subtree = tree:add('Merkle Proof')
    
    local offset = 0 
    subtree:add(fields.dsdetected_mp_flags, tvb(offset, 1))
    local flags = tvb(offset, 1):le_uint()
    offset = offset + 1

    local len, n = dissect_var_int(tvb(offset), subtree) --index field
    offset = offset + len 

    if flags == 0 then
        subtree:add(fields.merkle_proof_txid, tvb(offset, 32))
        offset = offset + 32
    end

    -- cjg & not supported til lua 5.3 (see wireshark->help->about->Wireshark Compiled with...
    --if flags & 0x6  == 0 then
        subtree:add(fields.merkle_proof_target, tvb(offset, 32))
        offset = offset + 32
    --end
    
    local len3, node_count = var_int(tvb(offset))
    offset = offset + len3
    subtree:add('Node Count', node_count)

    for i=0, node_count-1 do
        subtree:add(fields.dsdetected_mp_node_type, tvb(offset, 1))
        offset = offset + 1
        -- assume type 0 i.e. 32 byte value
        subtree:add(fields.dsdetected_mp_node_value, tvb(offset, 32))
        offset = offset + 32 
    end
    return offset
    --dissect_var_int(tvb(offset), subtree) 

    
--    local offset = 1
--    local len, tx_index = var_int(tvb(offset))
--    offset = offset + len
--    subtree:add('Tx Index', tx_index)
--    
--    local len2, tx_len = var_int(tvb(offset))
--    offset = offset + len2
--    subtree:add('Tx Length', tx_len)
--   
--    subtree:add(fields.dsdetected_mp_tx, tvb(offset, tx_len))
--    offset = offset + tx_len
--    subtree:add(fields.dsdetected_mp_merkle_root, tvb(offset, 32))
--    offset = offset + 32
--
--    local len3, node_count = var_int(tvb(offset))
--    offset = offset + len3
--    subtree:add('Node Count', node_count)
--
--    for i=0, node_count-1 do
--        subtree:add(fields.dsdetected_mp_node_type, tvb(offset, 1))
--        offset = offset + 1
--        -- assume type 0 i.e. 32 byte value
--        subtree:add(fields.dsdetected_mp_node_value, tvb(offset, 32))
--        offset = offset + 32 
--    end
--    return offset
end

function dissect_block_details(tvb, tree)
    local subtree = tree:add('Block Detail')
    local offset = dissect_header_list(tvb, subtree)
    --return offset + dissect_merkle_proof(tvb(offset), subtree)
    local len = dissect_merkle_proof(tvb(offset), subtree)
    return offset + len
end

msg_dissectors.dsdetected = function (tvb, pinfo, tree)
    
    tree:add_le(fields.dsdetected_version, tvb(0, 2))
    local offset = 2

    local len, n = dissect_var_int(tvb(offset), tree)
    offset = offset + len

    local subtree = tree:add('Block Details')
    for i=0, n-1 do
        len = dissect_block_details(tvb(offset), subtree)        
        offset = offset + len
    end
end

msg_dissectors.unknown = function(cmd, pinfo)
    update_info_col(pinfo, '*** dissector not yet implemented ***')
end

function header_length(tvb)
    if is_ext_header(tvb) then
        return 44        
    else
        return 24
    end
end

function body_length(tvb)
    if is_ext_header(tvb) then
        -- Wireshark doesn't seem to be able to handle >4gb application messages
        -- Therefore, just show the extended headers
        --return tvb(36, 8):le_uint64()
        return 0
    else
        return tvb(16, 4):le_uint()
    end
end

-- pre-condition length(tvb) >= 4
function valid_magic_bytes(tvb)
    local b = tvb(0, 4):uint()
    for k, v in pairs(magic) do
        if(b == k) then
            return true
        end
    end
    return false
end

-- returns number bytes dissected, msg length 
function dissect_msg(tvb, pinfo, sv_tree)
    
    local seg_len = tvb:len()
    if seg_len >= 4 then 
        if not valid_magic_bytes(tvb) then
            update_info_col(pinfo, 'unrecognised magic bytes')
            return seg_len, 0 -- This is not a sv message
        end
    end

    if seg_len < min_header_len then 
        return 0, min_header_len
    end

    local header_len = header_length(tvb)
    if seg_len < header_len then
        return 0, header_length
    end 

    local body_len = body_length(tvb) 
    local msg_len = header_len + body_len
    if(msg_len > seg_len) then
        return 0, msg_len 
    end

    local msg_tree = sv_tree:add('msg')
        
    local cmd = dissect_header(tvb, pinfo, msg_tree)

    if body_len > 0 then
        local cmd_dissector = msg_dissectors[cmd]
        if cmd_dissector ~= nil then
            cmd_dissector(tvb(header_len), pinfo, msg_tree)
        else
            msg_dissectors.unknown(cmd, pinfo)
        end
    end
    
    return msg_len, msg_len
end

function bsv_protocol.dissector(tvb, pinfo, tree)
    local seg_len = tvb:len()

    pinfo.cols.protocol = bsv_protocol.name
    pinfo.cols.info = ''
    
    local subtree = tree:add(bsv_protocol, tvb(), "Bitcoin SV")

    --see https://wiki.wireshark.org/Lua/Dissectors
    local offset = 0
    while offset < seg_len do
        local msg_read, msg_len = dissect_msg(tvb(offset), pinfo, subtree)
        offset = offset + msg_read
        if msg_read == 0 then
            pinfo.desegment_len = offset + msg_len - seg_len 
            pinfo.desegment_offset = offset
            return 
        end
    end
end

local tcp_port_dissector = DissectorTable.get("tcp.port")

tcp_port_dissector:add(8333, bsv_protocol) -- mainnet
tcp_port_dissector:add(9333, bsv_protocol) -- stn
tcp_port_dissector:add(18333, bsv_protocol) -- testnet
tcp_port_dissector:add(18444, bsv_protocol) -- regtest

