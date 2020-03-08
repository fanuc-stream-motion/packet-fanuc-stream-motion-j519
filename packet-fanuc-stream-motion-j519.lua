--[[

  Copyright (c) 2018-2019, G.A. vd. Hoorn
  All rights reserved.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

  ---

  Primitive Wireshark dissector for the Fanuc "Stream Motion" protocol.

  TODO: improve documententation.

  This dissector uses some relatively recent features of the Wireshark Lua
  API, and is therefore not expected to work with anything older than version
  2.0.x.

]]
do
	-- feature detection
	assert (set_plugin_info and Pref.range, "This dissector (Fanuc Stream Motion (J519)) requires Wireshark 2 or newer.")


	-- 
	-- constants
	-- 
	local DISSECTOR_VERSION             = "0.0.6"

	local DEFAULT_J519_PORT             = 60015
	local FANUCROB_OUI                  = 0x00e0e4
	local GEFANUCA_OUI                  = 0x000991

	local DEF_NUM_AXES                  = 6
	local MAX_NUM_AXES                  = 9

	-- bit of a kludge: packets have fixed lengths
	local SZ_HEADER                     =   8
	local SZ_START_PKT                  =   SZ_HEADER
	-- TODO: mass of magic numbers
	local SZ_STATE_PKT                  =   SZ_HEADER + (4 + (2 * 1) + (3 * 2) + 4 + (9 * 4) + (9 * 4) + (9 * 4))
	local SZ_CMD_PKT                    =   SZ_HEADER + (4 + (2 * 1) + (2 * 2) + (2 * 1) + (4 * 2) + (9 * 4))
	local SZ_STOP_PKT                   =   SZ_HEADER
	local SZ_REQUEST_PKT                =   SZ_HEADER + (2 * 4)
	                                        -- TODO: incorrect when increment is not 5%
	local SZ_ACK_PKT                    =   SZ_HEADER + ((4 * 4) + (20 * 4) + (20 * 4))


	-- packet types PC -> ROBOT
	local PKT_TYPE_START_PKT                =   0
	local PKT_TYPE_CMD_PKT                  =   1
	local PKT_TYPE_STOP_PKT                 =   2
	local PKT_TYPE_REQUEST_PKT              =   3

	-- packet types ROBOT -> PC
	local PKT_TYPE_STATE_PKT                =   0
	local PKT_TYPE_ACK_PKT                  =   3


	-- state packet: status bits (all other bits are reserved)
	-- NOTE: bit positions, not masks
	local STATE_STATUS_BIT_0_CMD_READY        = 0  -- robot is ready to receive command packets
	local STATE_STATUS_BIT_1_CMD_READY_ACK    = 1  -- robot has received (at least one) command packet(s)
	local STATE_STATUS_BIT_2_SYSRDY_ON        = 2  -- 
	local STATE_STATUS_BIT_3_IN_MOTION        = 3  -- 1: robot is in motion. 0: robot is stopped


	-- IO types
	local IO_TYPE_DI                          = 1
	local IO_TYPE_DO                          = 2
	local IO_TYPE_RI                          = 8
	local IO_TYPE_RO                          = 9
	local IO_TYPE_SI                          = 11
	local IO_TYPE_SO                          = 12
	local IO_TYPE_WI                          = 16
	local IO_TYPE_WO                          = 17
	local IO_TYPE_UI                          = 20
	local IO_TYPE_UO                          = 21
	local IO_TYPE_WSI                         = 26
	local IO_TYPE_WSO                         = 27
	local IO_TYPE_F                           = 35
	local IO_TYPE_M                           = 36


	-- command packet: data style
	local CMD_DATA_STYLE_CARTESIAN            = 0
	local CMD_DATA_STYLE_JOINT                = 1


	-- request packet: threshold types
	local REQ_THRESHOLD_VEL                   = 0
	local REQ_THRESHOLD_ACC                   = 1
	local REQ_THRESHOLD_JRK                   = 2



	-- 
	-- constant -> string rep tables
	-- 
	local pkt_type_str = {
		[PKT_TYPE_START_PKT  ] = "Start",
		[PKT_TYPE_STOP_PKT   ] = "Stop",
		[PKT_TYPE_STATE_PKT  ] = "Robot Status",   -- TODO: same key a "data start"
		[PKT_TYPE_CMD_PKT    ] = "Motion Command",
		[PKT_TYPE_REQUEST_PKT] = "Request",
		[PKT_TYPE_ACK_PKT    ] = "Ack",            -- TODO: same key as "request"
	}

	local cmd_data_style_str = {
		[CMD_DATA_STYLE_CARTESIAN] = "Cartesian",
		[CMD_DATA_STYLE_JOINT    ] = "Joint",
	}

	local io_type_str = {
		[0          ] = "None",
		[IO_TYPE_DI ] = "DI",
		[IO_TYPE_DO ] = "DO",
		[IO_TYPE_RI ] = "RI",
		[IO_TYPE_RO ] = "RO",
		[IO_TYPE_SI ] = "SI",
		[IO_TYPE_SO ] = "SO",
		[IO_TYPE_WI ] = "WI",
		[IO_TYPE_WO ] = "WO",
		[IO_TYPE_UI ] = "UI",
		[IO_TYPE_UO ] = "UO",
		[IO_TYPE_WSI] = "WSI",
		[IO_TYPE_WSO] = "WSO",
		[IO_TYPE_F  ] = "F",
		[IO_TYPE_M  ] = "M",
	}


	local state_status_bit_str = {
		[STATE_STATUS_BIT_0_CMD_READY    ] = "Ready for commands",
		[STATE_STATUS_BIT_1_CMD_READY_ACK] = "Command received",
		[STATE_STATUS_BIT_2_SYSRDY_ON    ] = "SYSRDY",
		[STATE_STATUS_BIT_3_IN_MOTION    ] = "In motion",
	}


	local thresh_type_str = {
		[REQ_THRESHOLD_VEL] = "Velocity (deg/s)",
		[REQ_THRESHOLD_ACC] = "Acceleration (deg/s^2)",
		[REQ_THRESHOLD_JRK] = "Jerk (deg/s^3)",
	}


	local thresh_unit_str = {
		[REQ_THRESHOLD_VEL] = "deg/s",
		[REQ_THRESHOLD_ACC] = "deg/s^2",
		[REQ_THRESHOLD_JRK] = "deg/s^3",
	}


	-- TODO: hard-coded
	local axes_str_cart = {
		"X", "Y", "Z", "W", "P", "R", "E1", "E2", "E3",
	}

	-- TODO: hard-coded
	-- TODO: missing units for E1, E2, E3
	local axes_units_str = {
		"mm", "mm", "mm", "deg", "deg", "deg",
	}



	-- 
	-- misc
	-- 

	-- cache globals to local for speed
	local _F=string.format

	-- wireshark API globals
	local Pref = Pref

	-- minimal default config
	local config = {
		disp_unused = true,
		num_axes = DEF_NUM_AXES,
		ignore_mac = true,
	}

	local ctx = {
		pkt_to_robot = true
	}

	-- register version info with wireshark
	set_plugin_info({version = DISSECTOR_VERSION})




	-- 
	-- Protocol object creation and setup
	-- 
	local p_fanuc_stream_motion = Proto("FRJ519", "Fanuc Robotics - Stream Motion (J519)")

	-- preferences
	p_fanuc_stream_motion.prefs["udp_ports"] = Pref.range("UDP Ports", _F("%d", DEFAULT_J519_PORT), _F("UDP ports the dissector should be registered for (default: %d).", DEFAULT_J519_PORT), 65535)
	p_fanuc_stream_motion.prefs["disp_unused"] = Pref.bool ("Show reserved fields", true, "Should reserved fields be added to dissection tree?")
	p_fanuc_stream_motion.prefs["num_axes"] = Pref.uint("Number of axes", DEF_NUM_AXES, "Maximum nr of axes to display fields for (all values will always be dissected).")
	p_fanuc_stream_motion.prefs["ignore_mac"] = Pref.bool("Dissect all packets", true, "Do not check MAC address of incoming packets (ie: treat anything coming from the J519 UDP port as J519 packets).")


	-- 
	-- protocol fields
	--
	local fields = p_fanuc_stream_motion.fields

	fields.packet_type    = ProtoField.uint32("frj519.packet_type"   , "Packet Type"       , base.HEX    , pkt_type_str, nil, "Type of packet")
	fields.version_no     = ProtoField.uint32("frj519.version_no"    , "Version No"        , base.DEC_HEX, nil         , nil, "Version of packet")

	fields.sequence_no    = ProtoField.uint32("frj519.sequence_no"   , "Sequence No"       , base.DEC_HEX, nil         , nil, "Sequence number of packet")
	fields.last_data      = ProtoField.uint8 ("frj519.last_data"     , "Last Data"         , base.DEC    , {[0] = "No", [1] = "Yes"}, nil, "Last Data")
	fields.read_io_type   = ProtoField.uint8 ("frj519.read_io_type"  , "Reading I/O Type " , base.DEC    , io_type_str , nil, "Reading I/O Type")
	fields.read_io_index  = ProtoField.uint16("frj519.read_io_index" , "Reading I/O Index" , base.DEC    , nil         , nil, "Reading I/O Index")
	fields.read_io_mask   = ProtoField.uint16("frj519.read_io_mask"  , "Reading I/O Mask " , base.HEX    , nil         , nil, "Reading I/O Mask")  -- TODO: split out bits
	fields.read_io_value  = ProtoField.uint16("frj519.read_io_value" , "Read I/O Value"    , base.DEC_HEX, nil         , nil, "Reading I/O Value")
	fields.data_style     = ProtoField.uint8 ("frj519.data_style"    , "Data Style"        , base.DEC    , cmd_data_style_str, nil, "Data Style")
	fields.write_io_type  = ProtoField.uint8 ("frj519.write_io_type" , "Writing I/O Type " , base.DEC    , io_type_str , nil, "Writing I/O Type")
	fields.write_io_index = ProtoField.uint16("frj519.write_io_index", "Writing I/O Index" , base.DEC    , nil         , nil, "Writing I/O Index")
	fields.write_io_mask  = ProtoField.uint16("frj519.write_io_mask" , "Writing I/O Mask " , base.HEX    , nil         , nil, "Writing I/O Mask")  -- TODO: split out bits
	fields.write_io_value = ProtoField.uint16("frj519.write_io_value", "Writing I/O Value" , base.HEX    , nil         , nil, "Writing I/O Value")

	fields.cmd_unused     = ProtoField.uint16("frj519.cmd.unused"    , "Unused"            , base.HEX    , nil         , nil, "Unused")

	fields.status             = ProtoField.uint8 ("frj519.status"    , "Status"            , base.HEX    , nil         , nil, "Status")
	fields.status_rdy_for_cmd = ProtoField.uint8 ("frj519.status.rdy_for_cmd", _F("%-19s", state_status_bit_str[STATE_STATUS_BIT_0_CMD_READY    ]), base.DEC, nil, bit.lshift(1, STATE_STATUS_BIT_0_CMD_READY    ), state_status_bit_str[STATE_STATUS_BIT_0_CMD_READY    ])
	fields.status_cmd_rcvd    = ProtoField.uint8 ("frj519.status.cmd_rcvd"   , _F("%-19s", state_status_bit_str[STATE_STATUS_BIT_1_CMD_READY_ACK]), base.DEC, nil, bit.lshift(1, STATE_STATUS_BIT_1_CMD_READY_ACK), state_status_bit_str[STATE_STATUS_BIT_1_CMD_READY_ACK])
	fields.status_sysrdy      = ProtoField.uint8 ("frj519.status.sysrdy"     , _F("%-19s", state_status_bit_str[STATE_STATUS_BIT_2_SYSRDY_ON    ]), base.DEC, nil, bit.lshift(1, STATE_STATUS_BIT_2_SYSRDY_ON    ), state_status_bit_str[STATE_STATUS_BIT_2_SYSRDY_ON    ])
	fields.status_in_motion   = ProtoField.uint8 ("frj519.status.in_motion"  , _F("%-19s", state_status_bit_str[STATE_STATUS_BIT_3_IN_MOTION    ]), base.DEC, nil, bit.lshift(1, STATE_STATUS_BIT_3_IN_MOTION    ), state_status_bit_str[STATE_STATUS_BIT_3_IN_MOTION    ])

	fields.time_stamp     = ProtoField.uint32("frj519.time_stamp"    , "Time Stamp"        , base.DEC_HEX, nil         , nil, "Time stamp when position data and motor current are recorded. Unit is ms. Resolution is 2ms.")

	fields.axis_no        = ProtoField.uint32("frj519.axis_no"       , "Axis No"           , base.DEC    , nil         , nil, "Axis number (1-9)")
	fields.thresh_type    = ProtoField.uint32("frj519.threshold_type", "Threshold Type"    , base.DEC    , thresh_type_str, nil, "Threshold type")
	fields.max_cart_spd   = ProtoField.uint32("frj519.max_cart_spd"  , "Max Cart Speed"    , base.DEC    , nil         , nil, "Maximum Cartesian program speed of the robot (mm/s)")
	fields.cart_vel_incr  = ProtoField.uint32("frj519.cart_vel_incr" , "Cart Speed Incr"   , base.DEC    , nil         , nil, "Threshold table speed increment (percent per column)")



	local experts = p_fanuc_stream_motion.experts
	experts.to_robot = ProtoExpert.new("frj519.expert.to_robot", "Packet sent to robot controller", expert.group.REQUEST_CODE, expert.severity.NOTE)
	experts.from_robot = ProtoExpert.new("frj519.expert.from_robot", "Packet received from robot controller", expert.group.RESPONSE_CODE, expert.severity.NOTE)


	-- field extractors
	local f_eth_dst     = Field.new("eth.dst")

	local f_udp_dstport = Field.new("udp.dstport")
	local f_udp_srcport = Field.new("udp.srcport")

	local f_pkt_type    = Field.new("frj519.packet_type")
	local f_version_no  = Field.new("frj519.version_no")

	local f_data_style  = Field.new("frj519.data_style")
	local f_status      = Field.new("frj519.status")

	local f_axis        = Field.new("frj519.axis_no")
	local f_thresh_type = Field.new("frj519.threshold_type")
	local f_cart_vel_incr = Field.new("frj519.cart_vel_incr")







	local function is_pkt_to_robot()
		-- TODO: should GE Fanuc OUI be checked as well?
		return ((f_udp_dstport().value == DEFAULT_J519_PORT) and ((f_eth_dst().range(0, 3):uint() == FANUCROB_OUI) or config.ignore_mac))
	end

	local function pkt_from_robot()
		return (not is_pkt_to_robot())
	end

	local function get_pkt_len(pkt_type, pkt_to_robot)
		-- TODO: giant kludge
		if pkt_to_robot then
			local temp = {
				[PKT_TYPE_START_PKT  ] = SZ_START_PKT,
				[PKT_TYPE_STOP_PKT   ] = SZ_STOP_PKT,
				[PKT_TYPE_CMD_PKT    ] = SZ_CMD_PKT,
				[PKT_TYPE_REQUEST_PKT] = SZ_REQUEST_PKT,
			}
			return temp[pkt_type]
		else
			local temp = {
				[PKT_TYPE_STATE_PKT] = SZ_STATE_PKT,
				[PKT_TYPE_ACK_PKT  ] = SZ_ACK_PKT,
			}
			return temp[pkt_type]
		end
	end

	local function extract_pkt_type(buf, offset)
		return buf((offset + 0), 4):uint()
	end

	local function extract_pkt_version(buf, offset)
		return buf((offset + 4), 4):uint()
	end

	local function stringify_flagbits(bit_val, bit_tab)
		-- TODO: this loses order of flags
		local temp = {}
		for k, v in pairs(bit_tab) do
			if (bit.band(bit_val, bit.lshift(1, k)) > 0) then table.insert(temp, v) end
		end
		return table.concat(temp, ", ")
	end


	local function disf_pos_data(buf, tree, offset, num_elem, label, jnames, axis_units)
		local offset_ = offset
		local item_len = 4
		local jtree = tree:add(buf(offset_, (num_elem * item_len)), label)

		for i = 1, num_elem do
			local jbuf  = buf(offset_, item_len)
			local jval  = jbuf:float()
			local jname = jnames[i] or _F("J%d", i)
			local junits = axis_units[i] or "deg"
			jtree:add(jbuf, _F("%-6s: %10.5f", jname, jval)):append_text(" " .. junits)
			offset_ = offset_ + item_len
		end

		return (offset_ - offset)
	end


	local function disf_threshold_data(buf, tree, offset, label, vel_incr, axis_units)
		local offset_ = offset
		local item_len = 4
		-- TODO: make sure num_elem is an int
		local num_elem = 100/vel_incr
		local jtree = tree:add(buf(offset_, (num_elem * item_len)), label)

		-- start at first increment (never 0)
		local perc = vel_incr

		-- loop over all columns
		for i = 1, num_elem do
			local jbuf  = buf(offset_, item_len)
			local jval  = jbuf:float()
			jtree:add(jbuf, _F("%3.0f%% of Vmax: %7.2f", perc, jval)):append_text(" " .. axis_units)
			offset_ = offset_ + item_len
			perc = perc + vel_incr
		end

		return (offset_ - offset)
	end


	local function disf_p2r_start_pkt(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- nothing here

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function disf_p2r_cmd_pkt(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		lt:add(fields.sequence_no, buf(offset_, 4))
		offset_ = offset_ + 4

		lt:add(fields.last_data, buf(offset_, 1))
		offset_ = offset_ + 1

		local io_read_tree = lt:add(buf(offset_, 5), "Read IO")

			io_read_tree:add(fields.read_io_type, buf(offset_, 1))
			offset_ = offset_ + 1

			io_read_tree:add(fields.read_io_index, buf(offset_, 2))
			offset_ = offset_ + 2

			io_read_tree:add(fields.read_io_mask, buf(offset_, 2))
			offset_ = offset_ + 2

		lt:add(fields.data_style, buf(offset_, 1))
		offset_ = offset_ + 1

		local io_write_tree = lt:add(buf(offset_, 7), "Write IO")

			io_write_tree:add(fields.write_io_type, buf(offset_, 1))
			offset_ = offset_ + 1

			io_write_tree:add(fields.write_io_index, buf(offset_, 2))
			offset_ = offset_ + 2

			io_write_tree:add(fields.write_io_mask, buf(offset_, 2))
			offset_ = offset_ + 2

			io_write_tree:add(fields.write_io_value, buf(offset_, 2))
			offset_ = offset_ + 2

		lt:add(fields.cmd_unused, buf(offset_, 2))
		offset_ = offset_ + 2


		-- dissect commanded axis values
		local xn = {}
		local xu = {}
		if f_data_style().value == CMD_DATA_STYLE_CARTESIAN then
			xn = axes_str_cart
			xu = axes_units_str
		end
		offset_ = offset_ + disf_pos_data(buf, lt, offset_, MAX_NUM_AXES, "Joint Data", xn, xu)


		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function disf_r2p_state_pkt(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		lt:add(fields.sequence_no, buf(offset_, 4))
		offset_ = offset_ + 4

		local status_bit_tree = lt:add(fields.status, buf(offset_, 1))

			status_bit_tree:add(fields.status_rdy_for_cmd, buf(offset_, 1))
			status_bit_tree:add(fields.status_cmd_rcvd   , buf(offset_, 1))
			status_bit_tree:add(fields.status_sysrdy     , buf(offset_, 1))
			status_bit_tree:add(fields.status_in_motion  , buf(offset_, 1))

		offset_ = offset_ + 1

		-- append high bit flags to bitfield parent item
		if f_status().value ~= 0 then
			status_bit_tree:append_text(_F(" (%s)", stringify_flagbits(f_status().value, state_status_bit_str)))
		end

		local io_read_tree = lt:add(buf(offset_, 7), "Read IO")

			io_read_tree:add(fields.read_io_type, buf(offset_, 1))
			offset_ = offset_ + 1

			io_read_tree:add(fields.read_io_index, buf(offset_, 2))
			offset_ = offset_ + 2

			io_read_tree:add(fields.read_io_mask, buf(offset_, 2))
			offset_ = offset_ + 2

			io_read_tree:add(fields.read_io_value, buf(offset_, 2))
			offset_ = offset_ + 2

		lt:add(fields.time_stamp, buf(offset_, 4))
		offset_ = offset_ + 4

		-- dissect commanded axis values
		offset_ = offset_ + disf_pos_data(buf, lt, offset_, MAX_NUM_AXES,
			"Cartesian Pose (world -> tool0)", axes_str_cart, axes_units_str)

		-- "Jn" labels will be automatically generated.
		-- Units are assumed to be 'degree' for all axes (TODO: fix)
		offset_ = offset_ + disf_pos_data(buf, lt, offset_, MAX_NUM_AXES,
			"Joint Pose", {}, {})

		-- TODO: ugly
		offset_ = offset_ + disf_pos_data(buf, lt, offset_, MAX_NUM_AXES,
			"Motor Current", {}, {"A", "A", "A", "A", "A", "A", "A", "A", "A"})

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function disf_p2r_request_pkt(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		lt:add(fields.axis_no, buf(offset_, 4))
		offset_ = offset_ + 4

		lt:add(fields.thresh_type, buf(offset_, 4))
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function disf_r2p_ack_pkt(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		lt:add(fields.axis_no, buf(offset_, 4))
		offset_ = offset_ + 4

		lt:add(fields.thresh_type, buf(offset_, 4))
		offset_ = offset_ + 4

		lt:add(fields.max_cart_spd, buf(offset_, 4)):append_text(" mm/s")
		offset_ = offset_ + 4

		lt:add(fields.cart_vel_incr, buf(offset_, 4))
		offset_ = offset_ + 4

		-- dissect threshold limit values
		local unit_str = thresh_unit_str[f_thresh_type().value] or "ERROR"
		local num_elem = f_cart_vel_incr().value
		offset_ = offset_ + disf_threshold_data(buf, lt, offset_,
			"Thresholds - NO load", num_elem, unit_str)

		offset_ = offset_ + disf_threshold_data(buf, lt, offset_,
			"Thresholds - MAX load", num_elem, unit_str)

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	-- 
	-- pkt type -> dissection function map
	-- 
	-- true  : PC -> Robot
	-- false : Robot -> PC
	-- 
	local map_pkt_type_to_disf = {
		[true] = {
			--[PKT_TYPE_START_PKT] = disf_p2r_start_pkt,
			[PKT_TYPE_CMD_PKT] = disf_p2r_cmd_pkt,
			--[PKT_TYPE_STOP_PKT] = disf_p2r_start_pkt,
			[PKT_TYPE_REQUEST_PKT] = disf_p2r_request_pkt,
		},
		[false] = {
			[PKT_TYPE_STATE_PKT] = disf_r2p_state_pkt,
			[PKT_TYPE_ACK_PKT] = disf_r2p_ack_pkt,
		}
	}


	local function parse(buf, pkt, tree, offset, pkt_type)
		local offset_ = offset
		local lt = tree

		if ctx.pkt_to_robot then
			lt:add_proto_expert_info(experts.to_robot)
		else
			lt:add_proto_expert_info(experts.from_robot)
		end

		-- header tree
		local hdr_tree = lt:add(buf(offset_, 8), "Header")
			hdr_tree:add(fields.packet_type, buf(offset_, 4))
			offset_ = offset_ + 4
			hdr_tree:add(fields.version_no, buf(offset_, 4))
			offset_ = offset_ + 4

		-- retrieve dissection function for packet type
		local f = map_pkt_type_to_disf[ctx.pkt_to_robot][pkt_type]


		-- TODO: kludge: work-around START vs STATE ambiguity
		if buf:len() > 8 then
			if (f) and (type(f) == "function") then
				-- if we found something and it is a function, call it
				offset_ = offset_ + f(buf, pkt, lt, offset_)
			end
		end

		-- mark bytes we haven't dissected as such
		local zlen = (buf:len() - (offset_ - offset))
		if (zlen > 0) then
			lt:add(buf(offset_, zlen), _F("Undissected (%u bytes)", zlen))
			offset_ = offset_ + zlen
		end

		-- fixup body buffer highlight length
		-- TODO: should this be done here or in main dissector function?
		lt:set_len(offset_ - offset)

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	-- actual dissector method
	function p_fanuc_stream_motion.dissector(buf, pkt, tree)
		--info("---------------")
		-- check buffer len
		local buf_len = buf:len()
		--info("buffer length: " .. buf_len)
		-- anything less than the size of a header will not do
		if (buf_len <= 0) or (buf_len < SZ_HEADER) then return end

		-- either we resume dissecting, or we start fresh
		local offset = pkt.desegment_offset or 0
		--info("offset: " .. offset)

		-- keep dissecting as long as there are bytes available
		while true do
			-- see whether this is a request or reply pkt
			ctx.pkt_to_robot = is_pkt_to_robot()
			--info("to robot: " .. tostring(ctx.pkt_to_robot))

			-- retrieve the pkt type from the header and use it to figure out
			-- how many bytes we really would need to dissect this pkt.
			-- if this is an unknown packet get_pkt_len() returns None, so
			-- make sure to catch that.
			local pkt_type = extract_pkt_type(buf, offset)
			local pkt_len = get_pkt_len(pkt_type, ctx.pkt_to_robot) or 0

			--info("pkt_type: " .. pkt_type)
			--info("pkt_len: " .. pkt_len)

			-- create string repr of packet type
			local pkt_t_str = pkt_type_str[pkt_type] or "Unknown"
			--info("pkt_t_str: " .. pkt_t_str)

			-- TODO: kludge: packet ID 0 is used for both the 'start pkt'
			-- and the 'state' pkt. That is unfortunate, as it complicates
			-- the code. For now work-around it with this conditional
			if (pkt_type == PKT_TYPE_STATE_PKT) and (buf_len == SZ_START_PKT) then
				pkt_t_str = "Data Output Start"
				pkt_type = PKT_TYPE_START_PKT
				pkt_len = SZ_START_PKT
			end

			-- TODO: kludge: override pkt name we display for "type 3" pkts,
			-- depending on whether it is sent to the controller, or received.
			-- NOTE: this does not 'fix' fields.packet_type, so the pkt name
			-- shown in the dissection tree will be wrong
			if (ctx.pkt_to_robot) and (pkt_type == PKT_TYPE_REQUEST_PKT) then
				pkt_t_str = "Request"
			end

			-- '0' is an invalid packet length, so abort
			if pkt_len == 0 then
				critical("Unknown pkt type for pkt " .. pkt.number)
				return
			end

			--info("pkt_type: " .. pkt_type)
			--info("pkt_len: " .. pkt_len)

			-- TODO: is reassembly over UDP even supported?
			-- If we don't have enough bytes in the buffer, signal
			-- caller by setting appropriate fields in 'pkt' argument
			-- NOTE: this should never happen, as the docs state (imply)
			--       that pkts will always be sent in single datagrams,
			--       and don't cross datagram boundaries, but you never know
			local nextpkt = offset + pkt_len
			--info("nextpkt: " .. nextpkt)
			if (nextpkt > buf_len) then
				pkt.desegment_len = nextpkt - buf_len
				pkt.desegment_offset = offset
				return
			end

			-- add protocol to tree
			local prot_tree = tree:add(p_fanuc_stream_motion, buf(offset, pkt_len))

			-- dissect pkt
			local res = parse(buf, pkt, prot_tree, offset, pkt_type)

			-- add some extra info to the protocol line in the packet treeview
			prot_tree:append_text(_F(", %s (0x%02x), %u bytes", 
				pkt_t_str, pkt_type, pkt_len))

			-- add info to top pkt view
			pkt.cols.protocol = p_fanuc_stream_motion.name

			-- for outgoing requests, add some info on what is requested
			local extra_str = ""
			if (pkt_type == PKT_TYPE_REQUEST_PKT) and (ctx.pkt_to_robot) then
				local thresht_str = thresh_type_str[f_thresh_type().value] or "UNKNOWN"
				extra_str = _F(", J%d, %s", f_axis().value, thresht_str)
			end

			-- use offset in buffer to determine if we need to append to or set
			-- the info column
			if (offset > 0) then
				pkt.cols.info:append(_F("; %s (0x%02x)%s", pkt_t_str, pkt_type, extra_str))
			else
				pkt.cols.info = _F("%s (0x%02x)%s", pkt_t_str, pkt_type, extra_str)
			end

			-- increment 'read pointer' and stop if we've dissected all bytes 
			-- in the buffer
			offset = nextpkt
			if (offset == buf_len) then return end

		-- end-of-dissect-while
		end

	-- end-of-dissector
	end


	-- init routine
	function p_fanuc_stream_motion.init()
		-- update config from prefs
		config.disp_unused = p_fanuc_stream_motion.prefs["disp_unused"]
		config.num_axes = p_fanuc_stream_motion.prefs["num_axes"]
		config.ignore_mac = p_fanuc_stream_motion.prefs["ignore_mac"]

		-- register the dissector
		local udp_dissector_table = DissectorTable.get("udp.port")
		udp_dissector_table:add(p_fanuc_stream_motion.prefs.udp_ports, p_fanuc_stream_motion)
	end
end
