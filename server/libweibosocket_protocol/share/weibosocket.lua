-- This is a prottocol dissector for wireshark.
-- Not completed yet.

do
	wsocket_v1 = Proto("weibosocket","weibosocket V1","weibosocket Protocol Version 1")

	-- dissector函数
	function wsocket_v1.dissector(buffer,pinfo,tree)
		--pinfo的成员可以参考用户手册
		pinfo.cols.protocol = "weibosocket"
		pinfo.cols.info = "weibosocket data"
		remain=buffer:len()
		local subtree = tree:add(wsocket_v1,buffer(),"weibosocket_V1 "..remain.." (Bytes)")
		--    subtree:add(buffer(0,2),"The first two bytes: " .. buffer(0,2):uint())
		--    subtree = subtree:add(buffer(2,2),"The next two bytes")
		--    subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
		--    subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
		return DESEGMENT_ONE_MORE_SEGMENT
	end


	tcp_table = DissectorTable.get("tcp.port")  
	--注册到tcp的1935端口
	tcp_table:add(8100,wsocket_v1)
end

