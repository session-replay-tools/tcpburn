#[Gryphon](https://github.com/wangbin579/gryphon) - Simulating millions of concurrent users

#简单说明
Gryphon是由网易自主研发的能够模拟千万级别并发用户的一个软件，目的是能够用较少的资源来模拟出大量并发用户，并且能够更加真实地进行压力测试， 以解决网络消息推送服务方面的压力测试的问题和传统压力测试的问题。Gryphon分为两个程序，一个运行gryphon，用来模拟用户，一个是 intercept，用来截获响应包信息给gryphon。Gryphon模拟用户的本质是用一个连接来模拟一个用户，所以有多少个连接，就有多少个用户，而用户的素材则取自于pcap抓包文件。

值得注意的是，Gryphon架构类似于tcpcopy，也可以采用传统使用方式和高级使用方式。

#下载地址：

###intercept程序

	git clone git://github.com/wangbin579/tcpcopy.git

###gryhpon程序：

	git clone git://github.com/wangbin579/gryphon.git


#传统使用

###1）下载编译运行intercept（运行类似于tcpcopy的intercept）：

	git clone git://github.com/wangbin579/tcpcopy.git
	cd tcpcopy
	sh autogen.sh
	./configure --enable-single   #由于gryphon可以模拟大量用户，一般只需要运行一个gryphon实例即可，这时候gryphon采用"--enable-single"模式最佳
	make
	make install
	具体执行如下：

      using ip queue (kernel < 3.5):
        modprobe ip_queue # if not running
        iptables -I OUTPUT -p tcp --sport port -j QUEUE # if not set
        ./intercept 

      or

      using nfqueue (kernel >= 3.5):
        iptables -I OUTPUT -p tcp --sport port -j NFQUEUE # if not set
        ./intercept

	如果是comet应用，那么应该在intercept设置-x参数，设置可以访问测试服务器的IP地址，以便让这个ip地址来publish主题

###2）下载编译运行gryphon：

	git clone git://github.com/wangbin579/gryphon.git
	cd gryphon
	sh autogen.sh
	
	如果是非comet应用：
	./configure --enable-single
	如果是comet类似的消息推送应用
	./configure --enable-single --enable-comet  #会过滤掉pcap文件中的连接关闭命令，由服务器来主动关闭连接
	
	make
	make install
	
	./gryphon -x historyServerPort-targetServerIP:targetServerPort -f <pcapfile,> -s <intercept address> -u <user num> -c <ip range,>
	
	比如：
	
	./gryphon -x 18081-61.xxx.xxx.217:8001 -f /home/wangbin/work/github/161_18081.pcap -s 10.yyy.yyy.217 -u 10000 -c 62.135.200.*
	
	从/home/wangbin/161_18081.pcap抓包文件中提取出访问18081端口的用户会话过程，复制到61.xxx.xxx.217服务器的8001端口中去，其中模拟的用户数量为10000个用户，ip地址范围为62.135.200.*系列,intercept所在的机器ip地址为10.yyy.yyy.217

###传统使用方式注意事项：

	1）-c参数指定的ip地址范围，目前只能是最后一个为‘*'，如果需要多个网段的ip地址，则采用‘,’隔开
	2）-s参数指定intercept所在机器的地址，一般只需指定ip地址即可
	3）-f文件，用来指定需要回放的pcap文件，要确保此文件尽可能完整，而且不丢包
	4）对于消息推送服务，需要用不同于targetServerIP的方式来访问（比如内网ip地址来publish主题，外网ip地址来供模拟客户端用户来访问），并设置intercept的-x参数
	5) gryphon定义的一个用户，就是一个连接的会话，从pcap文件中提取，所以用户构造会话过程，要注意连接的特性。
	6）采用传统方式，一定要确保ip queue或者nfqueue不丢包
	7）对于pcap文件，还可以采用-F参数来过滤。
	8）对于comet应用，pcap文件最好不要包含publish的请求
	9）更多信息还可以见-h命令

#高级使用方式

高级使用方式原理同tcpcopy，需要辅助服务器来截获从测试服务器路由过来的响应包信息

###1）下载编译运行intercept（运行类似于tcpcopy的intercept）：

	git clone git://github.com/wangbin579/tcpcopy.git
	cd tcpcopy
	sh autogen.sh
	./configure --enable-single  --enable-pcap --enable-advanced  #由于gryphon可以模拟大量用户，一般只需要运行一个gryphon实例即可，采用"--enable-single"模式效果最佳
	make
	make install
	
	具体执行如下：
	
	On the assistant server which runs intercept (the TCPCopy server) (root privilege is required):
	  ./intercept -F <filter> -i <device,> 
	
	  Note that the filter format is the same as the pcap filter.
	  For example:
	  ./intercept -i eth0 -F 'tcp and src port 80' -d
	  Intercept will capture response packets of the TCP based application which listens on port 80 
	  from device eth0 

###2）在测试服务器设置路由信息：

	On the test server which runs test server applications (root privilege is required):
	  Set route command appropriately to route response packets to the assistant server
	
	  For example:
	
	  Assume 61.135.233.219 is the actual IP address which is the default gateway, while 
	  61.135.233.161 is the IP address of the assistant server. We set the following route 
	  commands to route all extenal responses to the assistant server.
	
	  route del default gw 61.135.233.219
	  route add default gw 61.135.233.161
	
	  如果是comet应用，那么应该确保publish主题的ip地址的访问，其响应不能路由到辅助服务器中去

###3）下载编译运行gryphon：

	git clone git://github.com/wangbin579/gryphon.git
	cd tcpcopy
	sh autogen.sh
	
	如果是非comet应用：
	./configure --enable-single --enable-advanced
	如果是comet类似的消息推送应用
	./configure --enable-single --enable-advanced --enable-comet  #会过滤掉pcap文件中的连接关闭命令，由服务器来主动关闭连接
	
	make
	make install
	
	./gryphon -x historyServerPort-targetServerIP:targetServerPort -f <pcapfile,> -s <intercept address> -u <user num> -c <ip range,>
	
	比如：
	
	./gryphon -x 18081-61.xxx.xxx.217:8001 -f /home/wangbin/work/github/161_18081.pcap -s 10.yyy.yyy.208 -u 10000 -c 62.135.200.*
	
	从/home/wangbin/161_18081.pcap抓包文件中提取出访问18081端口的用户会话过程，复制到61.xxx.xxx.217服务器的8001端口中去，其中模拟的用户数量为10000个用户，ip地址范围为62.135.200.*系列,intercept所在的机器ip地址为10.yyy.yyy.208

###高级使用方式注意事项：
	
	1）-c参数指定的ip地址范围，目前只能是最后一个为‘*'，如果需要多个网段的ip地址，则采用‘,’隔开
	2）-s参数指定intercept所在机器的地址，一般只需指定ip地址即可
	3）-f文件，用来指定需要回放的pcap文件，要确保此文件尽可能完整，而且不丢包
	4）对于消息推送服务，需要确保有IP地址能够publish主题（比如内网ip地址来publish主题，外网ip地址来供模拟客户端用户来访问，外网的访问，其响应走辅助服务器）
	5）gryphon定义的一个用户，就是一个连接的会话，从pcap文件中提取，所以用户构造会话过程，要注意连接的特性。
	6）对于pcap文件，还可以采用-F参数来过滤。
	7）对于comet应用，pcap文件最好不要包含publish的请求
	8）更多信息还可以见-h命令

