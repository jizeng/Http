作者：fanxiaoyu321 
来源：CSDN 
原文：https://blog.csdn.net/xiaoyu_750516366/article/details/85219050 
版权声明：本文为博主原创文章，转载请附上博文链接！

客户端通过调用connect()系统调用建立与服务器的连接，对应到TCP协议层次，核心操作就是TCP的三次握手（从客户端角度），由于整个过程涉及内容较多，分两部分来看connect()的实现，这篇笔记是第一部分，包括系统调用入口以及SYN报文发送过程。

1. 内核入口
/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	lock_sock(sk);

	//connect()时，服务器端地址族必须要指定
	if (uaddr->sa_family == AF_UNSPEC) {
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	//根据socket的状态进行处理，这里只有到scoket的状态为SS_UNCONNECTED时才进行真正的处理，其余情况均返回错误
	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		//connect()不能重复调用
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		//正在连接
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;
		//TCB的状态必须为TCP_CLOSE状态
		if (sk->sk_state != TCP_CLOSE)
			goto out;
		//调用传输层接口进行connect()操作，AF_INET中TCP为tcp_v4_connect()
		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;
		//执行成功，将socket的状态设置为SS_CONNECTING状态，表示正在连接
		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	//根据是否是阻塞操作，确定connect()调用的超时时间，
	//阻塞模式下，connect()返回时三次握手已经完成了
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	//如果上面执行都没有问题，那么此时TCP的状态应该为TCPF_SYN_SENT或者TCPF_SYN_RECV(同时打开场景)
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		//timeo为0表示为非阻塞操作，这时直接返回；否则调用inet_wai_for_connect()
		//等待连接成功或者超时，如果连接成功则该函数返回非0，这时直接返回，否则进行超时处理
		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo))
			goto out;
		//检查是否有错误发生
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	//连接建立失败情形处理
	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */
	//连接建立成功，设置socket的状态为SS_CONNECTED
	sock->state = SS_CONNECTED;
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	//连接失败，socket的状态设置为SS_UNCONNECTED
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
2. SYN包发送
上面的核心操作是调用传输层协议提供的connect()回调，对于TCP over IP，该函数就是tcp_v4_init()，该函数的最终目的就是要发送SYN请求。

/* This will initiate an outgoing connection. */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
	int tmp;
	int err;

	//校验目标地址长度
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;
	//校验地址族，该函数只处理IPv4
	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	//路由相关处理
	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}
	//路由缓存相关操作
	tmp = ip_route_connect(&rt, nexthop, inet->saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->sport, usin->sin_port, sk, 1);
	if (tmp < 0) {
		if (tmp == -ENETUNREACH)
			IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return tmp;
	}
	//TCP不支持多播和广播，返回错误
	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}
	//源路由选项相关处理
	if (!inet->opt || !inet->opt->srr)
		daddr = rt->rt_dst;
	//如果没有指定过bind()，那么源地址还尚未确定，这时源IP选用路由查询结果中的源IP
	if (!inet->saddr)
		inet->saddr = rt->rt_src;
	inet->rcv_saddr = inet->saddr;

	//时间戳选项相关处理
	if (tp->rx_opt.ts_recent_stamp && inet->daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer(rt);
		/*
		 * VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state
		 * TIME-WAIT * and initialize rx_opt.ts_recent from it,
		 * when trying new connection.
		 */
		if (peer != NULL &&
		    peer->tcp_ts_stamp + TCP_PAWS_MSL >= get_seconds()) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	//将目的地址和目的端口保存到TCB中
	inet->dport = usin->sin_port;
	inet->daddr = daddr;
	//设置TCP首部选项部分长度
	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;
	//初始化对端MSS为536
	tp->rx_opt.mss_clamp = 536;

	//设置TCP状态为TCP_SYN_SENT
	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	//如果需要，该函数动态绑定一个端口并将该传输控制块加入到ehash散列表中
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	//上一步操作可能会导致源端口和源地址信息发生变化，所以这里可能需要重新路由
	err = ip_route_newports(&rt, IPPROTO_TCP,
				inet->sport, inet->dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

	//计算一个客户端初始发送序号
	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number(inet->saddr,
							   inet->daddr,
							   inet->sport,
							   usin->sin_port);

	inet->id = tp->write_seq ^ jiffies;

	//构造并发送SYN包
	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->dport = 0;
	return err;
}
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
2.1 端口绑定
该操作实际上会完成两件事情：

如果调用connect()之前没有执行过绑定操作，则为该传输控制块绑定一个本地地址，这个过程和bind()时调用的inet_csk_get_port()，但是它们使用的端口冲突检测函数不同(具体为什么还没研究过)；
将绑定后的TCB加入到TCP的ehash哈希表中。
/*
 * Bind a port for a connect operation and hash it.
 */
int inet_hash_connect(struct inet_timewait_death_row *death_row,
		      struct sock *sk)
{
	return __inet_hash_connect(death_row, sk, inet_sk_port_offset(sk),
			__inet_check_established, __inet_hash_nolisten);
}

int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		void (*hash)(struct sock *sk))
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	const unsigned short snum = inet_sk(sk)->num;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sk->sk_net;

	//端口的自动绑定部分非常类似于时调用的inet_csk_get_port()
	if (!snum) {
		int i, remaining, low, high, port;
		static u32 hint;
		u32 offset = hint + port_offset;
		struct hlist_node *node;
		struct inet_timewait_sock *tw = NULL;

		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1;

		local_bh_disable();
		for (i = 1; i <= remaining; i++) {
			port = low + (i + offset) % remaining;
			head = &hinfo->bhash[inet_bhashfn(port, hinfo->bhash_size)];
			spin_lock(&head->lock);

			/* Does not bother with rcv_saddr checks,
			 * because the established check is already
			 * unique enough.
			 */
			inet_bind_bucket_for_each(tb, node, &head->chain) {
				if (tb->ib_net == net && tb->port == port) {
					BUG_TRAP(!hlist_empty(&tb->owners));
					if (tb->fastreuse >= 0)
						goto next_port;
					if (!check_established(death_row, sk,
								port, &tw))
						goto ok;
					goto next_port;
				}
			}

			tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					net, head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				break;
			}
			tb->fastreuse = -1;
			goto ok;

		next_port:
			spin_unlock(&head->lock);
		}
		local_bh_enable();

		return -EADDRNOTAVAIL;

ok:
		hint += i;

		/* Head lock still held and bh's disabled */
		//将TCB和端口绑定
		inet_bind_hash(sk, tb, port);
		if (sk_unhashed(sk)) {
			inet_sk(sk)->sport = htons(port);
			hash(sk);
		}
		spin_unlock(&head->lock);

		if (tw) {
			inet_twsk_deschedule(tw, death_row);
			inet_twsk_put(tw);
		}

		ret = 0;
		goto out;
	}

	head = &hinfo->bhash[inet_bhashfn(snum, hinfo->bhash_size)];
	tb  = inet_csk(sk)->icsk_bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		//将TCB加入到TCP的ehash哈希表中
		hash(sk);
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = check_established(death_row, sk, snum, NULL);
out:
		local_bh_enable();
		return ret;
	}
}
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
3. SYN包的构造以及发送
该操作就是构造一个SYN报文，并将其发送出去，但是由于TCP要提供可靠性服务，所以发送完之后还需要将该SYN报文加入到发送队列，并启动SYN重传定时器，只有等收到对端的ACK报文后，才能将该报文从发送队列删除并停止SYN重传定时器。

/*
 * Build a SYN and send it off.
 */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;

	//对TCB进行一定的初始化
	tcp_connect_init(sk);

	//分配一个SKB用于构造SYN段
	buff = alloc_skb_fclone(MAX_TCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(buff == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
	skb_reserve(buff, MAX_TCP_HEADER);

	tp->snd_nxt = tp->write_seq;
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPCB_FLAG_SYN);
	TCP_ECN_send_syn(sk, buff);

	/* Send it off. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tp->retrans_stamp = TCP_SKB_CB(buff)->when;
	skb_header_release(buff);
	//把SKB加入发送队列，并更新相关的统计值
	__tcp_add_write_queue_tail(sk, buff);
	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	tp->packets_out += tcp_skb_pcount(buff);
	//发送该SYN请求报文
	tcp_transmit_skb(sk, buff, 1, GFP_KERNEL);

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	TCP_INC_STATS(TCP_MIB_ACTIVEOPENS);

	//启动SYN重传定时器，初始超时时间为1s
	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}

