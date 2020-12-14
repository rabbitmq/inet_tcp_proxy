%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 1997-2018. All Rights Reserved.
%% 
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%% 
%% %CopyrightEnd%
%%
%% Originally based on inet_tcp_dist and inet_tls_dist.
-module(inet_tcp_proxy_dist).

-export([enable/0]).

%% Handles the connection setup phase with other Erlang nodes.

-export([listen/1, accept/1, accept_connection/5,
	 setup/5, close/1, select/1, is_node_name/1]).

%% Optional
-export([setopts/2, getopts/2]).

%% Generalized dist API
-export([gen_listen/2, gen_accept/2, gen_accept_connection/6,
	 gen_setup/6, gen_select/2]).

%% internal exports

-export([accept_loop/3,do_accept/7,do_setup/7,getstat/1,tick/3]).

-export([dist_proc_start_link/0, dist_proc_init/1, dist_proc_loop/3]).
-export([system_continue/3,
         system_terminate/4,
         system_get_state/1,
         system_replace_state/2]).

-export([allow/1, block/1, is_blocked/1, info/0]).
-export([notify_new_state/2, dbg/1]).

-import(error_logger,[error_msg/2]).

-include_lib("kernel/include/net_address.hrl").
-include_lib("kernel/include/dist.hrl").
-include_lib("kernel/include/dist_util.hrl").

-record(proxy_socket, {
    driver :: atom(),
    socket :: term(),
    pid :: pid(),
    initiated = false :: boolean(),

    dhandle = undefined :: any(),
    input_buf = [] :: iodata(),
    node = undefined :: atom() | undefined
}).

%% ------------------------------------------------------------
%%  Enable dist compression (if proto dist is configured).
%% ------------------------------------------------------------

enable() ->
    case inet_tcp_proxy_dist_controller:is_dist_proto_mod_configured() of
        true ->
            {ok, _} = application:ensure_all_started(inet_tcp_proxy_dist),
            true;
        false ->
            false
    end.

%% ------------------------------------------------------------
%%  Select this protocol based on node name
%%  select(Node) => Bool
%% ------------------------------------------------------------

select(Node) ->
    gen_select(inet_tcp, Node).

gen_select(Driver, Node) ->
    case split_node(atom_to_list(Node), $@, []) of
	[_, Host] ->
	    case inet:getaddr(Host, Driver:family()) of
                {ok,_} -> true;
                _ -> false
            end;
	_ -> false
    end.

%% ------------------------------------------------------------
%% Create the listen socket, i.e. the port that this erlang
%% node is accessible through.
%% ------------------------------------------------------------

listen(Name) ->
    gen_listen(inet_tcp, Name).

gen_listen(Driver, Name) ->
    case do_listen(Driver, [{active, false}, {packet,2}, {reuseaddr, true}]) of
	{ok, Socket} ->
	    TcpAddress = get_tcp_address(Driver, Socket),
	    {_,Port} = TcpAddress#net_address.address,
	    ErlEpmd = net_kernel:epmd_module(),
	    case ErlEpmd:register_node(Name, Port, Driver) of
		{ok, Creation} ->
		    {ok, {Socket, TcpAddress, Creation}};
		Error ->
		    Error
	    end;
	Error ->
	    Error
    end.

do_listen(Driver, Options) ->
    {First,Last} = case application:get_env(kernel,inet_dist_listen_min) of
		       {ok,N} when is_integer(N) ->
			   case application:get_env(kernel,
						    inet_dist_listen_max) of
			       {ok,M} when is_integer(M) ->
				   {N,M};
			       _ ->
				   {N,N}
			   end;
		       _ ->
			   {0,0}
		   end,
    do_listen(Driver, First, Last, listen_options([{backlog,128}|Options])).

do_listen(_Driver, First,Last,_) when First > Last ->
    {error,eaddrinuse};
do_listen(Driver, First,Last,Options) ->
    case Driver:listen(First, Options) of
	{error, eaddrinuse} ->
	    do_listen(Driver, First+1,Last,Options);
	Other ->
	    Other
    end.

listen_options(Opts0) ->
    Opts1 =
	case application:get_env(kernel, inet_dist_use_interface) of
	    {ok, Ip} ->
		[{ip, Ip} | Opts0];
	    _ ->
		Opts0
	end,
    case application:get_env(kernel, inet_dist_listen_options) of
	{ok,ListenOpts} ->
	    ListenOpts ++ Opts1;
	_ ->
	    Opts1
    end.


%% ------------------------------------------------------------
%% Accepts new connection attempts from other Erlang nodes.
%% ------------------------------------------------------------

accept(Listen) ->
    gen_accept(inet_tcp, Listen).

gen_accept(Driver, Listen) ->
    spawn_opt(?MODULE, accept_loop, [Driver, self(), Listen], [link, {priority, max}]).

accept_loop(Driver, Kernel, Listen) ->
    case Driver:accept(Listen) of
	{ok, Socket} ->
	    Kernel ! {accept,self(),Socket,Driver:family(),tcp_proxy},
	    _ = controller(Driver, Kernel, Socket),
	    accept_loop(Driver, Kernel, Listen);
	Error ->
	    exit(Error)
    end.

controller(Driver, Kernel, Socket) ->
    receive
	{Kernel, controller, Pid} ->
	    flush_controller(Pid, Socket),
	    Driver:controlling_process(Socket, Pid),
	    flush_controller(Pid, Socket),
	    Pid ! {self(), controller};
	{Kernel, unsupported_protocol} ->
	    exit(unsupported_protocol)
    end.

flush_controller(Pid, Socket) ->
    receive
	{tcp, Socket, Data} ->
	    Pid ! {tcp, Socket, Data},
	    flush_controller(Pid, Socket);
	{tcp_closed, Socket} ->
	    Pid ! {tcp_closed, Socket},
	    flush_controller(Pid, Socket)
    after 0 ->
	    ok
    end.

%% ------------------------------------------------------------
%% Accepts a new connection attempt from another Erlang node.
%% Performs the handshake with the other side.
%% ------------------------------------------------------------

accept_connection(AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    gen_accept_connection(inet_tcp, AcceptPid, Socket, MyNode, Allowed, SetupTime).

gen_accept_connection(Driver, AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    spawn_opt(?MODULE, do_accept,
	      [Driver, self(), AcceptPid, Socket, MyNode, Allowed, SetupTime],
	      [link, {priority, max}]).

do_accept(Driver, Kernel, AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    receive
	{AcceptPid, controller} ->
	    Timer = dist_util:start_timer(SetupTime),
	    case check_ip(Driver, Socket) of
		true ->
		    ProxySocket = #proxy_socket{pid = DistCtrl} =
                    proxy_socket(Driver, Socket, undefined, false),
		    HSData = #hs_data{
		      kernel_pid = Kernel,
		      this_node = MyNode,
		      socket = DistCtrl,
		      timer = Timer,
		      this_flags = 0,
		      allowed = Allowed,
		      f_send = fun(Ctrl, Data) when Ctrl =:= DistCtrl ->
                                       f_send(ProxySocket, Data)
                               end,
		      f_recv = fun(Ctrl, Len, Timeout) when Ctrl =:= DistCtrl ->
                                       f_recv(ProxySocket, Len, Timeout)
                               end,
		      f_setopts_pre_nodeup = 
		      fun(Ctrl) when Ctrl =:= DistCtrl ->
			      inet:setopts(Socket, 
					   [{active, false},
					    {packet, 4},
					    nodelay()])
		      end,
		      f_setopts_post_nodeup = 
		      fun(Ctrl) when Ctrl =:= DistCtrl ->
			      inet:setopts(Socket, 
					   [{active, true},
%					    {deliver, port},
					    {packet, 4},
                                            binary,
					    nodelay()])
		      end,
		      f_getll = fun(Ctrl) when Ctrl =:= DistCtrl ->
					{ok, DistCtrl}
				end,
		      f_address = fun(Ctrl, Node) when Ctrl =:= DistCtrl -> get_remote_id(Driver, Socket, Node) end,
		      mf_tick = fun(Ctrl) when Ctrl =:= DistCtrl -> ?MODULE:tick(Ctrl, Driver, Socket) end,
		      mf_getstat = fun(Ctrl) when Ctrl =:= DistCtrl -> ?MODULE:getstat(Socket) end,
		      mf_setopts = fun(Ctrl, Opts) when Ctrl =:= DistCtrl -> ?MODULE:setopts(Socket, Opts) end,
		      mf_getopts = fun(Ctrl, Opts) when Ctrl =:= DistCtrl -> ?MODULE:getopts(Socket, Opts) end,
		      f_handshake_complete = fun(Ctrl, Node, DHandle) when Ctrl =:= DistCtrl ->
						     handshake_complete(Ctrl, Node, DHandle, ProxySocket)
					     end
		     },
		    dist_util:handshake_other_started(HSData);
		{false,IP} ->
		    error_msg("** Connection attempt from "
			      "disallowed IP ~w ** ~n", [IP]),
		    ?shutdown(no_node)
	    end
    end.

proxy_socket(Driver, Socket, Node, Initiated) ->
    {ok, _} = application:ensure_all_started(inet_tcp_proxy_dist),
    Id = {Node, Initiated, make_ref()},
    {ok, Pid} = supervisor:start_child(inet_tcp_proxy_dist_conn_sup, #{
        id => Id,
        start => {?MODULE, dist_proc_start_link, []},
        restart => temporary
    }),
    %% We link this process to the connection handler we just spawned.
    %% One usecase where this is useful is when both ends try to connect
    %% to each other. In this case, one connection will survive and
    %% the other will exit. The link will take care of exiting the
    %% connection handler process at the same time.
    erlang:link(Pid),
    #proxy_socket{driver = Driver,
                  socket = Socket,
                  pid = Pid,
                  initiated = Initiated}.

handshake_complete(DistCtrl, Node, DHandle, ProxySocket) ->
    #proxy_socket{socket = Socket} = ProxySocket,
    ok = gen_tcp:controlling_process(Socket, DistCtrl),
    DistCtrl ! ProxySocket#proxy_socket{node = Node,
                                        dhandle = DHandle},
    ok.

dist_proc_start_link() ->
    proc_lib:start_link(?MODULE, dist_proc_init, [self()]).

dist_proc_init(Parent) ->
    Debug = sys:debug_options([]),
    Self = self(),
    proc_lib:init_ack(Parent, {ok, Self}),
    receive
        ProxySocket = #proxy_socket{pid = Self, node = Node}
          when Node =/= undefined ->
            Blocked = is_blocked__internal(Node),
            case Blocked of
                false ->
                    logger:debug(
                      ?MODULE_STRING ": connection handler to ~s ready "
                      "(~p)",
                      [Node, Self]),
                    ProxySocket1 = output_dist_data(ProxySocket),
                    dist_proc_loop(ProxySocket1, Parent, Debug);
                true ->
                    logger:debug(
                      ?MODULE_STRING ": connection to ~s blocked; "
                      "handler terminating (~p)",
                      [Node, Self]),
                    exit({shutdown, blocked})
            end
    after 10000 ->
        exit({shutdown, init_timeout})
    end.

dist_proc_loop(#proxy_socket{
                  node = Node,
                  socket = Socket} = ProxySocket,
               Parent,
               Debug) ->
    ProxySocket1 =
    receive
        dist_data ->
            output_dist_data(ProxySocket);
        {tcp, Socket, Data} ->
            input_dist_data(ProxySocket, Data);
        {tcp_closed, Socket} ->
            exit(normal);
        {notify_new_state, allowed} ->
            %% Flush I/O buffers.
            logger:debug(
              ?MODULE_STRING ": Communication with ~s allowed; "
              "flushing I/O buffers (~p)",
              [Node, self()]),
            input_dist_data(
              output_dist_data(ProxySocket),
              []);
        {notify_new_state, _} ->
            ProxySocket;
        {info, From} ->
            send_info(ProxySocket, From),
            ProxySocket;
        {system, From, Request} ->
            sys:handle_system_msg(
              Request, From, Parent, ?MODULE, Debug,
              [ProxySocket]);
        Msg ->
            logger:debug(
              ?MODULE_STRING ": Unhandled message (ignored): ~p", [Msg]),
            ProxySocket
    end,
    dist_proc_loop(ProxySocket1, Parent, Debug).

output_dist_data(#proxy_socket{
                    node = Node,
                    driver = Driver,
                    socket = Socket,
                    dhandle = DHandle} = ProxySocket) ->
    Blocked = is_blocked__internal(Node),
    case Blocked of
        false ->
            case erlang:dist_ctrl_get_data(DHandle) of
                none ->
                    erlang:dist_ctrl_get_data_notification(DHandle),
                    ProxySocket;
                Data ->
                    Driver:send(Socket, Data),
                    output_dist_data(ProxySocket)
            end;
        true ->
            ProxySocket
    end.

input_dist_data(#proxy_socket{
                   node = Node,
                   dhandle = DHandle,
                   input_buf = Buf} = ProxySocket,
                Data) ->
    Blocked = is_blocked__internal(Node),
    case Blocked of
        false ->
            erlang:dist_ctrl_put_data(DHandle, [Buf, Data]),
            ProxySocket#proxy_socket{input_buf = []};
        true ->
            ProxySocket#proxy_socket{input_buf = [Buf, Data]}
    end.

is_blocked__internal(Node) ->
    Blocked = is_blocked__internal1(Node),
    DictKey = {?MODULE, last_block_warning},
    LastWarning = case get(DictKey) of
                      undefined -> allowed;
                      Value     -> Value
                  end,
    case LastWarning of
        allowed when not Blocked ->
            ok;
        blocked when Blocked ->
            ok;
        allowed when Blocked ->
            put(DictKey, blocked),
            logger:debug(
              ?MODULE_STRING ": Communication between ~s and ~s BLOCKED (~p)~n",
              [node(), Node, self()]);
        blocked when not Blocked ->
            put(DictKey, allowed),
            logger:debug(
              ?MODULE_STRING ": Communication between ~s and ~s allowed (~p)~n",
              [node(), Node, self()])
    end,
    Blocked.

is_blocked__internal1(Node) when Node =/= undefined andalso Node =/= node() ->
    is_blocked(Node).

send_info(#proxy_socket{
             node = Node,
             initiated = Initiated},
          Requester) ->
    Info = #{peer => Node,
             blocked => is_blocked__internal1(Node),
             initiated => Initiated},
    Requester ! {info, self(), Info},
    ok.

system_continue(Parent, Debug, [ProxySocket]) ->
    dist_proc_loop(ProxySocket, Parent, Debug).

-spec system_terminate(term(), pid(), [sys:dbg_opt()], #proxy_socket{}) ->
    no_return().

system_terminate(Reason, _Parent, _Debug, _ProxySocket) ->
    %% FIXME: This process is part of a supervision tree. Don't we have
    %% a problem if this process is taken down as part of a supervision
    %% tree termination? Because, depending on the order of process
    %% shutdown, other processes/applications may loose their connection
    %% to a remote node.
    %%
    %% Another chicken and egg issue is: during shutdown, another
    %% process might reopen the connection to a remote node, populating
    %% this supervision tree again.
    %%
    %% Ideas to explore:
    %%   * Swith back to no compression on shutdown, possibly using
    %%     `inet_tcp_dist` if possible; what to do on restart?
    %%   * Store this process PID in a persistent_term and detach it
    %%     from the supervision tree and store. It can reattached on
    %%     restart using that persistent_term.
    exit(Reason).

system_get_state(ProxySocket) ->
    {ok, ProxySocket}.

system_replace_state(StateFun, ProxySocket) ->
    NewProxySocket = StateFun(ProxySocket),
    {ok, ProxySocket, NewProxySocket}.

%% we may not always want the nodelay behaviour
%% for performance reasons

nodelay() ->
    case application:get_env(kernel, dist_nodelay) of
	undefined ->
	    {nodelay, true};
	{ok, true} ->
	    {nodelay, true};
	{ok, false} ->
	    {nodelay, false};
	_ ->
	    {nodelay, true}
    end.


%% ------------------------------------------------------------
%% Get remote information about a Socket.
%% ------------------------------------------------------------
get_remote_id(Driver, Socket, Node) ->
    case inet:peername(Socket) of
	{ok,Address} ->
	    case split_node(atom_to_list(Node), $@, []) of
		[_,Host] ->
		    #net_address{address=Address,host=Host,
				 protocol=tcp_proxy,family=Driver:family()};
		_ ->
		    %% No '@' or more than one '@' in node name.
		    ?shutdown(no_node)
	    end;
	{error, _Reason} ->
	    ?shutdown(no_node)
    end.

%% ------------------------------------------------------------
%% Setup a new connection to another Erlang node.
%% Performs the handshake with the other side.
%% ------------------------------------------------------------

setup(Node, Type, MyNode, LongOrShortNames,SetupTime) ->
    gen_setup(inet_tcp, Node, Type, MyNode, LongOrShortNames, SetupTime).

gen_setup(Driver, Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    spawn_opt(?MODULE, do_setup, 
	      [Driver, self(), Node, Type, MyNode, LongOrShortNames, SetupTime],
	      [link, {priority, max}]).

do_setup(Driver, Kernel, Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    ?trace("~p~n",[{inet_tcp_dist,self(),setup,Node}]),
    Blocked = is_blocked__internal(Node),
    case Blocked of
        false -> ok;
        true  -> ?shutdown(Node)
    end,
    [Name, Address] = splitnode(Driver, Node, LongOrShortNames),
    AddressFamily = Driver:family(),
    ErlEpmd = net_kernel:epmd_module(),
    {ARMod, ARFun} = get_address_resolver(ErlEpmd),
    Timer = dist_util:start_timer(SetupTime),
    case ARMod:ARFun(Name, Address, AddressFamily) of
	{ok, Ip, TcpPort, Version} ->
		?trace("address_please(~p) -> version ~p~n",
			[Node,Version]),
		do_setup_connect(Driver, Kernel, Node, Address, AddressFamily,
		                 Ip, TcpPort, Version, Type, MyNode, Timer);
	{ok, Ip} ->
	    case ErlEpmd:port_please(Name, Ip) of
		{port, TcpPort, Version} ->
		    ?trace("port_please(~p) -> version ~p~n", 
			   [Node,Version]),
			do_setup_connect(Driver, Kernel, Node, Address, AddressFamily,
			                 Ip, TcpPort, Version, Type, MyNode, Timer);
		_ ->
		    ?trace("port_please (~p) "
			   "failed.~n", [Node]),
		    ?shutdown(Node)
	    end;
	_Other ->
	    ?trace("inet_getaddr(~p) "
		   "failed (~p).~n", [Node,_Other]),
	    ?shutdown(Node)
    end.

%%
%% Actual setup of connection
%%
do_setup_connect(Driver, Kernel, Node, Address, AddressFamily,
                 Ip, TcpPort, Version, Type, MyNode, Timer) ->
	dist_util:reset_timer(Timer),
	case
	Driver:connect(
	  Ip, TcpPort,
	  connect_options([{active, false}, {packet, 2}]))
	of
	{ok, Socket} ->
		ProxySocket = #proxy_socket{pid = DistCtrl} =
                proxy_socket(Driver, Socket, Node, true),
		HSData = #hs_data{
		  kernel_pid = Kernel,
		  other_node = Node,
		  this_node = MyNode,
		  socket = DistCtrl,
		  timer = Timer,
		  this_flags = 0,
		  other_version = Version,
		  f_send = fun(Ctrl, Data) when Ctrl =:= DistCtrl ->
                                   f_send(ProxySocket, Data)
                           end,
		  f_recv = fun(Ctrl, Len, Timeout) when Ctrl =:= DistCtrl ->
                                   f_recv(ProxySocket, Len, Timeout)
                           end,
		  f_setopts_pre_nodeup =
		  fun(Ctrl) when Ctrl =:= DistCtrl ->
			  inet:setopts
			(Socket,
			 [{active, false},
			  {packet, 4},
			  nodelay()])
		  end,
		  f_setopts_post_nodeup =
		  fun(Ctrl) when Ctrl =:= DistCtrl ->
			  inet:setopts
			(Socket,
			 [{active, true},
%			  {deliver, port},
			  {packet, 4},
			  binary,
			  nodelay()])
		  end,
		  f_getll = fun(Ctrl) when Ctrl =:= DistCtrl ->
				    {ok, DistCtrl}
			    end,
		  f_address =
		  fun(Ctrl, _RemoteNode) when Ctrl =:= DistCtrl ->
			  #net_address{
		   address = {Ip,TcpPort},
		   host = Address,
		   protocol = tcp_proxy,
		   family = AddressFamily}
		  end,
		  mf_tick = fun(Ctrl) when Ctrl =:= DistCtrl -> ?MODULE:tick(Ctrl, Driver, Socket) end,
		  mf_getstat = fun(Ctrl) when Ctrl =:= DistCtrl -> ?MODULE:getstat(Socket) end,
		  request_type = Type,
		  mf_setopts = fun(Ctrl, Opts) when Ctrl =:= DistCtrl -> ?MODULE:setopts(Socket, Opts) end,
		  mf_getopts = fun(Ctrl, Opts) when Ctrl =:= DistCtrl -> ?MODULE:getopts(Socket, Opts) end,
		  f_handshake_complete = fun(Ctrl, RemoteNode, DHandle) when Ctrl =:= DistCtrl ->
						 handshake_complete(Ctrl, RemoteNode, DHandle, ProxySocket)
					 end
		 },
		dist_util:handshake_we_started(HSData);
	_ ->
		%% Other Node may have closed since
		%% discovery !
		?trace("other node (~p) "
		   "closed since discovery (port_please).~n",
		   [Node]),
		?shutdown(Node)
	end.

connect_options(Opts) ->
    case application:get_env(kernel, inet_dist_connect_options) of
	{ok,ConnectOpts} ->
	    ConnectOpts ++ Opts;
	_ ->
	    Opts
    end.

%%
%% Close a socket.
%%
close(Socket) ->
    inet_tcp:close(Socket).


%% If Node is illegal terminate the connection setup!!
splitnode(Driver, Node, LongOrShortNames) ->
    case split_node(atom_to_list(Node), $@, []) of
	[Name|Tail] when Tail =/= [] ->
	    Host = lists:append(Tail),
	    case split_node(Host, $., []) of
		[_] when LongOrShortNames =:= longnames ->
                    case Driver:parse_address(Host) of
                        {ok, _} ->
                            [Name, Host];
                        _ ->
                            error_msg("** System running to use "
                                      "fully qualified "
                                      "hostnames **~n"
                                      "** Hostname ~ts is illegal **~n",
                                      [Host]),
                            ?shutdown(Node)
                    end;
		L when length(L) > 1, LongOrShortNames =:= shortnames ->
		    error_msg("** System NOT running to use fully qualified "
			      "hostnames **~n"
			      "** Hostname ~ts is illegal **~n",
			      [Host]),
		    ?shutdown(Node);
		_ ->
		    [Name, Host]
	    end;
	[_] ->
	    error_msg("** Nodename ~p illegal, no '@' character **~n",
		      [Node]),
	    ?shutdown(Node);
	_ ->
	    error_msg("** Nodename ~p illegal **~n", [Node]),
	    ?shutdown(Node)
    end.

split_node([Chr|T], Chr, Ack) -> [lists:reverse(Ack)|split_node(T, Chr, [])];
split_node([H|T], Chr, Ack)   -> split_node(T, Chr, [H|Ack]);
split_node([], _, Ack)        -> [lists:reverse(Ack)].

%% ------------------------------------------------------------
%% Fetch local information about a Socket.
%% ------------------------------------------------------------
get_tcp_address(Driver, Socket) ->
    {ok, Address} = inet:sockname(Socket),
    {ok, Host} = inet:gethostname(),
    #net_address {
		  address = Address,
		  host = Host,
		  protocol = tcp_proxy,
		  family = Driver:family()
		 }.

%% ------------------------------------------------------------
%% Determine if EPMD module supports address resolving. Default
%% is to use inet:getaddr/2.
%% ------------------------------------------------------------
get_address_resolver(EpmdModule) ->
    case erlang:function_exported(EpmdModule, address_please, 3) of
        true -> {EpmdModule, address_please};
        _    -> {erl_epmd, address_please}
    end.

%% ------------------------------------------------------------
%% Do only accept new connection attempts from nodes at our
%% own LAN, if the check_ip environment parameter is true.
%% ------------------------------------------------------------
check_ip(Driver, Socket) ->
    case application:get_env(check_ip) of
	{ok, true} ->
	    case get_ifs(Socket) of
		{ok, IFs, IP} ->
		    check_ip(Driver, IFs, IP);
		_ ->
		    ?shutdown(no_node)
	    end;
	_ ->
	    true
    end.

get_ifs(Socket) ->
    case inet:peername(Socket) of
	{ok, {IP, _}} ->
	    case inet:getif(Socket) of
		{ok, IFs} -> {ok, IFs, IP};
		Error     -> Error
	    end;
	Error ->
	    Error
    end.

check_ip(Driver, [{OwnIP, _, Netmask}|IFs], PeerIP) ->
    case {Driver:mask(Netmask, PeerIP), Driver:mask(Netmask, OwnIP)} of
	{M, M} -> true;
	_      -> check_ip(Driver, IFs, PeerIP)
    end;
check_ip(_Driver, [], PeerIP) ->
    {false, PeerIP}.
    
is_node_name(Node) when is_atom(Node) ->
    case split_node(atom_to_list(Node), $@, []) of
	[_, _Host] -> true;
	_ -> false
    end;
is_node_name(_Node) ->
    false.

tick(DistCtrl, Driver, Socket) ->
    DictKey = {?MODULE, peer},
    Peer = case get(DictKey) of
               undefined ->
                   DistCtrl ! {info, self()},
                   Info = receive {info, DistCtrl, I} -> I end,
                   case Info of
                       #{peer := P} ->
                           put(DictKey, P),
                           P;
                       _ ->
                           undefined
                   end;
               P ->
                   P
           end,
    Blocked = case Peer of
                  undefined -> false;
                  _         -> is_blocked__internal(Peer)
              end,
    case Blocked of
        false ->
            case Driver:send(Socket, [], [force]) of
                {error, closed} ->
                    self() ! {tcp_closed, Socket},
                    {error, closed};
                R ->
                    R
            end;
        true ->
            ok
    end.

getstat(Socket) ->
    case inet:getstat(Socket, [recv_cnt, send_cnt, send_pend]) of
	{ok, Stat} ->
	    split_stat(Stat,0,0,0);
	Error ->
	    Error
    end.

split_stat([{recv_cnt, R}|Stat], _, W, P) ->
    split_stat(Stat, R, W, P);
split_stat([{send_cnt, W}|Stat], R, _, P) ->
    split_stat(Stat, R, W, P);
split_stat([{send_pend, P}|Stat], R, W, _) ->
    split_stat(Stat, R, W, P);
split_stat([], R, W, P) ->
    {ok, R, W, P}.


setopts(S, Opts) ->
    case [Opt || {K,_}=Opt <- Opts,
		 K =:= active orelse K =:= deliver orelse K =:= packet] of
	[] -> inet:setopts(S,Opts);
	Opts1 -> {error, {badopts,Opts1}}
    end.

getopts(S, Opts) ->
    inet:getopts(S, Opts).

f_send(#proxy_socket{
          driver = Driver,
          socket = S},
       Data) ->
    Driver:send(S, Data).

f_recv(#proxy_socket{
          driver = Driver,
          socket = S},
       Length,
       Timeout) ->
    Driver:recv(S, Length, Timeout).

%% ------------------------------------------------------------
%% Public API to manage allowed/blocked peers.
%% ------------------------------------------------------------

allow(Peer) -> inet_tcp_proxy_dist_controller:allow(Peer).
block(Peer) -> inet_tcp_proxy_dist_controller:block(Peer).
is_blocked(Peer) -> inet_tcp_proxy_dist_controller:is_blocked(Peer).
info() -> inet_tcp_proxy_dist_controller:info().

notify_new_state(DistPid, Blocked) ->
    DistPid ! {notify_new_state, Blocked},
    ok.

dbg(ProxySocket) ->
    dbg:tracer(),
    dbg:p(self(), [c, m]),
    dbg:tpl(?MODULE, cx),
    dbg:tpl(erlang, dist_ctrl_get_data, cx),
    dbg:tpl(erlang, dist_ctrl_put_data, cx),
    dbg:tpl(erlang, dist_ctrl_get_data_notification, cx),
    dbg:tpl(ProxySocket#proxy_socket.driver, send, cx).
