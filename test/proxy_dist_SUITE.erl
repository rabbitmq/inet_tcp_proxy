-module(proxy_dist_SUITE).

-export([suite/0,
         all/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2,

         two_nodes_with_default_dist/0,
         two_nodes_with_default_dist/1,
         two_nodes_with_proxy_dist/0,
         two_nodes_with_proxy_dist/1,
         proxy_node_connects_to_default_node/0,
         proxy_node_connects_to_default_node/1,
         default_node_connects_to_proxy_node/0,
         default_node_connects_to_proxy_node/1,
         app_is_started_but_proto_dist_is_unconfigured/0,
         app_is_started_but_proto_dist_is_unconfigured/1,
         proto_dist_is_configured_but_app_is_stopped/0,
         proto_dist_is_configured_but_app_is_stopped/1,
         send_large_message/0,
         send_large_message/1,
         three_nodes_with_proxy_on_two_only/0,
         three_nodes_with_proxy_on_two_only/1,
         asymmetrical_block_works/0,
         asymmetrical_block_works/1,

         test_basic_communication/2,
         asymmetrical_block_works/2
        ]).

-import(proxy_dist_test_lib,
        [send_to_tstcntrl/1,
         apply_on_test_node/2,
         stop_test_node/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("proxy_dist_test_lib.hrl").

%% -------------------------------------------------------------------
%% common_test callbacks.
%% -------------------------------------------------------------------

suite() ->
    [{timetrap, {minutes, 10}}].

all() ->
    [{group, non_parallel_tests}].

groups() ->
    [
     {non_parallel_tests, [],
      [two_nodes_with_default_dist,
       two_nodes_with_proxy_dist,
       proxy_node_connects_to_default_node,
       default_node_connects_to_proxy_node,
       app_is_started_but_proto_dist_is_unconfigured,
       proto_dist_is_configured_but_app_is_stopped,
       send_large_message,
       three_nodes_with_proxy_on_two_only,
       asymmetrical_block_works]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(Testcase, Config) ->
    NodeConfigs = node_configs_for_testcase(Testcase),
    Config1 = case Testcase of
                  send_large_message ->
                      [{message_size, 20 * 1024 * 1024} | Config];
                  _ ->
                      Config
              end,
    [{testcase, Testcase}, {node_configs, NodeConfigs} | Config1].

node_configs_for_testcase(two_nodes_with_default_dist) ->
    [#{proto_dist => default,
       expect_proxy_enabled => false},
     #{proto_dist => default,
       expect_proxy_enabled => false}];
node_configs_for_testcase(proxy_node_connects_to_default_node) ->
    [#{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true},
     #{proto_dist => default}];
node_configs_for_testcase(default_node_connects_to_proxy_node) ->
    [#{proto_dist => default,
       expect_proxy_enabled => false},
     #{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true}];
node_configs_for_testcase(app_is_started_but_proto_dist_is_unconfigured) ->
    [#{proto_dist => default,
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => false},
     #{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true}];
node_configs_for_testcase(proto_dist_is_configured_but_app_is_stopped) ->
    [#{proto_dist => "inet_tcp_proxy",
       start_apps => [],
       expect_proxy_enabled => false},
     #{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true}];
node_configs_for_testcase(three_nodes_with_proxy_on_two_only) ->
    [#{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true},
     #{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true},
     #{proto_dist => default,
       expect_proxy_enabled => false}];
node_configs_for_testcase(_) ->
    [#{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true},
     #{proto_dist => "inet_tcp_proxy",
       start_apps => [inet_tcp_proxy_dist],
       expect_proxy_enabled => true}].

end_per_testcase(_Testcase, _Config) ->
    ok.

%% -------------------------------------------------------------------
%% Testcases.
%% -------------------------------------------------------------------

two_nodes_with_default_dist() ->
    [{doc,
      "Verify that default dist works before we test "
      "inet_tcp_proxy_dist"}].
two_nodes_with_default_dist(Config) ->
    gen_dist_test(test_basic_communication, Config).

two_nodes_with_proxy_dist() ->
    [{doc,
      "Verify that default dist works before we test "
      "inet_tcp_proxy_dist"}].
two_nodes_with_proxy_dist(Config) ->
    gen_dist_test(test_basic_communication, Config).

proxy_node_connects_to_default_node() ->
    [{doc,
      "Verify a proxy-dist node can connect to a default-dist node"}].
proxy_node_connects_to_default_node(Config) ->
    gen_dist_test(test_basic_communication, Config).

default_node_connects_to_proxy_node() ->
    [{doc,
      "Verify a default-dist node can connect to a proxy-dist node"}].
default_node_connects_to_proxy_node(Config) ->
    gen_dist_test(test_basic_communication, Config),
    Config1 = rotate_nodes_in_config(Config),
    gen_dist_test(test_basic_communication, Config1).

app_is_started_but_proto_dist_is_unconfigured() ->
    [{doc,
      "Verify that a node without the proto dist behaves as a default node"}].
app_is_started_but_proto_dist_is_unconfigured(Config) ->
    gen_dist_test(test_basic_communication, Config),
    Config1 = rotate_nodes_in_config(Config),
    gen_dist_test(test_basic_communication, Config1).

proto_dist_is_configured_but_app_is_stopped() ->
    [{doc,
      "Verify that a node without the proto dist behaves as a default node"}].
proto_dist_is_configured_but_app_is_stopped(Config) ->
    gen_dist_test(test_basic_communication, Config),
    Config1 = rotate_nodes_in_config(Config),
    gen_dist_test(test_basic_communication, Config1),
    Config2 = rotate_nodes_in_config(Config1),
    gen_dist_test(test_basic_communication, Config2).

send_large_message() ->
    [{doc,
      "Verify that we can send larger amount of data"}].
send_large_message(Config) ->
    gen_dist_test(test_basic_communication, Config).

three_nodes_with_proxy_on_two_only() ->
    [{doc,
      "Verify that a cluster of three nodes with inconsistent node "
      "configurations (i.e. a mix of default and proxy)"}].
three_nodes_with_proxy_on_two_only(Config) ->
    gen_dist_test(test_basic_communication, Config).

test_basic_communication(Config, NHs) ->
    Nodes = lists:sort([NH#node_handle.nodename || NH <- NHs]),

    %% Start applications (e.g. inet_tcp_proxy_dist) & check
    %% proxy status if requested.
    [begin
         apply_on_test_node(
           NH,
           fun() ->
                   case NodeConfig of
                       #{start_apps := Apps}
                         when Apps =/= [] ->
                           [{ok, _} = application:ensure_all_started(App)
                            || App <- Apps];
                       _ ->
                           ok
                   end,
                   case NodeConfig of
                       #{expect_proxy_enabled := State} ->
                           ?assertEqual(
                              State,
                              inet_tcp_proxy_dist_neg:
                              is_proxy_dist_fully_configured());
                       _ ->
                           ok
                   end
           end)
     end
     || #node_handle{priv = NodeConfig} = NH <- NHs],

    %% Block communication, then from each node, ping all other nodes to
    %% try establish the connection.
    block(NHs),
    [begin
         This = NH#node_handle.nodename,
         Others = Nodes -- [This],
         ct:pal(
           ?LOW_IMPORTANCE,
           "Ping other nodes from ~s --> ~p",
           [This, Others]),
         true = apply_on_test_node(
                  NH,
                  fun() ->
                          lists:all(
                            fun(Node) -> pang =:= net_adm:ping(Node) end,
                            Others)
                  end)
     end
     || #node_handle{priv = #{expect_proxy_enabled := true}} = NH <- NHs],

    %% From each node, verify that one node knows no other node.
    [begin
         This = NH#node_handle.nodename,
         ct:pal(
           ?LOW_IMPORTANCE,
           "Check nodes known to ~s",
           [This]),
         true = apply_on_test_node(
                  NH,
                  fun() ->
                          [] =:= nodes()
                  end)
     end
     || #node_handle{priv = #{expect_proxy_enabled := true}} = NH <- NHs],

    %% Allow communication, then from each node, ping all other nodes to
    %% establish the connection.
    allow(NHs),
    [begin
         This = NH#node_handle.nodename,
         Others = Nodes -- [This],
         ct:pal(
           ?LOW_IMPORTANCE,
           "Ping other nodes from ~s --> ~p",
           [This, Others]),
         true = apply_on_test_node(
                  NH,
                  fun() ->
                          lists:all(
                            fun(Node) -> pong =:= net_adm:ping(Node) end,
                            Others)
                  end)
     end
     || NH <- NHs],

    %% From each node, verify that one node knows about the others.
    [begin
         This = NH#node_handle.nodename,
         Others = Nodes -- [This],
         ct:pal(
           ?LOW_IMPORTANCE,
           "Check nodes known to ~s",
           [This]),
         true = apply_on_test_node(
                  NH,
                  fun() -> Others =:= lists:sort(nodes()) end)
     end
     || NH <- NHs],

    %% Block communication (after the connections were established),
    %% then from each node, try to send a message to all other nodes and
    %% verify it times out.
    block(NHs),
    Ref1 = make_ref(),
    Bytes = proplists:get_value(message_size, Config, 100000),
    [begin
         %% Spawn a process on all other nodes to wait for a message
         %% from this node.
         OtherNHs = NHs -- [NH],
         [spawn(fun() ->
                        apply_on_test_node(
                          OtherNH,
                          fun() ->
                                  send_to_tstcntrl({Ref1, self()}),
                                  receive
                                      {From, Msg} -> From ! {self(), Msg}
                                  end
                          end)
                end)
          || OtherNH <- OtherNHs],

         %% Get PIDs from other nodes and send them a message.
         This = NH#node_handle.nodename,
         Pids = [receive {Ref1, Pid} -> Pid end || _ <- OtherNHs],
         [begin
              ct:pal(
                ?LOW_IMPORTANCE,
                "Send message from ~s to ~s",
                [This, node(Pid)]),
              ok = apply_on_test_node(
                     NH,
                     fun() ->
                             Msg = crypto:strong_rand_bytes(Bytes),
                             Pid ! {self(), Msg},
                             receive
                                 {Pid, Msg} ->
                                     unexpected_success
                             after 2000 ->
                                       ok
                             end
                     end)
          end
          || Pid <- Pids]
     end
     || #node_handle{priv = #{expect_proxy_enabled := true}} = NH <- NHs],

    %% Allow communication, then from each node, send a message to all
    %% other nodes.
    allow(NHs),
    Ref2 = make_ref(),
    Bytes = proplists:get_value(message_size, Config, 100000),
    [begin
         %% Spawn a process on all other nodes to wait for a message
         %% from this node.
         OtherNHs = NHs -- [NH],
         [spawn(fun() ->
                        apply_on_test_node(
                          OtherNH,
                          fun() ->
                                  send_to_tstcntrl({Ref2, self()}),
                                  receive
                                      {From, Msg} -> From ! {self(), Msg}
                                  end
                          end)
                end)
          || OtherNH <- OtherNHs],

         %% Get PIDs from other nodes and send them a message.
         This = NH#node_handle.nodename,
         Pids = [receive {Ref2, Pid} -> Pid end || _ <- OtherNHs],
         [begin
              ct:pal(
                ?LOW_IMPORTANCE,
                "Send message from ~s to ~s",
                [This, node(Pid)]),
              ok = apply_on_test_node(
                     NH,
                     fun() ->
                             Msg = crypto:strong_rand_bytes(Bytes),
                             Pid ! {self(), Msg},
                             receive {Pid, Msg} -> ok end
                     end)
          end
          || Pid <- Pids]
     end
     || NH <- NHs].

asymmetrical_block_works() ->
    [{doc,
      "Verify that blocking one direction does not interfere with the "
      "communication in the opposite direction"}].
asymmetrical_block_works(Config) ->
    gen_dist_test(asymmetrical_block_works, Config).

asymmetrical_block_works(
  _Config,
  [#node_handle{nodename = N1} = NH1,
   #node_handle{nodename = N2} = NH2]) ->
    PingN1 = fun() -> net_adm:ping(N1) end,
    PingN2 = fun() -> net_adm:ping(N2) end,

    %% Establishing the connection is not possible because it involves
    %% bidirectional communication.
    block(NH1, [N2]),
    ?assertEqual(pang, apply_on_test_node(NH1, PingN2)),
    ?assertEqual(pang, apply_on_test_node(NH2, PingN1)),

    %% Establishing the connection is now possible.
    allow(NH1, [N2]),
    ?assertEqual(pong, apply_on_test_node(NH2, PingN1)),
    ?assertEqual(pong, apply_on_test_node(NH1, PingN2)),

    Ref1 = make_ref(),
    Ref2 = make_ref(),
    ForwardMsg = fun(Ref) ->
                         fun() ->
                                 send_to_tstcntrl({Ref, self()}),
                                 receive Msg1 -> send_to_tstcntrl(Msg1) end,
                                 receive Msg2 -> send_to_tstcntrl(Msg2) end
                         end
                 end,
    spawn(fun() -> apply_on_test_node(NH1, ForwardMsg(Ref1)) end),
    spawn(fun() -> apply_on_test_node(NH2, ForwardMsg(Ref2)) end),
    Pid1 = receive {Ref1, P1} -> P1 end,
    Pid2 = receive {Ref2, P2} -> P2 end,

    SendMsg = fun(Pid, Msg) ->
                      fun() ->
                              inet_tcp_proxy_dist_controller:info(),
                              Pid ! Msg
                      end
              end,
    Msg1 = {Ref1, take1},
    Msg2 = {Ref2, take1},
    apply_on_test_node(NH1, SendMsg(Pid2, Msg1)),
    apply_on_test_node(NH2, SendMsg(Pid1, Msg2)),

    receive Msg1 -> ok end,
    receive Msg2 -> ok end,

    block(NH1, [N2]),
    Msg3 = {Ref1, take2},
    Msg4 = {Ref2, take2},
    apply_on_test_node(NH1, SendMsg(Pid2, Msg3)),
    apply_on_test_node(NH2, SendMsg(Pid1, Msg4)),

    ?assertEqual(
       ok,
       receive Msg3 -> msg_received_unexpectedly after 5000 -> ok end),
    ?assertEqual(
       ok,
       receive Msg4 -> ok after 5000 -> msg_not_received_before_timeout end),

    ok.

%% -------------------------------------------------------------------
%% Helpers.
%% -------------------------------------------------------------------

gen_dist_test(Test, Config) ->
    NodeConfigs = proplists:get_value(node_configs, Config, []),

    NHs = [begin
               NH0 = start_test_node(Config, NodeConfig),
               NH0#node_handle{priv = NodeConfig}
           end
           || NodeConfig <- NodeConfigs],
    try
        ?MODULE:Test(Config, NHs)
    catch
        _:Reason:Stacktrace ->
            [stop_test_node(NH) || NH <- NHs],
            ct:fail({Reason, Stacktrace})
    end,
    [stop_test_node(NH) || NH <- NHs],
    ok.

start_test_node(Config, NodeConfig) ->
    Nodename = make_test_nodename(Config),
    DistProto = maps:get(proto_dist, NodeConfig, default),
    Args0 = "-kernel logger_level debug",
    Args1 = case DistProto of
                default -> Args0;
                _       -> Args0 ++ " -proto_dist " ++ DistProto
            end,
    proxy_dist_test_lib:start_test_node(Nodename, Args1).

make_test_nodename(Config) ->
    N = erlang:unique_integer([positive]),
    Case = proplists:get_value(testcase, Config),
    atom_to_list(?MODULE)
    ++ "_"
    ++ atom_to_list(Case)
    ++ "_"
    ++ integer_to_list(N).

rotate_nodes_in_config(Config) ->
    [Head | Tail] = proplists:get_value(node_configs, Config),
    NodeConfigs = Tail ++ [Head],
    lists:keystore(node_configs, 1, Config, {node_configs, NodeConfigs}).

allow(NHs) -> maybe_allow(NHs, true).
block(NHs) -> maybe_allow(NHs, false).

maybe_allow(NHs, Allowed) ->
    Nodes = lists:sort([NH#node_handle.nodename || NH <- NHs]),

    [begin
         This = NH#node_handle.nodename,
         Others = Nodes -- [This],
         case Allowed of
             true  -> allow(NH, Others);
             false -> block(NH, Others)
         end
     end
     || NH <- NHs].

allow(#node_handle{nodename = This} = NH, Peers) ->
    ct:pal(
      ?LOW_IMPORTANCE,
      "Allowing communication: ~s --> ~p",
      [This, Peers]),
    apply_on_test_node(
      NH,
      fun() ->
              lists:foreach(
                fun(Node) -> inet_tcp_proxy_dist:allow(Node) end,
                Peers)
      end).

block(#node_handle{nodename = This} = NH, Peers) ->
    ct:pal(
      ?LOW_IMPORTANCE,
      "BLOCKING communication: ~s --> ~p",
      [This, Peers]),
    apply_on_test_node(
      NH,
      fun() ->
              lists:foreach(
                fun(Node) ->
                        inet_tcp_proxy_dist:block(Node)
                end,
                Peers)
      end).
