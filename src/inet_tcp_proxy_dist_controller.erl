%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2018-2020 VMware, Inc. or its affiliates.  All rights reserved.
%%
-module(inet_tcp_proxy_dist_controller).

-export([allow/1,
         block/1,
         is_blocked/1,
         is_dist_proto_mod_configured/0,
         is_inet_tcp_dist_proxy_conn_sup_ready/0,
         is_proxy_dist_fully_configured/0,
         connection_states/0,
         info/0]).

-define(PT_BLOCKED_PAIR(NodeA, NodeB), {?MODULE, blocked_pair, NodeA, NodeB}).

%% -------------------------------------------------------------------
%% Public API.
%% -------------------------------------------------------------------

allow(Peer) when Peer =:= node() ->
    ok;
allow(Peer) when Peer =/= undefined ->
    case is_dist_proto_mod_configured() of
        true ->
            logger:debug(
              ?MODULE_STRING ": Allowing connection between ~s and ~s",
              [node(), Peer]),
            Erased = persistent_term:erase(pt_blocked_pair(node(), Peer)),
            case Erased of
                true  -> notify_new_state(Peer, allowed);
                false -> ok
            end;
        false ->
            ok
    end,
    ok.

block(Peer) when Peer =:= node() ->
    ok;
block(Peer) when Peer =/= undefined ->
    case is_dist_proto_mod_configured() of
        true ->
            logger:debug(
              ?MODULE_STRING ": BLOCKING connection between ~s and ~s",
              [node(), Peer]),
            persistent_term:put(pt_blocked_pair(node(), Peer), true),
            notify_new_state(Peer, blocked);
        false ->
            ok
    end,
    ok.

is_blocked(Peer) when Peer =:= node() ->
    false;
is_blocked(Peer) when Peer =/= undefined ->
    persistent_term:get(pt_blocked_pair(node(), Peer), false).

pt_blocked_pair(NodeA, NodeB) when NodeB < NodeA ->
    ?PT_BLOCKED_PAIR(NodeB, NodeA);
pt_blocked_pair(NodeA, NodeB) ->
    ?PT_BLOCKED_PAIR(NodeA, NodeB).

notify_new_state(Node, State) ->
    case get_dist_proc_for_node(Node) of
        undefined ->
            ok;
        DistPid ->
            logger:debug(
              ?MODULE_STRING ": Notify dist process ~p about new state ~p",
              [DistPid, State]),
            inet_tcp_proxy_dist:notify_new_state(DistPid, State)
    end.

get_proto_dist_module() ->
    case init:get_argument(proto_dist) of
        {ok, [[ModStr]]} -> ModStr;
        _                -> "inet_tcp"
    end.

is_dist_proto_mod_configured() ->
    "inet_tcp_proxy" =:= get_proto_dist_module().

is_inet_tcp_dist_proxy_conn_sup_ready() ->
    is_pid(erlang:whereis(inet_tcp_proxy_dist_conn_sup)).

is_proxy_dist_fully_configured() ->
    is_dist_proto_mod_configured()
    andalso
    is_inet_tcp_dist_proxy_conn_sup_ready().

connection_states() ->
    DistProcs = get_dist_procs(),
    [get_dist_proc_info(Pid) || Pid <- DistProcs].

info() ->
    Ready = {is_dist_proto_mod_configured(),
             is_inet_tcp_dist_proxy_conn_sup_ready()},
    case Ready of
        {true, true} ->
            States = connection_states(),
            UseColors = case os:getenv("TERM") of
                            false -> false;
                            ""    -> false;
                            _     -> true
                        end,
            display_info(States, UseColors);
        {false, _} ->
            io:format(
              "Dist proxy unavailable: dist proto module set to `~s` "
              "(instead of `inet_tcp_proxy`)~n",
              [get_proto_dist_module()]);
        {_, false} ->
            io:format(
              "Dist proxy unavailable: `inet_tcp_proxy_dist` "
              "application not started~n")
    end,
    ok.

display_info(States, UseColors) ->
    {TitleColor,
     BlockedColor,
     ColorReset,
     LineStart,
     LineChar,
     LineReset} = case UseColors of
                      true ->
                          {"\033[1m",
                           "\033[31m",
                           "\033[0m",
                           "\033(0",
                           "q",
                           "\033(B"};
                      false ->
                          {"",
                           "",
                           "",
                           "",
                           "-",
                           ""}
                  end,
    io:format(
      "~n"
      "~sErlang distribution connections between ~s and peer nodes:~s~n"
      "[*] node which initiated the connection~n",
      [TitleColor, node(), ColorReset]),
    This = node(),
    %% Displays something like:
    %%   *rabbit@rmq1* <---[ none ]--->  rabbit@rmq0
    %%    rabbit@rmq1  <---[ zstd ]---> *rabbit@rmq2*
    %%    rabbit@rmq1  <---[ lz4  ]---> *rabbit@rmq3*
    lists:foreach(
      fun
          (#{peer := Remote, blocked := false, initiated := true}) ->
              io:format(
                "  *~s* "
                "~s<~s~9.." ++ LineChar ++ "s~s>~s"
                "  ~s~n",
                [This, "", LineStart, "", LineReset,
                 ColorReset, Remote]);
          (#{peer := Remote, blocked := true, initiated := true}) ->
              io:format(
                "  *~s* "
                "~s<~s~3.." ++ LineChar ++ "s~s X ~s~3.." ++ LineChar ++ "s~s>~s"
                "  ~s~n",
                [This, BlockedColor, LineStart, "", LineReset,
                 LineStart, "", LineReset,
                 ColorReset, Remote]);
          (#{peer := Remote, blocked := false, initiated := false}) ->
              io:format(
                "   ~s  "
                "~s<~s~9.." ++ LineChar ++ "s~s>~s"
                " *~s*~n",
                [This, "", LineStart, "", LineReset,
                 ColorReset, Remote]);
          (#{peer := Remote, blocked := true, initiated := false}) ->
              io:format(
                "   ~s  "
                "~s<~s~3.." ++ LineChar ++ "s~s X ~s~3.." ++ LineChar ++ "s~s>~s"
                " *~s*~n",
                [This, BlockedColor, LineStart, "", LineReset,
                 LineStart, "", LineReset,
                 ColorReset, Remote])
      end, States),

    io:format("~n", []).

%% -------------------------------------------------------------------
%% Internal helpers.
%% -------------------------------------------------------------------

conn_sup_children() ->
    supervisor:which_children(inet_tcp_proxy_dist_conn_sup).

get_dist_procs() ->
    [Pid || {_, Pid, _, _} <- conn_sup_children()].

get_dist_proc_for_node(Node) ->
    get_dist_proc_for_node(conn_sup_children(), Node).

get_dist_proc_for_node([{{Node, _, _}, Child, _Type, _Modules} | _],
                       Node) ->
    Child;
get_dist_proc_for_node([{{undefined, _, _}, Child, _Type, _Modules} | Rest],
                       Node) ->
     case get_dist_proc_info(Child, infinity) of
         #{peer := Node} -> Child;
         _               -> get_dist_proc_for_node(Rest, Node)
     end;
get_dist_proc_for_node([{_Id, _Child, _Type, _Modules} | Rest],
                       Node) ->
    get_dist_proc_for_node(Rest, Node);
get_dist_proc_for_node([], _) ->
    undefined.

get_dist_proc_info(Pid) ->
    get_dist_proc_info(Pid, 5000).

get_dist_proc_info(Pid, Timeout) ->
    Pid ! {info, self()},
    receive
        {info, Pid, Info} -> Info
    after Timeout         -> undefined
    end.
