%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2018-2020 VMware, Inc. or its affiliates.  All rights reserved.
%%
-module(inet_tcp_proxy_dist_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
	Procs = [#{id => inet_tcp_proxy_dist_conn_sup,
                   start => {inet_tcp_proxy_dist_conn_sup, start_link, []},
                   type => supervisor}
                ],
	{ok, {{one_for_one, 1, 5}, Procs}}.
