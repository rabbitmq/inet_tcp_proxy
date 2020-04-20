-module(inet_tcp_proxy_dist_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_Type, _Args) ->
	inet_tcp_proxy_dist_sup:start_link().

stop(_State) ->
	ok.
