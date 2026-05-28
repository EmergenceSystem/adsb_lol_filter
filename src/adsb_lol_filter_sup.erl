%%%-------------------------------------------------------------------
%%% @doc adsb_lol_filter supervisor.
%%%
%%% Supervises the adsb_lol_filter_server gen_server.
%%% @end
%%%-------------------------------------------------------------------
-module(adsb_lol_filter_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    ServerSpec = #{
        id      => adsb_lol_filter_server,
        start   => {adsb_lol_filter_server, start_link, []},
        restart => permanent,
        type    => worker
    },
    {ok, {#{strategy => one_for_one, intensity => 3, period => 10},
          [ServerSpec]}}.
