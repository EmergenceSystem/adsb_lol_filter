%%%-------------------------------------------------------------------
%%% @doc ADS-B Aircraft Data Agent using the adsb.lol API.
%%%
%%% Deduplication by URL is handled upstream by the Emquest pipeline.
%%%
%%% === Capability cascade ===
%%%
%%%   base_capabilities/0 extends em_filter:base_capabilities().
%%%
%%% Handler contract: handle/2 (Body, Memory) -> {RawList, Memory}.
%%% @end
%%%-------------------------------------------------------------------
-module(adsb_lol_filter_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([handle/2, base_capabilities/0]).

-define(BASE_URL,    "https://api.adsb.lol/v2/").
-define(MAX_RESULTS, 100).
-define(MAX_RADIUS,  250).

%%====================================================================
%% Capability cascade
%%====================================================================

-spec base_capabilities() -> [binary()].
base_capabilities() ->
    em_filter:base_capabilities() ++ [<<"adsb">>, <<"aircraft">>,
                                      <<"realtime">>, <<"aviation">>,
                                      <<"tracking">>].

%%====================================================================
%% Application behaviour
%%====================================================================

start(_Type, _Args) ->
    em_filter:start_agent(adsb_lol_filter, ?MODULE, #{
        capabilities => base_capabilities()
    }),
    {ok, self()}.

stop(_State) ->
    em_filter:stop_agent(adsb_lol_filter).

%%====================================================================
%% Agent handler
%%====================================================================

handle(Body, Memory) when is_binary(Body) ->
    {generate_embryo_list(normalize_body(Body)), Memory};
handle(_, Memory) ->
    {[], Memory}.

%%====================================================================
%% Normalize body
%%====================================================================

normalize_body(Body) ->
    case catch json:decode(Body) of
        Map when is_map(Map) ->
            case maps:get(<<"value">>, Map, undefined) of
                undefined -> wrap_value(Body);
                _         -> Body
            end;
        _ ->
            wrap_value(Body)
    end.

wrap_value(Body) ->
    list_to_binary(io_lib:format("{\"value\":\"~s\"}", [binary_to_list(Body)])).

%%====================================================================
%% Generate embryo list
%%====================================================================

generate_embryo_list(JsonBinary) ->
    case catch json:decode(JsonBinary) of
        Map when is_map(Map) ->
            Value     = binary_to_list(maps:get(<<"value">>, Map, <<>>)),
            RawType   = binary_to_list(maps:get(<<"query_type">>, Map, <<"auto">>)),
            QueryType = case RawType of
                "auto" -> detect_query_type(Value);
                Other  -> Other
            end,
            fetch_by_type(QueryType, Value, Map);
        _ -> []
    end.

detect_query_type(Value) ->
    case string:len(Value) of
        6 ->
            case is_hex(Value) of
                true  -> "icao";
                false -> "callsign"
            end;
        _ -> "callsign"
    end.

is_hex(Str) ->
    lists:all(fun(C) ->
        (C >= $0 andalso C =< $9) orelse
        (C >= $A andalso C =< $F) orelse
        (C >= $a andalso C =< $f)
    end, Str).

fetch_by_type("icao",         Value, _) -> fetch_aircraft(fmt("icao/~s",         [Value]));
fetch_by_type("callsign",     Value, _) -> fetch_aircraft(fmt("callsign/~s",     [Value]));
fetch_by_type("registration", Value, _) -> fetch_aircraft(fmt("registration/~s", [Value]));
fetch_by_type("type",         Value, _) -> fetch_aircraft(fmt("type/~s",         [Value]));
fetch_by_type("point",   _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_aircraft(fmt("point/~s/~s/~s",
        [binary_to_list(Lat), binary_to_list(Lon), limit_radius(R)]));
fetch_by_type("closest", _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_aircraft(fmt("closest/~s/~s/~s",
        [binary_to_list(Lat), binary_to_list(Lon), limit_radius(R)]));
fetch_by_type(_, _, _) -> [].

limit_radius(R) ->
    case catch list_to_integer(R) of
        {'EXIT', _}                    -> integer_to_list(?MAX_RADIUS);
        Int when Int > ?MAX_RADIUS     -> integer_to_list(?MAX_RADIUS);
        Int when Int < 0               -> "0";
        Int                            -> integer_to_list(Int)
    end.

fetch_aircraft(Path) ->
    Url = ?BASE_URL ++ Path,
    case httpc:request(get, {Url, []}, [], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} -> parse_aircraft_data(Body);
        _                            -> []
    end.

parse_aircraft_data(JsonBinary) ->
    case catch json:decode(JsonBinary) of
        #{<<"ac">> := AircraftList} when is_list(AircraftList) ->
            Valid = [A || A <- AircraftList, is_valid_aircraft(A)],
            build_embryos(Valid, 1, []);
        _ -> []
    end.

is_valid_aircraft(A) when is_map(A) ->
    has_data(A, <<"hex">>) andalso has_data(A, <<"lat">>) andalso has_data(A, <<"lon">>);
is_valid_aircraft(_) -> false.

has_data(Map, Key) ->
    maps:is_key(Key, Map) andalso maps:get(Key, Map) =/= null.

build_embryos([], _I, Acc) -> lists:reverse(Acc);
build_embryos([H | T], I, Acc) ->
    build_embryos(T, I + 1, [make_embryo(H, I) | Acc]).

make_embryo(A, I) ->
    Hex   = maps:get(<<"hex">>,    A),
    Call  = maps:get(<<"flight">>, A, <<"">>),
    Reg   = maps:get(<<"r">>,      A, <<"">>),
    Alt   = maps:get(<<"alt_baro">>, A, null),
    GS    = maps:get(<<"gs">>,     A, null),
    Track = maps:get(<<"track">>,  A, null),
    Url   = list_to_binary(fmt("https://adsb.lol/?icao=~s", [binary_to_list(Hex)])),
    #{
        <<"properties">> => #{
            <<"url">>           => Url,
            <<"hex">>           => Hex,
            <<"flight">>        => Call,
            <<"registration">>  => Reg,
            <<"altitude_baro">> => format_alt(Alt),
            <<"ground_speed">>  => format_speed(GS),
            <<"track">>         => format_heading(Track),
            <<"index">>         => I
        }
    }.

format_alt(null)   -> <<"N/A">>;
format_alt(X)      -> list_to_binary(fmt("~p ft",  [X])).
format_speed(null) -> <<"N/A">>;
format_speed(X)    -> list_to_binary(fmt("~p kts", [X])).
format_heading(null) -> <<"N/A">>;
format_heading(X)    -> list_to_binary(fmt("~p deg", [X])).

fmt(Fmt, Args) -> lists:flatten(io_lib:format(Fmt, Args)).
