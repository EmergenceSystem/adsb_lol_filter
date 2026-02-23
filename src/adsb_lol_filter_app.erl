%%%-------------------------------------------------------------------
%%% @doc
%%% ADS-B Aircraft Data Agent using the adsb.lol API.
%%% Maintains memory to avoid duplicates across queries.
%%%-------------------------------------------------------------------

-module(adsb_lol_filter_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([handle/2]).

-define(BASE_URL, "https://api.adsb.lol/v2/").
-define(MAX_RESULTS, 100).
-define(MAX_RADIUS, 250).

-define(CAPABILITIES, [
    <<"adsb">>,
    <<"aircraft">>,
    <<"realtime">>,
    <<"aviation">>,
    <<"tracking">>
]).

%%====================================================================
%% Application Behaviour
%%====================================================================

start(_Type, _Args) ->
    em_filter:start_agent(adsb_lol_filter, ?MODULE, #{
        capabilities => ?CAPABILITIES,
        memory       => ets
    }).

stop(_State) ->
    em_filter:stop_agent(adsb_lol_filter).

%%====================================================================
%% Main Handler
%% Receives Body (JSON or plain text) and Memory.
%% Returns {List of aircraft embryos, updated memory}.
%%====================================================================

handle(Body, Memory) when is_binary(Body) ->
    io:format("~n[adsb] handle called with body: ~p~n", [Body]),

    %% Normalize input
    NormalizedBody = normalize_body(Body),

    Seen = maps:get(seen, Memory, #{}),
    Embryos = generate_embryo_list(NormalizedBody),

    Fresh = [E || E <- Embryos, not maps:is_key(url_of(E), Seen)],
    UpdatedSeen = lists:foldl(fun(E, Acc) -> Acc#{url_of(E) => true} end, Seen, Fresh),

    {Fresh, Memory#{seen => UpdatedSeen}};

handle(_, Memory) ->
    {[], Memory}.

%%====================================================================
%% Normalize body: wrap plain text or missing "value" into JSON
%%====================================================================

normalize_body(Body) ->
    case catch json:decode(Body) of
        Map when is_map(Map) ->
            case maps:get(<<"value">>, Map, undefined) of
                undefined -> wrap_value(Body);
                _ -> Body
            end;
        _ ->
            wrap_value(Body)
    end.

wrap_value(Body) ->
    list_to_binary(
        io_lib:format("{\"value\":\"~s\"}", [binary_to_list(Body)])
    ).

%%====================================================================
%% Generate embryo list from JSON body
%%====================================================================

generate_embryo_list(JsonBinary) ->
    case catch json:decode(JsonBinary) of
        Map when is_map(Map) ->
            Value = binary_to_list(maps:get(<<"value">>, Map, <<>>)),
            RawType = binary_to_list(maps:get(<<"query_type">>, Map, <<"auto">>)),
            QueryType =
                case RawType of
                    "auto" -> detect_query_type(Value);
                    Other -> Other
                end,
            fetch_by_type(QueryType, Value, Map);
        _ -> []
    end.

%%====================================================================
%% Detect query type based on input string
%%====================================================================

detect_query_type(Value) ->
    case string:len(Value) of
        6 ->
            case is_hex(Value) of
                true -> "icao";
                false -> "callsign"
            end;
        _ -> "callsign"
    end.

%% Helper: check if string is hex
is_hex(Str) ->
    lists:all(
        fun(C) ->
            (C >= $0 andalso C =< $9) orelse
            (C >= $A andalso C =< $F) orelse
            (C >= $a andalso C =< $f)
        end,
        Str
    ).

%%====================================================================
%% Fetch aircraft data based on query type
%%====================================================================

fetch_by_type("icao", Value, _) ->
    fetch_aircraft(fmt("icao/~s", [Value]));
fetch_by_type("callsign", Value, _) ->
    fetch_aircraft(fmt("callsign/~s", [Value]));
fetch_by_type("registration", Value, _) ->
    fetch_aircraft(fmt("registration/~s", [Value]));
fetch_by_type("type", Value, _) ->
    fetch_aircraft(fmt("type/~s", [Value]));
fetch_by_type("point", _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_aircraft(fmt("point/~s/~s/~s", [binary_to_list(Lat), binary_to_list(Lon), limit_radius(R)]));
fetch_by_type("closest", _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_aircraft(fmt("closest/~s/~s/~s", [binary_to_list(Lat), binary_to_list(Lon), limit_radius(R)]));
fetch_by_type(_, _, _) -> [].

limit_radius(R) ->
    case catch list_to_integer(R) of
        {'EXIT', _} -> integer_to_list(?MAX_RADIUS);
        Int when Int > ?MAX_RADIUS -> integer_to_list(?MAX_RADIUS);
        Int when Int < 0 -> "0";
        Int -> integer_to_list(Int)
    end.

%%====================================================================
%% HTTP Request to ADS-B API
%%====================================================================

fetch_aircraft(Path) ->
    Url = ?BASE_URL ++ Path,
    case httpc:request(get, {Url, []}, [], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} ->
            parse_aircraft_data(Body);
        _ ->
            []
    end.

%%====================================================================
%% Parse aircraft JSON into embryos
%%====================================================================

parse_aircraft_data(JsonBinary) ->
    case catch json:decode(JsonBinary) of
        #{<<"ac">> := AircraftList} when is_list(AircraftList) ->
            case AircraftList of
                [] -> [];
                _  ->
                    Valid = [A || A <- AircraftList, is_valid_aircraft(A)],
                    build_embryos(Valid, 1, [])
            end;
        _ -> []
    end.

is_valid_aircraft(A) when is_map(A) ->
    has_data(A, <<"hex">>) andalso
    has_data(A, <<"lat">>) andalso
    has_data(A, <<"lon">>);
is_valid_aircraft(_) -> false.

has_data(Map, Key) ->
    maps:is_key(Key, Map) andalso maps:get(Key, Map) =/= null.

build_embryos([], _I, Acc) -> lists:reverse(Acc);
build_embryos([H|T], I, Acc) ->
    Embryo = make_embryo(H, I),
    build_embryos(T, I+1, [Embryo|Acc]).

make_embryo(A, I) ->
    Hex = maps:get(<<"hex">>, A),
    Call = maps:get(<<"flight">>, A, <<"">>),
    Reg  = maps:get(<<"r">>, A, <<"">>),
    Alt  = maps:get(<<"alt_baro">>, A, null),
    GS   = maps:get(<<"gs">>, A, null),
    Track= maps:get(<<"track">>, A, null),

    TrackingUrl = list_to_binary(fmt("https://adsb.lol/?icao=~s", [binary_to_list(Hex)])),

    #{
        <<"properties">> => #{
            <<"url">>           => TrackingUrl,
            <<"hex">>           => Hex,
            <<"flight">>        => Call,
            <<"registration">>  => Reg,
            <<"altitude_baro">> => format_alt(Alt),
            <<"ground_speed">>  => format_speed(GS),
            <<"track">>         => format_heading(Track),
            <<"index">>         => I
        }
    }.

format_alt(null) -> <<"N/A">>;
format_alt(X) -> list_to_binary(fmt("~p ft", [X])).

format_speed(null) -> <<"N/A">>;
format_speed(X) -> list_to_binary(fmt("~p kts", [X])).

format_heading(null) -> <<"N/A">>;
format_heading(X) -> list_to_binary(fmt("~p deg", [X])).

fmt(Fmt, Args) -> lists:flatten(io_lib:format(Fmt, Args)).

%%====================================================================
%% Utility
%%====================================================================
url_of(#{<<"properties">> := #{<<"url">> := U}}) -> U.
