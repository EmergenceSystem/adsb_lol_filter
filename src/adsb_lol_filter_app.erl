%%%-------------------------------------------------------------------
%%% @doc ADS-B aircraft data filter using the adsb.lol API.
%%%
%%% Queries the adsb.lol v2 API based on the incoming search value
%%% and returns a list of embryo maps — one per valid aircraft.
%%%
%%% Supported query types (auto-detected or explicit via "query_type"):
%%%   icao, registration, callsign, type, squawk,
%%%   military, pia, ladd, point, closest.
%%% @end
%%%-------------------------------------------------------------------
-module(adsb_lol_filter_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([handle/1]).

-define(BASE_URL,    "https://api.adsb.lol/v2/").
-define(MIN_ALTITUDE, 0).
-define(MAX_ALTITUDE, 50000).
-define(MIN_SPEED,    0).
-define(MAX_SPEED,    1000).
-define(MAX_RESULTS,  100).
-define(MAX_RADIUS,   250).

%%====================================================================
%% Application behaviour
%%====================================================================

start(_Type, _Args) ->
    em_filter:start_filter(adsb_lol_filter, ?MODULE).

stop(_State) ->
    em_filter:stop_filter(adsb_lol_filter).

%%====================================================================
%% Filter handler — returns a list of embryo maps
%%====================================================================

%% @doc Called by em_filter_server for every incoming query.
%% Returns a list of embryo maps (not pre-encoded JSON).
handle(Body) when is_binary(Body) ->
    generate_embryo_list(Body);
handle(_) ->
    [].

%%====================================================================
%% Query dispatch
%%====================================================================

generate_embryo_list(JsonBinary) ->
    try json:decode(JsonBinary) of
        Map when is_map(Map) ->
            Value        = binary_to_list(maps:get(<<"value">>,      Map, <<>>)),
            QueryTypeRaw = binary_to_list(maps:get(<<"query_type">>, Map, <<"auto">>)),
            QueryType    = case QueryTypeRaw of
                "auto" -> detect_query_type(Value);
                Other  -> Other
            end,
            fetch_by_type(QueryType, Value, Map);
        _ -> []
    catch
        _:_ -> []
    end.

%%--------------------------------------------------------------------
%% Query type auto-detection
%%--------------------------------------------------------------------

detect_query_type(Value) ->
    case length(Value) of
        6 ->
            case all_hex_chars(Value) of
                true  -> "icao";
                false -> detect_other_types(Value)
            end;
        _ -> detect_other_types(Value)
    end.

all_hex_chars([]) -> true;
all_hex_chars([H | T]) ->
    if (H >= $0 andalso H =< $9) orelse
       (H >= $A andalso H =< $F) orelse
       (H >= $a andalso H =< $f) -> all_hex_chars(T);
       true -> false
    end.

detect_other_types(Value) ->
    case re:run(Value, "^[A-Z]{1,2}-[A-Z0-9]{1,5}$|^N[0-9]{1,5}[A-Z]{0,2}$",
                [caseless]) of
        {match, _} -> "registration";
        nomatch ->
            case re:run(Value, "^[A-Z][A-Z0-9]{2,3}$", [caseless]) of
                {match, _} when length(Value) >= 3, length(Value) =< 4 ->
                    IsType = lists:member(string:to_upper(Value), aircraft_types()),
                    if IsType -> "type"; true -> "callsign" end;
                _ ->
                    if length(Value) > 0 -> "callsign"; true -> "unknown" end
            end
    end.

aircraft_types() ->
    ["A320","A321","A330","A340","A350","A380",
     "B737","B738","B739","B747","B757","B767","B777","B787",
     "E190","E195","CRJ2","CRJ7","CRJ9","DHC8","AT72"].

%%--------------------------------------------------------------------
%% Fetch dispatch
%%--------------------------------------------------------------------

fetch_by_type("point", _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_aircraft_by_point(binary_to_list(Lat), binary_to_list(Lon), binary_to_list(R));
fetch_by_type("closest", _, #{<<"lat">> := Lat, <<"lon">> := Lon, <<"radius">> := R}) ->
    fetch_closest_aircraft(binary_to_list(Lat), binary_to_list(Lon), binary_to_list(R));
fetch_by_type("callsign",     V, _) -> fetch_aircraft_by_callsign(V);
fetch_by_type("icao",         V, _) -> fetch_aircraft_by_icao(V);
fetch_by_type("registration", V, _) -> fetch_aircraft_by_registration(V);
fetch_by_type("type",         V, _) -> fetch_aircraft_by_type(V);
fetch_by_type("squawk",       V, _) -> fetch_aircraft_by_squawk(V);
fetch_by_type("military",     _, _) -> fetch_military_aircraft();
fetch_by_type("pia",          _, _) -> fetch_pia_aircraft();
fetch_by_type("ladd",         _, _) -> fetch_ladd_aircraft();
fetch_by_type(_Unknown,       _, _) -> [].

%%--------------------------------------------------------------------
%% HTTP helpers
%%--------------------------------------------------------------------

limit_radius(R) ->
    case catch list_to_integer(R) of
        {'EXIT', _}                  -> integer_to_list(?MAX_RADIUS);
        Int when Int > ?MAX_RADIUS   -> integer_to_list(?MAX_RADIUS);
        Int when Int < 0             -> "0";
        Int                          -> integer_to_list(Int)
    end.

fetch_aircraft_by_point(Lat, Lon, Radius) ->
    make_request(fmt("~spoint/~s/~s/~s", [?BASE_URL, Lat, Lon, limit_radius(Radius)])).

fetch_closest_aircraft(Lat, Lon, Radius) ->
    make_request(fmt("~sclosest/~s/~s/~s", [?BASE_URL, Lat, Lon, limit_radius(Radius)])).

fetch_aircraft_by_callsign(C)    -> make_request(fmt("~scallsign/~s",    [?BASE_URL, C])).
fetch_aircraft_by_icao(I)        -> make_request(fmt("~sicao/~s",        [?BASE_URL, I])).
fetch_aircraft_by_registration(R)-> make_request(fmt("~sregistration/~s",[?BASE_URL, R])).
fetch_aircraft_by_type(T)        -> make_request(fmt("~stype/~s",        [?BASE_URL, T])).
fetch_aircraft_by_squawk(S)      -> make_request(fmt("~ssquawk/~s",      [?BASE_URL, S])).
fetch_military_aircraft()        -> make_request(?BASE_URL ++ "mil").
fetch_pia_aircraft()             -> make_request(?BASE_URL ++ "pia").
fetch_ladd_aircraft()            -> make_request(?BASE_URL ++ "ladd").

make_request(Url) ->
    case httpc:request(get, {Url, []}, [], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} -> parse_aircraft_data(Body);
        _                            -> []
    end.

%% Shorthand for lists:flatten(io_lib:format(...))
fmt(Fmt, Args) -> lists:flatten(io_lib:format(Fmt, Args)).

%%--------------------------------------------------------------------
%% JSON parsing and embryo building
%%--------------------------------------------------------------------

parse_aircraft_data(JsonBinary) ->
    try json:decode(JsonBinary) of
        #{<<"ac">> := AircraftList} when is_list(AircraftList) ->
            Filtered = filter_valid_aircraft(AircraftList),
            build_embryos(Filtered, 1, []);
        _ -> []
    catch
        _:_ -> []
    end.

filter_valid_aircraft(List) ->
    Valid = [A || A <- List, is_valid_aircraft(A)],
    case length(Valid) > ?MAX_RESULTS of
        true  -> lists:sublist(Valid, ?MAX_RESULTS);
        false -> Valid
    end.

is_valid_aircraft(A) when is_map(A) ->
    HasHex = maps:is_key(<<"hex">>, A)
             andalso maps:get(<<"hex">>, A) =/= null
             andalso maps:get(<<"hex">>, A) =/= <<>>,
    HasPos = maps:is_key(<<"lat">>, A)
             andalso maps:is_key(<<"lon">>, A)
             andalso maps:get(<<"lat">>, A) =/= null
             andalso maps:get(<<"lon">>, A) =/= null,
    AltOk  = case maps:get(<<"alt_baro">>, A, null) of
        null                      -> true;
        Alt when is_number(Alt)   -> Alt >= ?MIN_ALTITUDE andalso Alt =< ?MAX_ALTITUDE;
        _                         -> false
    end,
    SpeedOk = case maps:get(<<"gs">>, A, null) of
        null                      -> true;
        Speed when is_number(Speed) -> Speed >= ?MIN_SPEED andalso Speed =< ?MAX_SPEED;

        _                         -> false
    end,
    HasHex andalso HasPos andalso AltOk andalso SpeedOk;
is_valid_aircraft(_) -> false.

build_embryos([], _Idx, Acc) ->
    lists:reverse(Acc);
build_embryos([H | T], Idx, Acc) ->
    build_embryos(T, Idx + 1, [build_single_embryo(H, Idx) | Acc]).

build_single_embryo(A, Idx) ->
    Hex          = maps:get(<<"hex">>,       A, <<"Unknown">>),
    Flight       = maps:get(<<"flight">>,    A, <<"Unknown">>),
    Registration = maps:get(<<"r">>,         A, <<"Unknown">>),
    AltBaro      = maps:get(<<"alt_baro">>,  A, null),
    GroundSpeed  = maps:get(<<"gs">>,        A, null),
    Track        = maps:get(<<"track">>,     A, null),
    Emergency    = maps:get(<<"emergency">>, A, <<"none">>),
    Alert        = maps:get(<<"alert">>,     A, 0),

    Description  = build_description(Flight, Hex, Registration,
                                     AltBaro, GroundSpeed, Track,
                                     Emergency, Alert),
    TrackingUrl  = list_to_binary(fmt("https://adsb.lol/?icao=~s",
                                      [binary_to_list(Hex)])),
    #{
        <<"properties">> => #{
            <<"url">>              => TrackingUrl,
            <<"resume">>           => list_to_binary(Description),
            <<"hex">>              => Hex,
            <<"flight">>           => Flight,
            <<"registration">>     => Registration,
            <<"altitude_baro">>    => format_altitude(AltBaro),
            <<"ground_speed">>     => format_speed(GroundSpeed),
            <<"track">>            => format_heading(Track),
            <<"emergency">>        => Emergency,
            <<"alert">>            => format_boolean(Alert),
            <<"index">>            => Idx
        }
    }.

%%--------------------------------------------------------------------
%% Description builder
%%--------------------------------------------------------------------

build_description(Flight, Hex, Registration, AltBaro, GroundSpeed,
                  Track, Emergency, Alert) ->
    FlightId = determine_flight_id(Flight, Hex, Registration),
    RegStr   = build_reg_str(Registration, FlightId),
    AltStr   = case AltBaro of
        N when is_number(N) -> fmt(" at ~p ft", [N]);
        _                   -> ""
    end,
    SpeedStr = case GroundSpeed of
        GS when is_number(GS), GS > 0 -> fmt(", ~.1f kts", [GS]);
        _                              -> ""
    end,
    TrackStr = case Track of
        T when is_number(T) -> fmt(", heading ~.1f deg", [T]);
        _                   -> ""
    end,
    AlertStr = case Alert of
        1 -> " [ALERT]";
        _ -> ""
    end,
    EmergencyStr = case Emergency of
        <<"none">>    -> "";
        <<"general">> -> " [EMERGENCY]";
        E when is_binary(E) ->
            fmt(" [EMERGENCY: ~s]", [binary_to_list(E)]);
        _ -> ""
    end,
    lists:flatten(fmt("Aircraft ~s~s~s~s~s~s~s.",
        [FlightId, RegStr, AltStr, SpeedStr, TrackStr, AlertStr, EmergencyStr])).

determine_flight_id(Flight, Hex, Registration) ->
    FlightStr = trim_bin(Flight),
    HexStr    = trim_bin(Hex),
    RegStr    = trim_bin(Registration),
    case FlightStr of
        ""        -> use_fallback(RegStr, HexStr);
        "Unknown" -> use_fallback(RegStr, HexStr);
        F         -> F
    end.

use_fallback("",        HexStr) -> HexStr;
use_fallback("Unknown", HexStr) -> HexStr;
use_fallback(RegStr,    _)      -> RegStr.

build_reg_str(Registration, FlightId) ->
    RegStr = trim_bin(Registration),
    case RegStr =:= "" orelse RegStr =:= FlightId of
        true  -> "";
        false -> fmt(" [~s]", [RegStr])
    end.

%% Converts a binary to a trimmed string; returns "" for non-binaries.
trim_bin(B) when is_binary(B) -> string:trim(binary_to_list(B));
trim_bin(_)                   -> "".

%%--------------------------------------------------------------------
%% Format helpers
%%--------------------------------------------------------------------

format_altitude(null)                    -> <<"N/A">>;
format_altitude(A) when is_number(A)    -> list_to_binary(fmt("~p ft",  [A]));
format_altitude(_)                       -> <<"N/A">>.

format_speed(null)                       -> <<"N/A">>;
format_speed(S) when is_number(S)       -> list_to_binary(fmt("~p kts", [S]));
format_speed(_)                          -> <<"N/A">>.

format_heading(null)                     -> <<"N/A">>;
format_heading(H) when is_number(H)     -> list_to_binary(fmt("~p deg", [H]));
format_heading(_)                        -> <<"N/A">>.

format_boolean(0)     -> <<"false">>;
format_boolean(1)     -> <<"true">>;
format_boolean(true)  -> <<"true">>;
format_boolean(false) -> <<"false">>;
format_boolean(_)     -> <<"unknown">>.
