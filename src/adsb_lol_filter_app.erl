%%%-------------------------------------------------------------------
%%% @doc ADSB.lol ADS-B aircraft data filter and HTTP handler module.
%%%      Consistently uses binary keys for JSON maps.
%%%      Avoids illegal guard expressions.
%%%-------------------------------------------------------------------

-module(adsb_lol_filter_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([handle/1]).

-define(BASE_URL, "https://api.adsb.lol/v2/").
-define(MIN_ALTITUDE, 0).
-define(MAX_ALTITUDE, 50000).
-define(MIN_SPEED, 0).
-define(MAX_SPEED, 1000).
-define(MAX_RESULTS, 100).
-define(MAX_RADIUS, 250).

start(_Type, _Args) ->
    {ok, Port} = em_filter:find_port(),
    em_filter_sup:start_link(adsb_lol_filter, ?MODULE, Port).

stop(_State) -> ok.


%% @doc Handle incoming requests from the filter server.
%% This function is called by em_filter_server through Wade.
%% @param Body The request body (JSON binary or string)
%% @return JSON response as binary or string
handle(Body) when is_binary(Body) ->
    handle(binary_to_list(Body));

handle(Body) when is_list(Body) ->
    io:format("Bing Filter received body: ~p~n", [Body]),
    EmbryoList = generate_embryo_list(list_to_binary(Body)),
    Response = #{embryo_list => EmbryoList},
    jsone:encode(Response);

handle(_) ->
    jsone:encode(#{error => <<"Invalid request body">>}).

generate_embryo_list(JsonBinary) ->
    case jsone:decode(JsonBinary, [{keys, binary}]) of
        Map when is_map(Map) ->
            ValueBin = maps:get(<<"value">>, Map, <<>>),
            QueryTypeBin = maps:get(<<"query_type">>, Map, <<"auto">>),
            Value = binary_to_list(ValueBin),
            QueryTypeRaw = binary_to_list(QueryTypeBin),
            QueryType = case QueryTypeRaw of
                "auto" -> detect_query_type(Value);
                Other -> Other
            end,
            io:format("[INFO] Value: ~p, Query type: ~p~n", [Value, QueryType]),
            fetch_by_type(QueryType, Value, Map);
        _ ->
            io:format("[ERROR] Invalid JSON format~n"),
            []
    end.

detect_query_type(Value) ->
    case length(Value) of
        6 -> case all_hex_chars(Value) of
                true -> "icao";
                false -> detect_other_types(Value)
             end;
        _Other -> detect_other_types(Value)
    end.

%% Not a guard, just normal function
all_hex_chars([]) -> true;
all_hex_chars([H|T]) ->
    if (H >= $0 andalso H =< $9) orelse
       (H >= $A andalso H =< $F) orelse
       (H >= $a andalso H =< $f) ->
        all_hex_chars(T);
       true -> false
    end.

detect_other_types(Value) ->
    case re:run(Value, "^[A-Z]{1,2}-[A-Z0-9]{1,5}$|^N[0-9]{1,5}[A-Z]{0,2}$", [caseless]) of
        {match, _} -> "registration";
        nomatch ->
            case re:run(Value, "^[A-Z][A-Z0-9]{2,3}$", [caseless]) of
                {match, _} when length(Value) >= 3, length(Value) =< 4 ->
                    IsType = lists:member(string:to_upper(Value), aircraft_types()),
                    if IsType -> "type"; true -> "callsign" end;
                nomatch -> if length(Value) > 0 -> "callsign"; true -> "unknown" end
            end
    end.

aircraft_types() ->
    ["A320", "A321", "A330", "A340", "A350", "A380",
     "B737", "B738", "B739", "B747", "B757", "B767", "B777", "B787",
     "E190", "E195", "CRJ2", "CRJ7", "CRJ9", "DHC8", "AT72"].

fetch_by_type("point", _V, #{<<"lat">> := LatBin, <<"lon">> := LonBin, <<"radius">> := RadiusBin}) ->
    fetch_aircraft_by_point(binary_to_list(LatBin), binary_to_list(LonBin), binary_to_list(RadiusBin));
fetch_by_type("closest", _V, #{<<"lat">> := LatBin, <<"lon">> := LonBin, <<"radius">> := RadiusBin}) ->
    fetch_closest_aircraft(binary_to_list(LatBin), binary_to_list(LonBin), binary_to_list(RadiusBin));
fetch_by_type("callsign", V, _) -> fetch_aircraft_by_callsign(V);
fetch_by_type("icao", V, _) -> fetch_aircraft_by_icao(V);
fetch_by_type("registration", V, _) -> fetch_aircraft_by_registration(V);
fetch_by_type("type", V, _) -> fetch_aircraft_by_type(V);
fetch_by_type("squawk", V, _) -> fetch_aircraft_by_squawk(V);
fetch_by_type("military", _, _) -> fetch_military_aircraft();
fetch_by_type("pia", _, _) -> fetch_pia_aircraft();
fetch_by_type("ladd", _, _) -> fetch_ladd_aircraft();
fetch_by_type(_, _, _) -> io:format("[ERROR] Unknown query type~n"), [].

limit_radius(R) ->
    case catch list_to_integer(R) of
        {'EXIT', _} -> integer_to_list(?MAX_RADIUS);
        Int when Int > ?MAX_RADIUS -> integer_to_list(?MAX_RADIUS);
        Int when Int < 0 -> "0";
        Int -> integer_to_list(Int)
    end.

%% HTTP requests to ADSB.lol
fetch_aircraft_by_point(Lat, Lon, Radius) ->
    Url = lists:flatten(io_lib:format("~spoint/~s/~s/~s", [?BASE_URL, Lat, Lon, limit_radius(Radius)])),
    make_request(Url).

fetch_closest_aircraft(Lat, Lon, Radius) ->
    Url = lists:flatten(io_lib:format("~sclosest/~s/~s/~s", [?BASE_URL, Lat, Lon, limit_radius(Radius)])),
    make_request(Url).

fetch_aircraft_by_callsign(Callsign) ->
    Url = lists:flatten(io_lib:format("~scallsign/~s", [?BASE_URL, Callsign])),
    make_request(Url).

fetch_aircraft_by_icao(Icao) ->
    Url = lists:flatten(io_lib:format("~sicao/~s", [?BASE_URL, Icao])),
    make_request(Url).

fetch_aircraft_by_registration(Reg) ->
    Url = lists:flatten(io_lib:format("~sregistration/~s", [?BASE_URL, Reg])),
    make_request(Url).

fetch_aircraft_by_type(Type) ->
    Url = lists:flatten(io_lib:format("~stype/~s", [?BASE_URL, Type])),
    make_request(Url).

fetch_aircraft_by_squawk(Squawk) ->
    Url = lists:flatten(io_lib:format("~ssquawk/~s", [?BASE_URL, Squawk])),
    make_request(Url).

fetch_military_aircraft() -> make_request(?BASE_URL ++ "mil").
fetch_pia_aircraft() -> make_request(?BASE_URL ++ "pia").
fetch_ladd_aircraft() -> make_request(?BASE_URL ++ "ladd").

make_request(Url) ->
    io:format("[INFO] Request URL: ~s~n", [Url]),
    case httpc:request(get, {Url, []}, [], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} -> parse_aircraft_data(Body);
        {ok, {{_, 400, _}, _, _}} -> io:format("[WARN] Bad request (400)~n"), [];
        {ok, {{_, 404, _}, _, _}} -> io:format("[INFO] Not found (404)~n"), [];
        {ok, {{_, 429, _}, _, _}} -> io:format("[WARN] Rate limit exceeded (429)~n"), [];
        {ok, {{_, Code, _}, _, _}} -> io:format("[INFO] HTTP status ~p~n", [Code]), [];
        {error, Reason} -> io:format("[ERROR] HTTP error: ~p~n", [Reason]), []
    end.

%% Parse JSON aircraft response
parse_aircraft_data(JsonBinary) ->
    io:format("[DEBUG] Raw JSON: ~s~n", [JsonBinary]),
    case catch jsone:decode(JsonBinary, [{keys, binary}]) of
        {'EXIT', Reason} ->
            io:format("[ERROR] JSON decode failed: ~p~n", [Reason]),
            [];
        Decoded when is_map(Decoded) ->
            case maps:get(<<"ac">>, Decoded, []) of
                AircraftList when is_list(AircraftList) ->
                    io:format("[DEBUG] Processing aircraft list with length ~p~n", [length(AircraftList)]),
                    try
                        Filtered = filter_valid_aircraft(AircraftList),
                        Embryos = build_embryos(Filtered, 1, []),
                        Embryos
                    catch
                        error:undef ->
                            io:format("[ERROR] Undefined function called during processing~n"),
                            [];
                        error:Reason ->
                            io:format("[ERROR] Processing error: ~p~n", [Reason]),
                            []
                    end;
                _ ->
                    io:format("[ERROR] 'ac' key missing or not a list~n"),
                    []
            end;
        _ ->
            io:format("[ERROR] Unexpected JSON structure~n"),
            []
    end.

filter_valid_aircraft(List) ->
    Valid = [A || A <- List, is_valid_aircraft(A)],
    case length(Valid) > ?MAX_RESULTS of
        true -> lists:sublist(Valid, ?MAX_RESULTS);
        false -> Valid
    end.

is_valid_aircraft(A) when is_map(A) ->
    HasHex = maps:is_key(<<"hex">>, A) andalso maps:get(<<"hex">>, A) =/= null andalso maps:get(<<"hex">>, A) =/= <<>>,
    HasPos = maps:is_key(<<"lat">>, A) andalso maps:is_key(<<"lon">>, A) andalso
             maps:get(<<"lat">>, A) =/= null andalso maps:get(<<"lon">>, A) =/= null,
    AltOk = case maps:get(<<"alt_baro">>, A, null) of
        null -> true;
        Alt when is_number(Alt) -> Alt >= ?MIN_ALTITUDE andalso Alt =< ?MAX_ALTITUDE;
        _ -> false
    end,
    SpeedOk = case maps:get(<<"gs">>, A, null) of
        null -> true;
        Speed when is_number(Speed) -> Speed >= ?MIN_SPEED andalso Speed =< ?MAX_SPEED;
        _ -> false
    end,
    HasHex andalso HasPos andalso AltOk andalso SpeedOk;
is_valid_aircraft(_) -> false.

build_embryos([], _Idx, Acc) -> lists:reverse(Acc);
build_embryos([H|T], Idx, Acc) ->
    Embryo = build_single_embryo(H, Idx),
    build_embryos(T, Idx + 1, [Embryo | Acc]).

build_single_embryo(A, Idx) ->
    Hex = maps:get(<<"hex">>, A, <<"Unknown">>),
    Flight = maps:get(<<"flight">>, A, <<"Unknown">>),
    Registration = maps:get(<<"r">>, A, <<"Unknown">>),
    AltBaro = maps:get(<<"alt_baro">>, A, null),
    GroundSpeed = maps:get(<<"gs">>, A, null),
    Track = maps:get(<<"track">>, A, null),
    Emergency = maps:get(<<"emergency">>, A, <<"none">>),
    Alert = maps:get(<<"alert">>, A, 0),

    Description = build_description(Flight, Hex, Registration, AltBaro, GroundSpeed, Track, Emergency, Alert),

    TrackingUrl = lists:flatten(io_lib:format("https://adsb.lol/?icao=~s", [binary_to_list(Hex)])),

    #{
      properties => #{
          <<"resume">> => list_to_binary(Description),
          <<"url">> => list_to_binary(TrackingUrl),
          <<"hex">> => Hex,
          <<"flight">> => Flight,
          <<"registration">> => Registration,
          <<"altitude_baro">> => format_altitude(AltBaro),
          <<"ground_speed">> => format_speed(GroundSpeed),
          <<"track">> => format_heading(Track),
          <<"emergency">> => Emergency,
          <<"alert">> => format_boolean(Alert),
          <<"index">> => Idx
      }
    }.

safe_binary_to_string(Bin) when is_binary(Bin) ->
    io:format("safe_binary_to_string: input=~p~n", [Bin]),
    Trimmed = string:trim(binary_to_list(Bin)),
    io:format("safe_binary_to_string: output=~p~n", [Trimmed]),
    Trimmed;
safe_binary_to_string(_) ->
    io:format("safe_binary_to_string: input is not binary, output=\"\"~n", []),
    "".

%% Main function
build_description(Flight, Hex, Registration, AltBaro, GroundSpeed, Track, Emergency, Alert) ->
    %% Debug: Print input parameters
    io:format("=== build_description: Input Parameters ===~n", []),
    io:format("Flight: ~p~n", [Flight]),
    io:format("Hex: ~p~n", [Hex]),
    io:format("Registration: ~p~n", [Registration]),
    io:format("AltBaro: ~p~n", [AltBaro]),
    io:format("GroundSpeed: ~p~n", [GroundSpeed]),
    io:format("Track: ~p~n", [Track]),
    io:format("Emergency: ~p~n", [Emergency]),
    io:format("Alert: ~p~n", [Alert]),

    %% Determine FlightId safely
    io:format("=== Determining FlightId ===~n", []),
    FlightId = determine_flight_id(Flight, Hex, Registration),
    io:format("FlightId result: ~p~n", [FlightId]),

    %% Build RegStr safely
    io:format("=== Building RegStr ===~n", []),
    RegStr = build_reg_str(Registration, FlightId),
    io:format("RegStr result: ~p~n", [RegStr]),

    %% Build Altitude string
    io:format("=== Building AltStr ===~n", []),
    AltStr = build_alt_str(AltBaro),
    io:format("AltStr result: ~p~n", [AltStr]),

    %% Build GroundSpeed string
    io:format("=== Building SpeedStr ===~n", []),
    SpeedStr = build_speed_str(GroundSpeed),
    io:format("SpeedStr result: ~p~n", [SpeedStr]),

    %% Build Track string
    io:format("=== Building TrackStr ===~n", []),
    TrackStr = build_track_str(Track),
    io:format("TrackStr result: ~p~n", [TrackStr]),

    %% Build Alert string
    io:format("=== Building AlertStr ===~n", []),
    AlertStr = build_alert_str(Alert),
    io:format("AlertStr result: ~p~n", [AlertStr]),

    %% Build Emergency string
    io:format("=== Building EmergencyStr ===~n", []),
    EmergencyStr = build_emergency_str(Emergency),
    io:format("EmergencyStr result: ~p~n", [EmergencyStr]),

    %% Compose result
    io:format("=== Composing final result ===~n", []),
    Result = lists:flatten(io_lib:format("Aircraft ~s~s~s~s~s~s~s.",
        [FlightId, RegStr, AltStr, SpeedStr, TrackStr, AlertStr, EmergencyStr])),
    io:format("=== build_description: Final description: ~s~n", [Result]),
    Result.

%% Helper functions for each part of the description

determine_flight_id(Flight, Hex, Registration) ->
    io:format("determine_flight_id: Flight=~p, Hex=~p, Registration=~p~n", [Flight, Hex, Registration]),
    FlightTrimmed = safe_binary_to_string(Flight),
    io:format("determine_flight_id: FlightTrimmed=~p~n", [FlightTrimmed]),
    case FlightTrimmed of
        "" ->
            io:format("determine_flight_id: Flight is empty, using Hex~n", []),
            safe_binary_to_string(Hex);
        "Unknown" ->
            io:format("determine_flight_id: Flight is 'Unknown', checking Registration~n", []),
            RegTrimmed = safe_binary_to_string(Registration),
            io:format("determine_flight_id: RegTrimmed=~p~n", [RegTrimmed]),
            case RegTrimmed of
                "Unknown" ->
                    io:format("determine_flight_id: Registration is 'Unknown', using Hex~n", []),
                    safe_binary_to_string(Hex);
                "" ->
                    io:format("determine_flight_id: Registration is empty, using Hex~n", []),
                    safe_binary_to_string(Hex);
                _ ->
                    io:format("determine_flight_id: Using Registration=~p~n", [RegTrimmed]),
                    RegTrimmed
            end;
        _ ->
            io:format("determine_flight_id: Using FlightTrimmed=~p~n", [FlightTrimmed]),
            FlightTrimmed
    end.

build_reg_str(Registration, FlightId) ->
    io:format("build_reg_str: Registration=~p, FlightId=~p~n", [Registration, FlightId]),
    RegTrimmed = safe_binary_to_string(Registration),
    io:format("build_reg_str: RegTrimmed=~p~n", [RegTrimmed]),
    case RegTrimmed of
        "" ->
            io:format("build_reg_str: Registration is empty, output=\"\"~n", []),
            "";
        _ ->
            case RegTrimmed == FlightId of
                true ->
                    io:format("build_reg_str: RegTrimmed == FlightId, output=\"\"~n", []),
                    "";
                false ->
                    io:format("build_reg_str: RegTrimmed != FlightId, output=[~s]~n", [RegTrimmed]),
                    lists:flatten(io_lib:format(" [~s]", [RegTrimmed]))
            end
    end.

build_alt_str(AltBaro) ->
    io:format("build_alt_str: AltBaro=~p~n", [AltBaro]),
    case AltBaro of
        N when is_number(N) ->
            io:format("build_alt_str: AltBaro is number, output=~p~n", [N]),
            lists:flatten(io_lib:format(" at ~p ft", [N]));
        _ ->
            io:format("build_alt_str: AltBaro is not number, output=\"\"~n", []),
            ""
    end.

build_speed_str(GroundSpeed) ->
    io:format("build_speed_str: GroundSpeed=~p~n", [GroundSpeed]),
    case GroundSpeed of
        GS when is_number(GS), GS > 0 ->
            io:format("build_speed_str: GroundSpeed is positive number, output=~p~n", [GS]),
            lists:flatten(io_lib:format(", ~.1f kts", [GS]));
        _ ->
            io:format("build_speed_str: GroundSpeed is not positive number, output=\"\"~n", []),
            ""
    end.

build_track_str(Track) ->
    io:format("build_track_str: Track=~p~n", [Track]),
    case Track of
        T when is_number(T) ->
            io:format("build_track_str: Track is number, output=~p~n", [T]),
            % Use 'deg' instead of the degree symbol to avoid UTF-8 encoding issues
            lists:flatten(io_lib:format(", heading ~.1f deg", [T]));
        _ ->
            io:format("build_track_str: Track is not number, output=\"\"~n", []),
            ""
    end.

build_alert_str(Alert) ->
    io:format("build_alert_str: Alert=~p~n", [Alert]),
    case Alert of
        1 ->
            io:format("build_alert_str: Alert is 1, output=\" [ALERT]\"~n", []),
            " [ALERT]";
        _ ->
            io:format("build_alert_str: Alert is not 1, output=\"\"~n", []),
            ""
    end.

build_emergency_str(Emergency) ->
    io:format("build_emergency_str: Emergency=~p~n", [Emergency]),
    case Emergency of
        <<"none">> ->
            io:format("build_emergency_str: Emergency is 'none', output=\"\"~n", []),
            "";
        <<"general">> ->
            io:format("build_emergency_str: Emergency is 'general', output=\" [EMERGENCY]\"~n", []),
            " [EMERGENCY]";
        E when is_binary(E) ->
            io:format("build_emergency_str: Emergency is binary, converting~n", []),
            EmergencyTrimmed = safe_binary_to_string(E),
            io:format("build_emergency_str: EmergencyTrimmed=~p~n", [EmergencyTrimmed]),
            lists:flatten(io_lib:format(" [EMERGENCY: ~s]", [EmergencyTrimmed]));
        _ ->
            io:format("build_emergency_str: Emergency is not binary, output=\"\"~n", []),
            ""
    end.

%% Format helpers
format_altitude(null) -> <<"N/A">>;
format_altitude(Alt) when is_number(Alt) -> list_to_binary(io_lib:format("~p ft", [Alt]));
format_altitude(_) -> <<"N/A">>.

format_speed(null) -> <<"N/A">>;
format_speed(Speed) when is_number(Speed) -> list_to_binary(io_lib:format("~p kts", [Speed]));
format_speed(_) -> <<"N/A">>.

format_heading(null) -> <<"N/A">>;
format_heading(H) when is_number(H) -> list_to_binary(io_lib:format("~p deg", [H]));
format_heading(_) -> <<"N/A">>.

format_boolean(0) -> <<"false">>;
format_boolean(1) -> <<"true">>;
format_boolean(true) -> <<"true">>;
format_boolean(false) -> <<"false">>;
format_boolean(_) -> <<"unknown">>.
