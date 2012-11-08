-module(pcapng_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

test_decode(FileName, Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    {ok, Data} = file:read_file(filename:join(DataDir, FileName)),
    pcapng:decode_init(Data),
    ok.

test_encode(FileName, Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    FName = filename:join(DataDir, FileName),
    {ok, Data} = file:read_file(FName),
    {Blocks, _} = pcapng:decode_init(Data),
    Bin = pcapng:encode(Blocks),
    %% file:write_file(FName ++ ".enc", Bin),
    case pcapng:decode_init(Bin) of
	{Blocks, _} ->
	    ok;
	{Other, _} ->
	    ct:fail("Expected: ~p~nGot: ~p~n", [Blocks, Other])
    end.

decode_file(FileName, Step, Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    {ok, Io} = file:open(filename:join(DataDir, FileName), [read, binary]),
    Handle = pcapng:decode_init(),
    decode_io_loop(Io, Step, Handle, file:read(Io, Step), []).

decode_io_loop(Io, _Step, _Handle, eof, Acc) ->
    file:close(Io),
    lists:reverse(Acc);
decode_io_loop(Io, _Step, _Handle, {error, Error}, _Acc) ->
    file:close(Io),
    ct:fail({error, Error});
decode_io_loop(Io, Step, Handle, {ok, Data}, Acc) ->
    {Blocks, NewHandle} = pcapng:decode(Data, Handle),
    case Blocks of
	[] ->
	    decode_io_loop(Io, Step, NewHandle, file:read(Io, Step), Acc);
	_ ->
	    decode_io_loop(Io, Step, NewHandle, file:read(Io, Step), [Blocks|Acc])
    end.

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].


wireshark_http_littleendian(Config) ->
    test_decode("wireshark/http.littleendian.ntar", Config).

wireshark_http_bigendian(Config) ->
    %% this test file is broken, see wireshark wiki
    test_decode("wireshark/http.bigendian.ntar", Config).

wireshark_test001(Config) ->
    test_decode("wireshark/test001.ntar", Config).

wireshark_test002(Config) ->
    test_decode("wireshark/test002.ntar", Config).

wireshark_test003(Config) ->
    test_decode("wireshark/test003.ntar", Config).

wireshark_test004(Config) ->
    test_decode("wireshark/test004.ntar", Config).

wireshark_test005(Config) ->
    test_decode("wireshark/test005.ntar", Config).

wireshark_test006(Config) ->
    test_decode("wireshark/test006.ntar", Config).

wireshark_test007(Config) ->
    test_decode("wireshark/test007.ntar", Config).

wireshark_test008(Config) ->
    test_decode("wireshark/test008.ntar", Config).

wireshark_test009(Config) ->
    test_decode("wireshark/test009.ntar", Config).

wireshark_test010(Config) ->
    test_decode("wireshark/test010.ntar", Config).

wireshark_icmp2(Config) ->
    test_decode("wireshark/icmp2.ntar", Config).

stream_read(Config) ->
    decode_file("wireshark/http.littleendian.ntar", 1, Config).

reencode_http_littleendian(Config) ->
    test_encode("wireshark/http.littleendian.ntar", Config).

reencode_test001(Config) ->
    test_encode("wireshark/test001.ntar", Config).

reencode_test002(Config) ->
    test_encode("wireshark/test002.ntar", Config).

reencode_test003(Config) ->
    test_encode("wireshark/test003.ntar", Config).

reencode_test004(Config) ->
    test_encode("wireshark/test004.ntar", Config).

reencode_test005(Config) ->
    test_encode("wireshark/test005.ntar", Config).

reencode_test006(Config) ->
    test_encode("wireshark/test006.ntar", Config).

reencode_test007(Config) ->
    test_encode("wireshark/test007.ntar", Config).

reencode_test008(Config) ->
    test_encode("wireshark/test008.ntar", Config).

reencode_test009(Config) ->
    test_encode("wireshark/test009.ntar", Config).

reencode_test010(Config) ->
    test_encode("wireshark/test010.ntar", Config).

reencode_icmp2(Config) ->
    test_encode("wireshark/icmp2.ntar", Config).

groups() ->
    [{decode, [], [wireshark_http_littleendian,
		   wireshark_test001, wireshark_test002, wireshark_test003,
		   wireshark_test004, wireshark_test005, wireshark_test006,
		   wireshark_test007, wireshark_test008, wireshark_test009,
		   wireshark_test010, wireshark_icmp2]},
     {stream, [], [stream_read]},
     {encode, [], [reencode_http_littleendian,
		   reencode_test001, reencode_test002, reencode_test003,
		   reencode_test004, reencode_test005, reencode_test006,
		   reencode_test007, reencode_test008, reencode_test009,
		   reencode_test010, reencode_icmp2]}].
all() -> 
    [{group, decode},
     {group, stream},
     {group, encode}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
	ok.

