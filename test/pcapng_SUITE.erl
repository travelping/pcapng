-module(pcapng_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

decode_file(FileName, Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    {ok, Data} = file:read_file(filename:join(DataDir, FileName)),
    pcapng:decode_init(Data).

decode_file(FileName, Step, Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    {ok, Io} = file:open(filename:join(DataDir, FileName), [read, binary]),
    Handle = pcapng:decode_init(),
    decode_io_loop(Io, Step, Handle, file:read(Io, Step), []).

decode_io_loop(Io, _Step, _Handle, eof, _Acc) ->
    file:close(Io),
    ok;
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
    decode_file("wireshark/http.littleendian.ntar", Config).

wireshark_http_bigendian(Config) ->
    %% this test file is broken, see wireshark wiki
    decode_file("wireshark/http.bigendian.ntar", Config).

wireshark_test001(Config) ->
    decode_file("wireshark/test001.ntar", Config).

wireshark_test002(Config) ->
    decode_file("wireshark/test002.ntar", Config).

wireshark_test003(Config) ->
    decode_file("wireshark/test003.ntar", Config).

wireshark_test004(Config) ->
    decode_file("wireshark/test004.ntar", Config).

wireshark_test005(Config) ->
    decode_file("wireshark/test005.ntar", Config).

wireshark_test006(Config) ->
    decode_file("wireshark/test006.ntar", Config).

wireshark_test007(Config) ->
    decode_file("wireshark/test007.ntar", Config).

wireshark_test008(Config) ->
    decode_file("wireshark/test008.ntar", Config).

wireshark_test009(Config) ->
    decode_file("wireshark/test009.ntar", Config).

wireshark_test010(Config) ->
    decode_file("wireshark/test010.ntar", Config).

wireshark_icmp2(Config) ->
    decode_file("wireshark/icmp2.ntar", Config).

stream_read(Config) ->
    decode_file("wireshark/http.littleendian.ntar", 1, Config).

all() -> 
	[wireshark_http_littleendian,
	 wireshark_test001, wireshark_test002, wireshark_test003,
	 wireshark_test004, wireshark_test005, wireshark_test006,
	 wireshark_test007, wireshark_test008, wireshark_test009,
	 wireshark_test010, wireshark_icmp2,
	 stream_read].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
	ok.

