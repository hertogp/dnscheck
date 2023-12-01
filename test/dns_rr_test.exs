defmodule DNS.Msg.RRTest do
  use ExUnit.Case
  doctest DNS.Msg.RR, import: true

  alias DNS.Msg.RR
  import Drill

  test "RR - new" do
    # input validation
    assert_raise DNS.Msg.Error, fn -> RR.new(type: 65536) end
    assert_raise DNS.Msg.Error, fn -> RR.new(type: -1) end
    assert_raise DNS.Msg.Error, fn -> RR.new(class: 65536) end
    assert_raise DNS.Msg.Error, fn -> RR.new(class: -1) end
    assert_raise DNS.Msg.Error, fn -> RR.new(ttl: 2_147_483_648) end
    assert_raise DNS.Msg.Error, fn -> RR.new(ttl: -2_147_483_649) end
    assert_raise DNS.Msg.Error, fn -> RR.new(rdmap: []) end
    assert_raise DNS.Msg.Error, fn -> RR.new(name: "example.123") end
    assert_raise DNS.Msg.Error, fn -> RR.new(name: "example.-om") end
    assert_raise DNS.Msg.Error, fn -> RR.new(name: "example.co-") end
    label_too_long = String.duplicate("a", 64)
    assert_raise DNS.Msg.Error, fn -> RR.new(name: label_too_long <> ".com") end
    name_too_long = String.duplicate("aa", 84) |> String.replace("aa", "a.a") |> Kernel.<>(".a")
    assert 254 == String.length(name_too_long)
    assert_raise DNS.Msg.Error, fn -> RR.new(name: name_too_long) end

    # new will ignore some calculated fields
    rr = RR.new(rdlen: 7, rdata: <<"ignored">>, wdata: <<"ignored">>)
    assert 0 == rr.rdlen
    assert <<>> == rr.rdata
    assert <<>> == rr.wdata

    # new turns known numerics into atoms
    rr = RR.new(class: 1, type: 1)
    assert :IN == rr.class
    assert :A == rr.type

    # new has sane defaults
    rr = RR.new()
    assert "" == rr.name
    assert :A == rr.type
    assert :IN == rr.class
    assert 0 == rr.ttl
    assert 0 == rr.rdlen
    assert 0 == map_size(rr.rdmap)
    assert <<>> == rr.rdata
    assert <<>> == rr.wdata
  end

  test "RR - put" do
    rr = RR.new()
    # input validation
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, type: 65536) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, type: -1) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, type: "A") end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, type: :a) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, class: 65536) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, class: -1) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, ttl: 2_147_483_648) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, ttl: -2_147_483_649) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, rdmap: []) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, name: "example.123") end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, name: "example.-om") end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, name: "example.co-") end
    label_too_long = String.duplicate("a", 64)
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, name: label_too_long <> ".com") end
    name_too_long = String.duplicate("aa", 84) |> String.replace("aa", "a.a") |> Kernel.<>(".a")
    assert 254 == String.length(name_too_long)
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, name: name_too_long) end

    # good put's
    rr =
      RR.new()
      |> RR.put(name: "www.example.com")
      |> RR.put(type: 5)
      |> RR.put(class: :IN)
      |> RR.put(ttl: 3600)
      |> RR.put(rdmap: %{name: "example.com"})
      |> RR.put(ignored: "option")

    assert "www.example.com" == rr.name
    assert :CNAME == rr.type
    assert :IN == rr.class
    assert 3600 == rr.ttl
    assert "example.com" == rr.rdmap.name
  end

  test "RR - encode" do
    # encodes empty domain name
    rr = RR.new(type: :A, rdmap: %{ip: "1.1.1.1"}) |> RR.encode()
    assert 4 == byte_size(rr.rdata)
    assert <<1, 1, 1, 1>> == rr.rdata
    assert String.ends_with?(rr.wdata, rr.rdata)
    assert String.starts_with?(rr.wdata, <<0>>)

    # name encoding
    rr = RR.new(name: "example.com", rdmap: %{ip: "1.1.1.1"}) |> RR.encode()
    assert String.starts_with?(rr.wdata, <<7, "example", 3, "com", 0>>)

    # round trip
    {offset, rr2} = RR.decode(0, rr.wdata)
    assert offset == String.length(rr.wdata)
    assert rr == rr2

    # raises when missing fields or invalid rdmap values
    assert_raise DNS.Msg.Error, fn -> RR.new() |> RR.encode() end
    assert_raise DNS.Msg.Error, fn -> RR.new(rdmap: %{}) |> RR.encode() end
    assert_raise DNS.Msg.Error, fn -> RR.new(type: :A, rdmap: %{ip: "acdc::"}) |> RR.encode() end

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :AAAA, rdmap: %{ip: "1.1.1.1"}) |> RR.encode()
    end
  end

  test "EDNS0" do
    # default values, skipping unknown options
    rr = RR.new(name: "ignored", type: 41, option: :ignored)
    assert "" == rr.name
    assert :OPT == rr.type
    assert 32768 == rr.ttl
    assert 1410 == rr.class
    assert 1410 == rr.rdmap.bufsize
    assert :NOERROR == rr.rdmap.xrcode
    assert 1 == rr.rdmap.do
    assert 0 == rr.rdmap.z
    assert 0 == rr.rdmap.version
    assert [] == rr.rdmap.opts
    assert 0 == rr.rdlen
    assert "" == rr.rdata
    assert "" == rr.wdata

    rr = RR.encode(rr)
    assert "" == rr.rdata
    assert <<0, 0, 41, 5, 130, 0, 0, 128, 0, 0, 0>> == rr.wdata

    # input validation on known options
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, xrcode: 256) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, version: 256) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, do: 2) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, z: 32768) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, bufsize: 65536) end
    assert_raise DNS.Msg.Error, fn -> RR.put(rr, opts: %{}) end
  end

  test "EDNS0 - NSID" do
    rr = RR.new(type: :OPT, opts: [{:NSID, "abcdef"}]) |> RR.encode()
    assert "abcdef" == rr.rdmap.opts |> Keyword.get(:NSID)
    assert <<0, 3, 0, 6, "abcdef">> == rr.rdata
    assert String.ends_with?(rr.wdata, rr.rdata)

    # round trip
    {offset, rr2} = RR.decode(0, rr.wdata)
    assert offset == String.length(rr.wdata)
    assert rr == rr2
  end

  test "EDNS0 - EXPIRE" do
    rr = RR.new(type: :OPT, opts: [{:EXPIRE, 2 ** 32 - 1}]) |> RR.encode()
    assert 2 ** 32 - 1 == rr.rdmap.opts |> Keyword.get(:EXPIRE)

    # round trip
    {offset, rr2} = RR.decode(0, rr.wdata)
    assert offset == String.length(rr.wdata)
    assert rr == rr2

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:EXPIRE, 2 ** 32}]) |> RR.encode()
    end

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:EXPIRE, -1}]) |> RR.encode()
    end
  end

  test "EDNS0 - COOKIE" do
    rr = RR.new(type: :OPT, opts: [{:COOKIE, {"12345678", ""}}]) |> RR.encode()
    assert {"12345678", ""} == rr.rdmap.opts |> Keyword.get(:COOKIE)
    # round trip
    {offset, rr2} = RR.decode(0, rr.wdata)
    assert offset == String.length(rr.wdata)
    assert rr == rr2

    rr = RR.new(type: :OPT, opts: [{:COOKIE, {"12345678", "87654321"}}]) |> RR.encode()
    assert {"12345678", "87654321"} == rr.rdmap.opts |> Keyword.get(:COOKIE)
    # round trip
    {offset, rr2} = RR.decode(0, rr.wdata)
    assert offset == String.length(rr.wdata)
    assert rr == rr2

    # raises on invalid cookies
    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {"1234567", "87654321"}}]) |> RR.encode()
    end

    cookie_too_short = "1234567"

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {cookie_too_short, "87654321"}}]) |> RR.encode()
    end

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {"12345678", cookie_too_short}}]) |> RR.encode()
    end

    cookie_too_long = String.duplicate("a", 33)

    assert_raise DNS.Msg.Error, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {"12345678", cookie_too_long}}]) |> RR.encode()
    end
  end

  #
  # [[ DECODE WIRESAMPLES ]]
  #
  test "A RR - decode" do
    :ok = ensure_testfile("test/data/a-samples", false)
    {tests, []} = Code.eval_file("test/data/a-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type and rdmap.ip should exist
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :ip) end)
      assert Enum.all?(resp.answer, fn a -> :ip4 == Pfx.type(a.rdmap.ip) end)
    end
  end

  test "AAAA RR - decode" do
    :ok = ensure_testfile("test/data/aaaa-samples", false)
    {tests, []} = Code.eval_file("test/data/aaaa-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type and
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :ip) end)
      assert Enum.all?(resp.answer, fn a -> :ip6 == Pfx.type(a.rdmap.ip) end)
    end
  end

  test "CNAME RR - decode" do
    :ok = ensure_testfile("test/data/cname-samples", false)
    {tests, []} = Code.eval_file("test/data/cname-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :name) end)
    end
  end

  test "DNSKEY RR - decode" do
    :ok = ensure_testfile("test/data/dnskey-samples", false)
    {tests, []} = Code.eval_file("test/data/dnskey-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type and
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :pubkey) end)
    end
  end

  test "DS RR - decode" do
    :ok = ensure_testfile("test/data/ds-samples", false)
    {tests, []} = Code.eval_file("test/data/ds-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0, "#{name}, #{type} has #{resp.header.anc} answers"
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
    end
  end

  test "NS RR - decode" do
    :ok = ensure_testfile("test/data/ns-samples", false)
    {tests, []} = Code.eval_file("test/data/ns-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :name) end)
    end
  end

  test "RRSIG RR - decode" do
    :ok = ensure_testfile("test/data/rrsig-samples", false)
    {tests, []} = Code.eval_file("test/data/rrsig-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
    end
  end

  test "SOA RR - decode" do
    :ok = ensure_testfile("test/data/soa-samples", false)
    {tests, []} = Code.eval_file("test/data/soa-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :mname) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :rname) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :serial) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :refresh) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :retry) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :expire) end)
      assert Enum.all?(resp.answer, fn a -> Map.has_key?(a.rdmap, :minimum) end)
    end
  end

  test "TXT RR - decode" do
    :ok = ensure_testfile("test/data/txt-samples", false)
    {tests, []} = Code.eval_file("test/data/txt-samples")

    for {name, type, _output, wiredata} <- tests do
      resp = DNS.Msg.decode(wiredata)

      # check everything was decoded
      assert resp.wdata == wiredata

      # header is first 12 bytes
      assert 12 == byte_size(resp.header.wdata)
      assert :binary.part(wiredata, {0, 12}) == resp.header.wdata

      # All questions should list given name, type
      assert Enum.all?(resp.question, fn q -> q.name == name end)
      assert Enum.all?(resp.question, fn q -> q.type == type end)

      # all answers should list given name, type
      assert resp.header.anc > 0, "#{name}, #{type} has #{resp.header.anc} answers"
      assert Enum.all?(resp.answer, fn a -> a.name == name end)
      assert Enum.all?(resp.answer, fn a -> a.type == type end)
    end
  end
end
