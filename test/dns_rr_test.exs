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
  # [[ All types of RRs ]]
  #
  test "wiredata samples" do
    # get large set of wiredata samples
    samples = wire_samples()
    assert length(samples) > 0, "no wiredata samples found"

    for {name, type, output, wiredata} <- samples do
      resp = DNS.Msg.decode(wiredata)
      assert %DNS.Msg{} = resp, "failed for #{name}, #{type}"
      # basic value test
      id = List.first(output) |> String.split(" ") |> List.last()
      assert id == "#{resp.header.id}"
      # all wiredata was read
      assert wiredata == resp.wdata
      # basic struct consistency checks
      assert resp.header.qdc == length(resp.question)
      assert resp.header.anc == length(resp.answer)
      assert resp.header.nsc == length(resp.authority)
      assert resp.header.arc == length(resp.additional)
      # always 1 question
      assert 1 == resp.header.qdc
      q = hd(resp.question)
      assert name == q.name
      assert type == q.type
      # answer, authority & additional need individual testing
    end
  end

  #
  # [[ DECODE RR answers ]]
  #
  # - see test/data/<type>-domain-sample for values used in assert's
  # - if a sample is "renewed" by forced: true -> DNS might have changed
  #   in which case the corresponding test needs updating.
  #

  test "A RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :A)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 27830 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 2583 == rr.ttl
    assert "93.184.216.34" = rr.rdmap.ip
  end

  test "AAAA RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :AAAA)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 54473 = resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert "2606:2800:220:1:248:1893:25c8:1946" = rr.rdmap.ip
    assert 19877 == rr.ttl
    assert :AAAA == rr.type
  end

  test "CAA RR" do
    {name, type, _output, wiredata} = get_sample("google.nl", :CAA)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 29394 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 21221 == rr.ttl
    assert 0 == rr.rdmap.flags
    assert "issue" == rr.rdmap.tag
    assert "pki.goog" == rr.rdmap.value
  end

  test "CDNSKEY RR" do
    {name, type, _output, wiredata} = get_sample("dnsimple.zone", :CDNSKEY)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 24524 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 1224 == rr.ttl
    assert 257 == rr.rdmap.flags
    assert 8 == rr.rdmap.algo
    assert 3 == rr.rdmap.proto

    assert Base.encode64(rr.rdmap.pubkey) ==
             "AwEAAc0xuREyeyj25dvdUQs+xqfnzCouowntvy+vEnsJCqxMt6QHS7Omn7laGOgHDjko9UN/ggYxt5Dq7QVn8kJ3cDqTnPdY2kQ+Mscf1t0axcu3Z4ykloX1VrXJdlsiEymVuNn2ztb1bAfYlj2t5Po8QczL8S8eGmVsiRZCp7XoYBYUg/5sD9hSITvtPbrXqU/bdx94zWEiI/Xb9tLvNTJZnzE="

    # note drill output show no keytag nor type of key?
  end

  test "CDS RR" do
    {name, type, _output, wiredata} = get_sample("dnsimple.zone", :CDS)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 24465 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == resp.header.anc, "no answer RRs"
    rr = hd(resp.answer)
    assert name == rr.name
    assert 880 == rr.ttl
    assert type == rr.type
    assert 8 == rr.rdmap.algo
    assert 18760 == rr.rdmap.keytag
    assert 2 == rr.rdmap.type

    assert Base.encode16(rr.rdmap.digest, case: :lower) ==
             "e43ac6692f70b6ed3dd4021a22610a6213400b11bffc955e13784b315f0e0636"
  end

  test "CNAME RR" do
    {name, type, _output, wiredata} = get_sample("www.sidn.nl", :CNAME)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 59056 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 882 == rr.ttl
    assert "sidn.nl" == rr.rdmap.name
  end

  test "DNSKEY RR" do
    {name, type, _output, wiredata} = get_sample("internet.nl", :DNSKEY)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 1320 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert 257 == rr.rdmap.flags
    assert 13 == rr.rdmap.algo
    assert 3 == rr.rdmap.proto
    assert 22707 == rr.rdmap.keytag
    assert "ksk" == rr.rdmap.type

    assert Base.encode64(rr.rdmap.pubkey) ==
             "QA3dnKfJvTjvncs3FercMXITNIcpTwRA1aq+KaQF/VEbvWOBH90TZxgLuAwoh8/+s5/ayhkJiJ9VTY9BBciGJg=="
  end

  test "DS RR" do
    {name, type, _output, wiredata} = get_sample("internet.nl", :DS)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 17034 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 1674 == rr.ttl
    assert 13 == rr.rdmap.algo
    assert 22707 == rr.rdmap.keytag
    assert 2 == rr.rdmap.type

    assert Base.encode16(rr.rdmap.digest, case: :lower) ==
             "a69c3d2d414e4ef8ceaa66d39d90ed2b20ef36d9f4007d678cea0c0d803a0b7e"
  end

  test "MX RR" do
    {name, type, _output, wiredata} = get_sample("sidn.nl", :MX)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
  end

  test "NS RR" do
    {name, type, _output, wiredata} = get_sample("sidn.nl", :NS)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
  end

  test "NSEC RR" do
    {name, type, _output, wiredata} = get_sample("einbeispiel.ch", :NSEC)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
  end

  test "NSEC3 RR" do
    {name, type, _output, wiredata} = get_sample("x.example.com", :NSEC3)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    assert 0 == length(resp.answer)
    # rr = hd(resp.answer)
    # assert name == rr.name
    # assert type == rr.type
  end

  test "NSEC3PARAM RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :NSEC3PARAM, useD: true)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    assert 2 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
  end

  test "OPT RR" do
    {name, type, _output, wiredata} = get_sample("dnssec-failed.org", :OPT, useD: true)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    # answer
    # assert 1 == length(resp.answer)
    # rr = hd(resp.answer)
    # assert name == rr.name
    # assert type == rr.type
  end

  test "PTR RR" do
    {_name, _type, _output, wiredata} = get_sample("27.27.250.142.in-addr.arpa", :PTR)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert resp.header.anc > 0, "no answer RRs"
  end

  test "RRSIG RR" do
    {_name, _type, _output, wiredata} = get_sample("example.com", :RRSIG, useD: true)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert resp.header.anc > 0, "no answer RRs"
  end

  test "SOA RR" do
    {_name, _type, _output, wiredata} = get_sample("example.com", :SOA)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert resp.header.anc > 0, "no answer RRs"
  end

  test "TSLA" do
    {_name, _type, _output, wiredata} = get_sample("_25._tcp.esa.sidn.nl", :TLSA)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert resp.header.anc > 0, "no answer RRs"
  end

  test "TXT RR" do
    {_name, _type, _output, wiredata} = get_sample("example.com", :TXT)
    resp = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert resp.header.anc > 0, "no answer RRs"
  end
end
