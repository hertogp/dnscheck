defmodule DNS.Msg.RRTest do
  use ExUnit.Case
  doctest DNS.Msg.RR, import: true

  alias DNS.Msg.RR
  import Drill

  test "RR - new" do
    # input validation
    assert_raise DNS.MsgError, fn -> RR.new(type: 65536) end
    assert_raise DNS.MsgError, fn -> RR.new(type: -1) end
    assert_raise DNS.MsgError, fn -> RR.new(class: 65536) end
    assert_raise DNS.MsgError, fn -> RR.new(class: -1) end
    assert_raise DNS.MsgError, fn -> RR.new(ttl: 4_294_967_296) end
    assert_raise DNS.MsgError, fn -> RR.new(rdmap: []) end
    assert_raise DNS.MsgError, fn -> RR.new(name: "example.123") end
    assert_raise DNS.MsgError, fn -> RR.new(name: "example.-om") end
    assert_raise DNS.MsgError, fn -> RR.new(name: "example.co-") end
    label_too_long = String.duplicate("a", 64)
    assert_raise DNS.MsgError, fn -> RR.new(name: label_too_long <> ".com") end
    name_too_long = String.duplicate("aa", 84) |> String.replace("aa", "a.a") |> Kernel.<>(".a")
    assert 254 == String.length(name_too_long)
    assert_raise DNS.MsgError, fn -> RR.new(name: name_too_long) end

    # new accepts :rdata, sets :raw to true, ignores :wdata
    rr = RR.new(rdlen: 7, rdata: <<"not-ignored">>, wdata: <<"ignored">>)
    assert String.length("not-ignored") == rr.rdlen
    assert "not-ignored" == rr.rdata
    assert rr.raw == true
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
    assert_raise DNS.MsgError, fn -> RR.put(rr, type: 65536) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, type: -1) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, type: "A") end
    assert_raise DNS.MsgError, fn -> RR.put(rr, type: :a) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, class: 65536) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, class: -1) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, ttl: 4_294_967_296) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, rdmap: []) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, name: "example.123") end
    assert_raise DNS.MsgError, fn -> RR.put(rr, name: "example.-om") end
    assert_raise DNS.MsgError, fn -> RR.put(rr, name: "example.co-") end
    label_too_long = String.duplicate("a", 64)
    assert_raise DNS.MsgError, fn -> RR.put(rr, name: label_too_long <> ".com") end
    name_too_long = String.duplicate("aa", 84) |> String.replace("aa", "a.a") |> Kernel.<>(".a")
    assert 254 == String.length(name_too_long)
    assert_raise DNS.MsgError, fn -> RR.put(rr, name: name_too_long) end

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
    assert_raise DNS.MsgError, fn -> RR.new() |> RR.encode() end
    assert_raise DNS.MsgError, fn -> RR.new(rdmap: %{}) |> RR.encode() end
    assert_raise DNS.MsgError, fn -> RR.new(type: :A, rdmap: %{ip: "acdc::"}) |> RR.encode() end

    assert_raise DNS.MsgError, fn ->
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
    assert_raise DNS.MsgError, fn -> RR.put(rr, xrcode: 256) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, version: 256) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, do: 2) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, z: 32768) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, bufsize: 65536) end
    assert_raise DNS.MsgError, fn -> RR.put(rr, opts: %{}) end
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

    assert_raise DNS.MsgError, fn ->
      RR.new(type: :OPT, opts: [{:EXPIRE, 2 ** 32}]) |> RR.encode()
    end

    assert_raise DNS.MsgError, fn ->
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
    assert_raise DNS.MsgError, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {"1234567", "87654321"}}]) |> RR.encode()
    end

    cookie_too_short = "1234567"

    assert_raise DNS.MsgError, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {cookie_too_short, "87654321"}}]) |> RR.encode()
    end

    assert_raise DNS.MsgError, fn ->
      RR.new(type: :OPT, opts: [{:COOKIE, {"12345678", cookie_too_short}}]) |> RR.encode()
    end

    cookie_too_long = String.duplicate("a", 33)

    assert_raise DNS.MsgError, fn ->
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
      {:ok, resp} = DNS.Msg.decode(wiredata)
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
    {:ok, resp} = DNS.Msg.decode(wiredata)
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
    {:ok, resp} = DNS.Msg.decode(wiredata)
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

  test "AFSDB RR" do
    {name, type, _output, wiredata} = get_sample("afsdb.dns.netmeister.org", :AFSDB)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 4707 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert 1 == rr.rdmap.type
    assert "panix.netmeister.org" == rr.rdmap.name
    # apparently, no name compression is used here
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "AMTRELAY RR" do
    # drill doesnt know AMTRELAY as mnemonic, so use TYPE260
    {name, _type, _output, wiredata} = get_sample("amtrelay.dns.netmeister.org", "TYPE260")

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 62613 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert :AMTRELAY == rr.type
    assert 3600 == rr.ttl
    assert 10 == rr.rdmap.pref
    assert 0 == rr.rdmap.d
    assert 2 == rr.rdmap.type
    assert "2001:470:30:84:e276:63ff:fe72:3900" == rr.rdmap.relay
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "CAA RR" do
    {name, type, _output, wiredata} = get_sample("google.nl", :CAA)
    {:ok, resp} = DNS.Msg.decode(wiredata)
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
    {:ok, resp} = DNS.Msg.decode(wiredata)
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
    {:ok, resp} = DNS.Msg.decode(wiredata)
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

  test "CERT RR" do
    {name, type, _output, wiredata} = get_sample("cert.dns.netmeister.org", :CERT, useD: true)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 20547 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 4 == length(resp.answer)
    rr = Enum.at(resp.answer, 2)
    assert name == rr.name
    assert type == rr.type
    assert 3337 == rr.ttl
    assert 6 == rr.rdmap.type
    assert 0 == rr.rdmap.keytag
    assert 0 == rr.rdmap.algo
    assert "99CE1DC7770AC5A809A60DCD66CE4FE96F6BD3D7" == Base.encode64(rr.rdmap.cert)
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "CNAME RR" do
    {name, type, _output, wiredata} = get_sample("www.sidn.nl", :CNAME)
    {:ok, resp} = DNS.Msg.decode(wiredata)
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

  test "DNAME RR" do
    {name, type, _output, wiredata} = get_sample("dname.dns.netmeister.org", :DNAME)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 53721 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "dns.netmeister.org" == rr.rdmap.dname
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "CSYNC RR" do
    {name, type, _output, wiredata} = get_sample("csync.dns.netmeister.org", :CSYNC)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 10012 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert 2_021_071_001 == rr.rdmap.soa_serial
    assert 3 == rr.rdmap.flags
    assert [:NS] == rr.rdmap.covers
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "DNSKEY RR" do
    {name, type, _output, wiredata} = get_sample("internet.nl", :DNSKEY)
    {:ok, resp} = DNS.Msg.decode(wiredata)
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
    assert 22707 == rr.rdmap._keytag
    assert "ksk" == rr.rdmap._type

    assert Base.encode64(rr.rdmap.pubkey) ==
             "QA3dnKfJvTjvncs3FercMXITNIcpTwRA1aq+KaQF/VEbvWOBH90TZxgLuAwoh8/+s5/ayhkJiJ9VTY9BBciGJg=="
  end

  test "DS RR" do
    {name, type, _output, wiredata} = get_sample("internet.nl", :DS)
    {:ok, resp} = DNS.Msg.decode(wiredata)
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

  test "IPSECKEY RR" do
    {name, type, _output, wiredata} = get_sample("twokeys.libreswan.org", :IPSECKEY, useD: true)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 42737 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 3 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert :IN == rr.class
    assert type == rr.type
    assert 481 == rr.rdlen
    assert 10 == rr.rdmap.pref
    assert 2 == rr.rdmap.algo
    assert 0 == rr.rdmap.gw_type
    assert "" == rr.rdmap.gateway

    assert "AQPO39yuENlW1FvoF8mLxRszJfO63zT6k3kRmo7Ja1ptQB7T+lb6yfgUZToVFmaVV6uZrSGNTYu1CmyirMJbnxyFDhKmEg4KOgMuV3CDTRUMd6vJMQtYhiWAahV9pvwtkEi3Yer8nxDktWl5diUoJeQWq7IPn61xcj75/FoKqavg4YH1bqpN6cgbU2qMn04vSNNKQj0e3ToHHHIdTTPqvb5244UlDv7S7YdvuunfdSt/hsF+8wUz2wcDxRfWNL4ES7qagT7awGHHg/4XYr8ARt+kupRodsaTOR9nxp4VfE87iwR+qGSUd9DBl65wvZItbjrIqyexF0PE8UgjXVUWREHd3J51iNx4ft//vH7ItYPuOM2EXGJvYJ+GLk+JiOOMSC3X3YK7xC4bOv9+fiP0dA7pFLy0diNDt+9KMEUHDNtwx5KyvPoXk4Kr0c0weAagj+xY0NjxwubswCXHEd2URGSFW0BuLDuyl82TI2ZpiWGiCgY/B/x/xdKJbp1PBua8PnO3DgLe01mPgAgHGAJMzf22ZF+raFxNag4lbPQzGwM7f/W1YqLHI4BGeg3kd9krXfKKlFpyKtWcQeDonG2tfrNP8GvWDbIahrP1SbusKD6UfVA4FDB5VoZK8MeE6w==" ==
             Base.encode64(rr.rdmap.pubkey)

    # can't compare wdata since we donot do name compression.
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "ISDN RR" do
    {name, type, _output, wiredata} = get_sample("isdn.dns.netmeister.org", :ISDN)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 11650 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3049 == rr.ttl
    assert "150862028003217" == rr.rdmap.address
    assert "004" == rr.rdmap.sa
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "KX RR" do
    {name, type, _output, wiredata} = get_sample("kx.dns.netmeister.org", :KX)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 57000 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert 1 == rr.rdmap.pref
    assert "panix.netmeister.org" == rr.rdmap.name
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "MB RR" do
    {name, type, _output, wiredata} = get_sample("mb.dns.netmeister.org", :MB)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 10231 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "panix.netmeister.org" == rr.rdmap.name
    # for when we do name compression some day
    # rr2 = DNS.Msg.RR.encode(rr)
    # assert rr.rdata == rr2.rdata
  end

  test "MG RR" do
    # omg: google's 8.8.8.8 doesn't do MG
    {name, type, _output, wiredata} = get_sample("mg.dns.netmeister.org", :MG, ns: "166.84.7.99")

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 4254 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 3 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "jschauma.yahoo.com" == rr.rdmap.name
    # for when we do name compression some day
    # rr2 = DNS.Msg.RR.encode(rr)
    # assert rr.rdata == rr2.rdata
  end

  test "MR RR" do
    {name, type, _output, wiredata} = get_sample("mr.dns.netmeister.org", :MR)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 46657 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "panix.netmeister.org" == rr.rdmap.name
    # for when we do name compression some day
    # rr2 = DNS.Msg.RR.encode(rr)
    # assert rr.rdata == rr2.rdata
  end

  test "MINFO RR" do
    # omg: google's 8.8.8.8 doesn't do MG
    {name, type, _output, wiredata} = get_sample("minfo.dns.netmeister.org", :MINFO)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 35568 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3544 == rr.ttl
    assert "jschauma.netmeister.org" == rr.rdmap.rmailbx
    assert "postmaster.netmeister.org" == rr.rdmap.emailbx
    # for when we do name compression some day
    # rr2 = DNS.Msg.RR.encode(rr)
    # assert rr.rdata == rr2.rdata
  end

  test "MX RR" do
    {name, type, _output, wiredata} = get_sample("sidn.nl", :MX)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 30869 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 300 == rr.ttl
    assert 5 == rr.rdmap.pref
    assert "esa.sidn.nl" == rr.rdmap.name
  end

  test "NS RR" do
    {name, type, _output, wiredata} = get_sample("sidn.nl", :NS)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 4442 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 3 == length(resp.answer)

    for rr <- resp.answer do
      assert name == rr.name
      assert type == rr.type
      assert 3220 == rr.ttl
      assert String.match?(rr.rdmap.name, ~r/ns\d\.sidn\.nl/)
    end
  end

  test "NSEC RR" do
    {name, type, _output, wiredata} = get_sample("einbeispiel.ch", :NSEC)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 8916 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 900 == rr.ttl
    assert "einbettung.ch" == rr.rdmap.name
    assert 4 == length(rr.rdmap.covers)
    assert :NS in rr.rdmap.covers
    assert :DS in rr.rdmap.covers
    assert :RRSIG in rr.rdmap.covers
    assert :NSEC in rr.rdmap.covers
  end

  test "NSEC3 RR" do
    {_name, type, _output, wiredata} = get_sample("x.example.com", :NSEC3, useD: true)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 33209 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 0 == length(resp.answer)
    assert 6 == length(resp.authority)
    rrs = Enum.filter(resp.authority, fn rr -> rr.type == :NSEC3 end)

    for rr <- rrs do
      assert String.ends_with?(rr.name, "example.com")
      assert type == rr.type
      assert 3570 == rr.ttl
      # these are the same for both NSEC3s:
      assert 1 == rr.rdmap.algo
      assert 0 == rr.rdmap.flags
      assert 5 == rr.rdmap.iterations
      assert 8 == rr.rdmap.salt_len

      case length(rr.rdmap.covers) do
        4 ->
          assert [:A, :TXT, :AAAA, :RRSIG] == rr.rdmap.covers

        _ ->
          assert [:A, :NS, :SOA, :MX, :TXT, :AAAA, :RRSIG, :DNSKEY, :NSEC3PARAM] ==
                   rr.rdmap.covers
      end
    end
  end

  test "NSEC3PARAM RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :NSEC3PARAM, useD: true)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 16829 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 2 == length(resp.answer)
    rr = Enum.filter(resp.answer, fn rr -> rr.type == type end) |> hd()
    assert name == rr.name
    assert type == rr.type
    assert 0 == rr.ttl
    assert 1 == rr.rdmap.algo
    assert 0 == rr.rdmap.flags
    assert 5 == rr.rdmap.iterations
    assert 8 == rr.rdmap.salt_len
    assert "b0148fa0b0ab23b8" == Base.encode16(rr.rdmap.salt, case: :lower)
  end

  test "NULL RR" do
    {name, type, _output, wiredata} = get_sample("null.dns.netmeister.org", :NULL)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 50474 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "avocado" == rr.rdmap.data
    # for when we do name compression some day
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "OPENPGPKEY RR" do
    {name, type, _output, wiredata} =
      get_sample("openpgpkey.dns.netmeister.org", :OPENPGPKEY, useD: true)

    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 20232 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 2 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert true == rr.raw
  end

  test "OPT RR" do
    {_name, type, _output, wiredata} = get_sample("dnssec-failed.org", :OPT, useD: true)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 59961 == resp.header.id, "sample was updated, need to update test!"
    assert :SERVFAIL == resp.header.rcode
    assert 0 == length(resp.answer)
    assert 0 == length(resp.authority)
    # additional answer
    assert 1 == length(resp.additional)
    rr = hd(resp.additional)
    assert "" == rr.name
    assert type == rr.type
    assert 512 == rr.rdmap.bufsize
    assert 1 == rr.rdmap.do
    assert 0 == rr.rdmap.version
    assert 0 == rr.rdmap.z
    assert :NOERROR == rr.rdmap.xrcode
    assert length(rr.rdmap.opts) > 0
    # TODO: decode EXTENDED_DNS_ERRORs and test values here
  end

  test "PTR RR" do
    {name, type, _output, wiredata} = get_sample("27.27.250.142.in-addr.arpa", :PTR)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 43852 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 1857 == rr.ttl
    # add trailing dot, since that will have been stripped
    assert "ra-in-f27.1e100.net." == rr.rdmap.name <> "."
  end

  test "HINFO RR" do
    {name, _type, _output, wiredata} = get_sample("cloudflare.com", :ANY)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 9711 == resp.header.id, "sample was updated, need to update test!"
    assert 2 == length(resp.answer)
    rr = Enum.filter(resp.answer, fn rr -> rr.type == :HINFO end) |> hd
    assert name == rr.name
    assert :HINFO == rr.type
    assert "RFC8482" == rr.rdmap.cpu
    assert "" == rr.rdmap.os
  end

  test "RP RR" do
    {name, type, _output, wiredata} = get_sample("rp.dns.netmeister.org", :RP)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 28153 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "jschauma.netmeister.org" == rr.rdmap.mail
    assert "contact.netmeister.org" == rr.rdmap.txt
    # apparently, no name compression is used here
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "RRSIG RR" do
    {name, _type, _output, wiredata} = get_sample("example.com", :RRSIG, useD: true)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 6603 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 8 == length(resp.answer)
    rr = Enum.filter(resp.answer, fn rr -> rr.rdmap.type == :A end) |> hd
    assert name == rr.rdmap.name
    assert :A == rr.rdmap.type
    assert 86400 == rr.rdmap.ttl
    assert 13 == rr.rdmap.algo
    assert 2 == rr.rdmap.labels
    assert 46981 == rr.rdmap.keytag
    assert 1_700_302_601 == rr.rdmap.notbefore
    assert 1_702_095_730 == rr.rdmap.notafter

    assert "MJeJSwqWFQqlcX0DHEUnzR3FLxm/dQK3kLxsiHymrkMBbMlCqb2QEq/FaniudjXilnwBxn9yXu/PLGJ2g1T6Eg==" ==
             Base.encode64(rr.rdmap.signature)
  end

  test "RT RR" do
    {name, type, _output, wiredata} = get_sample("rt.dns.netmeister.org", :RT)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 24964 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "panix.netmeister.org" == rr.rdmap.name
    assert 10 == rr.rdmap.pref
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "SOA RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :SOA)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 62121 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "ns.icann.org" == rr.rdmap.mname
    assert "noc.dns.icann.org" == rr.rdmap.rname
    assert 2_022_091_367 == rr.rdmap.serial
    assert 7200 == rr.rdmap.refresh
    assert 3600 == rr.rdmap.retry
    assert 1_209_600 == rr.rdmap.expire
    assert 3600 == rr.rdmap.minimum
  end

  test "SRV RR" do
    {name, type, _output, wiredata} = get_sample("_sip._udp.sipgate.co.uk", :SRV)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 57124 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 1850 == rr.ttl
    assert 0 == rr.rdmap.prio
    assert 0 == rr.rdmap.weight
    assert 5060 == rr.rdmap.port
    assert "sipgate.co.uk" == rr.rdmap.target
    # only check rdata, due to name compression
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "SSHFP RR" do
    {name, type, _output, wiredata} = get_sample("salsa.debian.org", :SSHFP)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 7178 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 4 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert 600 == rr.ttl
    assert type == rr.type
    assert 1 == rr.rdmap.algo
    assert 1 == rr.rdmap.type

    assert "eaa6c147facf35bc49946d9e8b90e2235c7da361" ==
             Base.encode16(rr.rdmap.fp, case: :lower)

    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "TSLA" do
    {name, type, _output, wiredata} = get_sample("_25._tcp.esa.sidn.nl", :TLSA)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 26213 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 2742 == rr.ttl
    assert 3 == rr.rdmap.usage
    assert 1 == rr.rdmap.type
    assert 1 == rr.rdmap.selector

    assert "6ae547e04f4767c3d9fe27c49747ac8abc5b15bb304aaf712d9d50cb422b7cdd" ==
             Base.encode16(rr.rdmap.data, case: :lower)
  end

  test "TXT RR" do
    {name, type, _output, wiredata} = get_sample("example.com", :TXT)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 60410 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 2 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 9161 == rr.ttl
    assert ["v=spf1 -all"] == rr.rdmap.txt
  end

  test "URI RR" do
    {name, type, _output, wiredata} = get_sample("uri.dns.netmeister.org", :URI)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 26668 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert 10 == rr.rdmap.prio
    assert 1 == rr.rdmap.weight
    assert "https://www.netmeister.org/blog/dns-rrs.html" == rr.rdmap.target
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "WKS RR" do
    {name, type, _output, wiredata} = get_sample("wks.dns.netmeister.org", :WKS)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 1855 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 2 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "166.84.7.99" == rr.rdmap.ip
    # TODO: use result of decode_ip_proto in struct and test
    assert 17 == rr.rdmap.proto
    assert [53] == rr.rdmap.services
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "X25 RR" do
    {name, type, _output, wiredata} = get_sample("x25.dns.netmeister.org", :X25)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 40903 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert type == rr.type
    assert 3600 == rr.ttl
    assert "311061700956" == rr.rdmap.address
    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end

  test "ZONEMD RR" do
    {name, type, _output, wiredata} = get_sample("zonemd.dns.netmeister.org", :ZONEMD)
    {:ok, resp} = DNS.Msg.decode(wiredata)
    assert %DNS.Msg{} = resp
    assert 8222 == resp.header.id, "sample was updated, need to update test!"
    # answer
    assert 1 == length(resp.answer)
    rr = hd(resp.answer)
    assert name == rr.name
    assert 2866 == rr.ttl
    assert type == rr.type
    assert 2_021_071_219 == rr.rdmap.serial
    assert 1 == rr.rdmap.scheme
    assert 1 == rr.rdmap.algo

    assert "4274f6bc562cf8ce512b21aa0a4ccc1eb9f4faaaecd01642d0a07bdea890c8845849d6015cc590f54b0ac7e87b9e41ed" ==
             Base.encode16(rr.rdmap.digest, case: :lower)

    rr2 = DNS.Msg.RR.encode(rr)
    assert rr.rdata == rr2.rdata
  end
end
