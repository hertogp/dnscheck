defmodule DNS.CacheTest do
  use ExUnit.Case
  doctest DNS.Cache, import: true

  alias DNS.Cache
  alias DNS.Utils
  alias DNS.Msg.RR

  @cache :dns_cache

  setup do
    assert @cache == Cache.init()
    assert 0 == :ets.tab2list(@cache) |> length
    :ok
  end

  test "init/0 clears the cache" do
    rr = RR.new(name: "example.com", ttl: 100)
    assert Cache.put(rr)
    assert 1 == Cache.size()
    Cache.init()
    assert 0 == Cache.size()
  end

  test "get/3 won't serve stale entries" do
    rr = RR.new(name: "example.com", type: :A, ttl: 1)
    assert Cache.put(rr)
    assert 1 == Cache.size()

    # stale entries are removed during retrieval
    Utils.wait(1100)
    assert 1 == Cache.size()
    assert [] == Cache.get("example.com", :IN, :A)
    assert 0 == Cache.size()
  end

  test "get/3 adjusts RR's TTL before serving" do
    rr = RR.new(name: "example.com", type: :A, ttl: 10)
    assert Cache.put(rr)
    assert 1 == Cache.size()

    Utils.wait(1100)
    assert 1 == Cache.size()
    [rr2] = Cache.get("example.com", :IN, :A)
    assert rr.ttl > rr2.ttl
  end

  test "get/3 returns [] if input is invalid" do
    # this won't even touch the cache
    assert [] == Cache.get("example.com", :IN, 65536)
    assert [] == Cache.get("example.com", 65536, :A)
  end

  test "get/put use keys with normalized domain names" do
    assert 0 == DNS.Cache.size()
    rr = RR.new(name: "eXamPlE.cOm", type: :A, ttl: 10)
    assert Cache.put(rr)
    [rr] = Cache.get("example.com", :IN, :A)
    assert "eXamPlE.cOm" == rr.name

    # search case
    [rr] = Cache.get("EXAMPLE.COM", :IN, :A)
    assert "eXamPlE.cOm" == rr.name

    # search name with trailing dot
    [rr] = Cache.get("example.com.", :IN, :A)
    assert "eXamPlE.cOm" == rr.name
  end

  test "get/put preserve RR's name" do
    assert 0 == DNS.Cache.size()

    # trailing dot in cached name
    rr = RR.new(name: "eXamPlE.cOm.", type: :A, ttl: 10, rdmap: %{ip: "10.1.1.1"})
    assert "eXamPlE.cOm." == rr.name
    assert Cache.put(rr)

    # search with/without trailing dot
    [rr] = Cache.get("example.com", :IN, :A)
    assert "eXamPlE.cOm." == rr.name

    [rr] = Cache.get("example.com.", :IN, :A)
    assert "eXamPlE.cOm." == rr.name
  end

  test "get/put store RR's with/without trailing dot under the same key" do
    assert 0 == Cache.size()
    # trailing dot
    rr = RR.new(name: "eXamPlE.cOm.", type: :A, ttl: 10, rdmap: %{ip: "10.1.1.1"})
    assert "eXamPlE.cOm." == rr.name
    assert Cache.put(rr)
    # no trailing dot
    rr = RR.new(name: "example.com", type: :A, ttl: 20, rdmap: %{ip: "10.2.1.1"})
    assert Cache.put(rr)
    assert 1 == Cache.size()
    rrs = Cache.get("ExAmPlE.com", :IN, :A)
    assert 2 == length(rrs)
  end

  test "put/1 wipes wiredata from non-raw RR's" do
    rr = RR.new(name: "example.com", ttl: 100)
    rr = %{rr | rdata: "non-sense", wdata: "more non-sense"}
    assert Cache.put(rr)
    [rr2] = Cache.get("example.com", :IN, :A)
    assert 0 == byte_size(rr2.rdata)
    assert 0 == byte_size(rr2.wdata)
  end

  test "put/1 does NOT wipe wiredata from raw RR's" do
    rr = RR.new(name: "example.com", ttl: 100)
    rr = %{rr | rdata: "non-sense", wdata: "more non-sense", raw: true}
    assert Cache.put(rr)
    [rr2] = Cache.get("example.com", :IN, :A)
    assert "non-sense" == rr2.rdata
    assert "more non-sense" == rr2.wdata
  end

  test "put/1 ignores QTYPEs and pseudo types" do
    for type <- [:OPT, :ANY, :IXFR, :AXFR, :*, :MAILA, :MAILB] do
      rr = RR.new(name: "example.com", ttl: 100, type: type)
      refute Cache.put(rr)
    end
  end

  test "put/1 reports :error for invalid input" do
    rr = RR.new(name: "example.com", ttl: 100)
    refute Cache.put(%{rr | type: 65536})
    refute Cache.put(%{rr | class: 65536})
  end

  test "put/1 ignores TTL's < 1" do
    rr = RR.new(name: "example.com", ttl: 0)
    refute Cache.put(rr)
    refute Cache.put(%{rr | ttl: -1111})
  end

  test "put/1 replaces existing RR's" do
    rr = RR.new(name: "example.com", ttl: 1000)
    assert Cache.put(rr)

    for n <- 1..100,
        do: assert(Cache.put(%{rr | ttl: rr.ttl + n}))

    [rr] = Cache.get("example.com", :IN, :A)
    assert "example.com" == rr.name
    assert rr.ttl > 1000
    assert 1 == Cache.size()
  end

  test "put/1 ignores authority/additional sections when msg has answers" do
    # remember that TTL must be > 1, or it'll get :ignored
    qtn = [[name: "example.com", type: :A]]

    ans = [
      [name: "example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.1"}],
      [name: "example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.2"}]
    ]

    aut = [
      [name: "com", type: :NS, ttl: 100, rdmap: %{name: "ns1.example.com"}],
      [name: "com", type: :NS, ttl: 100, rdmap: %{name: "ns2.example.com"}]
    ]

    add = [
      [name: "ns1.example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.3"}],
      [name: "ns2.example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.4"}]
    ]

    {:ok, msg} = DNS.Msg.new(qtn: qtn, ans: ans, aut: aut, add: add)
    assert Cache.put(msg)
    rrs = Cache.get("example.com", :IN, :A)
    assert 2 == length(rrs)
    assert 1 == Cache.size()
    assert [] == Cache.get("com", :IN, :NS)
    assert [] == Cache.get("ns1.example.com", :IN, :A)
    assert [] == Cache.get("ns2.example.com", :IN, :A)
  end

  test "put/1 ignores RR's in answer section if not relevant to the qname" do
    # remember that TTL must be > 1, or it'll get :ignored
    qtn = [[name: "example.com", type: :A]]

    ans = [
      [name: "example.net", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.1"}],
      [name: "example.net", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.2"}]
    ]

    aut = [
      [name: "com", type: :NS, ttl: 100, rdmap: %{name: "ns1.example.com"}],
      [name: "com", type: :NS, ttl: 100, rdmap: %{name: "ns2.example.com"}]
    ]

    add = [
      [name: "ns1.example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.3"}],
      [name: "ns2.example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.4"}]
    ]

    # since msg.answers is not empty, authority/additional get ignored
    {:ok, msg} = DNS.Msg.new(qtn: qtn, ans: ans, aut: aut, add: add)
    assert Cache.put(msg)
    rrs = Cache.get("example.com", :IN, :A)
    assert 0 == length(rrs)
    assert 0 == Cache.size()
    assert [] == Cache.get("com", :IN, :NS)
    assert [] == Cache.get("ns1.example.com", :IN, :A)
    assert [] == Cache.get("ns2.example.com", :IN, :A)
  end

  test "put/1 ignores RR's in authority/additional section if not relevant to qname" do
    # remember that TTL must be > 1, or it'll get :ignored
    qtn = [[name: "example.com", type: :A]]

    aut = [
      [name: "com", type: :NS, ttl: 100, rdmap: %{name: "ns1.example.com"}],
      [name: "net", type: :NS, ttl: 100, rdmap: %{name: "ns2.example.net"}]
    ]

    add = [
      [name: "ns1.example.com", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.3"}],
      [name: "ns2.example.net", type: :A, ttl: 100, rdmap: %{ip: "10.1.1.4"}]
    ]

    # since msg.answers is empty, cache only relevant RR's from authority/additional
    {:ok, msg} = DNS.Msg.new(qtn: qtn, aut: aut, add: add)
    assert Cache.put(msg)
    assert [] == Cache.get("example.com", :IN, :A)
    [ns] = Cache.get("com", :IN, :NS)
    assert "com" == ns.name
    assert "ns1.example.com" == ns.rdmap.name
    # cached only the right NS and A records (i.e. 2)
    assert 2 == Cache.size()
    [rr] = Cache.get("ns1.example.com", :IN, :A)
    assert "10.1.1.3" == rr.rdmap.ip
    assert [] == Cache.get("ns2.example.net", :IN, :A)
  end

  test "size/0 returns either size or :error" do
    assert 0 == Cache.size()
    assert true == :ets.delete(:dns_cache)
    assert :undefined == Cache.size()
  end
end
