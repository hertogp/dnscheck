defmodule DNS.Msg.QtnTest do
  use ExUnit.Case
  doctest DNS.Msg.Qtn, import: true

  import DNS.Msg.Qtn

  test "Decode a question" do
    # no name compression
    msg = <<"stuff", 7, "example", 3, "net", 0, 1::16, 1::16, "more stuff">>
    {offset, q} = decode(5, msg)
    assert 22 == offset
    assert "example.net" == q.name

    <<_::binary-size(offset), rest::binary>> = msg
    assert "more stuff" == rest

    # name compression
    msg = <<"stuff", 3, "net", 0, 7, "example", 192, 5, 1::16, 1::16, "more stuff">>
    {offset, q} = decode(10, msg)
    assert 24 == offset
    assert "example.net" == q.name
    <<_::binary-size(offset), rest::binary>> = msg
    assert "more stuff" == rest
  end

  test "Encode a question" do
    q = new(name: "example.COM", type: :A, class: :IN)
    assert q.name == "example.COM"
    assert q.type == :A
    assert q.class == :IN
    assert q.wdata == <<>>

    # case is preserved
    q = encode(q)
    assert q.name == "example.COM"
    assert q.type == :A
    assert q.class == :IN
    assert q.wdata == <<7, "example", 3, "COM", 0, 1::16, 1::16>>
  end

  test "new question" do
    # default values
    q = new()
    assert q.name == ""
    assert q.type == :A
    assert q.class == :IN
    assert q.wdata == <<>>

    # raises on illegal domain names
    assert_raise DNS.Msg.Error, fn -> new(name: "example.-com") end
    assert_raise DNS.Msg.Error, fn -> new(name: "example.com-") end
    assert_raise DNS.Msg.Error, fn -> new(name: "example.123") end
    assert_raise DNS.Msg.Error, fn -> new(name: 123) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> new(type: 65536) end
    assert_raise DNS.Msg.Error, fn -> new(class: 65536) end

    # manual override of name and encoding is possible
    q = %{new() | name: "example.123"}
    assert q.name == "example.123"
    q = encode(q)
    assert q.wdata == <<7, "example", 3, "123", 0, 1::16, 1::16>>

    q = %{new() | name: 123}
    assert q.name == 123
    assert_raise DNS.Msg.Error, fn -> encode(q) end

    # encoding numbers cannot be overridden
    q = %{new() | type: 65536}
    assert_raise DNS.Msg.Error, fn -> encode(q) end
    q = %{new() | class: 65536}
    assert_raise DNS.Msg.Error, fn -> encode(q) end

    # ignores unknown options
    q = new(foo: :bar)
    assert q.name == ""
    assert q.type == :A
    assert q.class == :IN
    assert q.wdata == <<>>
  end

  test "Put in a value" do
    q = new()
    assert q.name == ""
    q = put(q, name: "example.com")
    q = put(q, type: :NS)
    q = put(q, class: :CH)
    assert q.name == "example.com"
    assert q.type == :NS
    assert q.class == :CH

    # raises on illegal name and numbers
    q = new()
    assert_raise DNS.Msg.Error, fn -> put(q, name: "example.123") end
    assert_raise DNS.Msg.Error, fn -> put(q, name: 123) end
    assert_raise DNS.Msg.Error, fn -> put(q, type: 65536) end
    assert_raise DNS.Msg.Error, fn -> put(q, class: 65536) end
  end
end
