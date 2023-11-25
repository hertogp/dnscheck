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
end
