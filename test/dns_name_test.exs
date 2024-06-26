defmodule DNS.NameTest do
  use ExUnit.Case
  doctest DNS.Name, import: true

  import DNS.Name

  test "DNAME - decode" do
    # normal case
    msg = "stuff" <> <<7, ?E, ?x, ?A, ?m, ?P, ?l, ?E, 3, ?c, ?O, ?m, 0>> <> "more stuff"
    assert {18, "ExAmPlE.cOm"} == decode(5, msg)
    <<_::binary-size(18), rest::binary>> = msg
    assert "more stuff" == rest

    # name compression, the <<192, 0>> points back to start
    msg = <<3, ?n, ?e, ?t, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>
    assert {15, "example.net"} == decode(5, msg)

    msg = <<3, ?n, ?e, ?t, 192, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>
    assert_raise DNS.MsgError, fn -> decode(6, msg) end

    # not <<0>> terminated, raises
    msg = "stuff" <> <<7, ?E, ?x, ?A, ?m, ?P, ?l, ?E, 3, ?c, ?O, ?m>> <> "more stuff"
    assert_raise DNS.MsgError, fn -> decode(5, msg) end
  end

  test "DNAME - to_labels" do
    # normal case
    assert ["example", "com"] == to_labels("example.com")

    # trailing dot is ignored
    assert ["example", "com"] == to_labels("example.com.")

    # case is preserved
    assert ["eXamPle", "CoM"] == to_labels("eXamPle.CoM.")

    # empty and root name have no labels
    assert [] == to_labels("")
    assert [] == to_labels(".")

    # donot raise on illegal tld's
    assert ["example", "123"] == to_labels("example.123")
    assert ["example", "-com"] == to_labels("example.-com")
    assert ["example", "com-"] == to_labels("example.com-")

    # raises on empty labels
    assert_raise DNS.MsgError, fn -> to_labels("example..com") end
    assert_raise DNS.MsgError, fn -> to_labels(".example.com") end
    assert_raise DNS.MsgError, fn -> to_labels("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.MsgError, fn -> to_labels(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.MsgError, fn -> to_labels(name) end
  end

  test "DNAME - valid?" do
    # normal cases
    assert true == valid?("")
    assert true == valid?(".")
    assert true == valid?("example.com")
    assert true == valid?("example.com.")
    assert true == valid?("example.c0m.")
    assert true == valid?("example.c-m.")
    assert true == valid?("_25._tcp.example.com")
    assert true == valid?("*.example.com")

    # tld errors
    assert false == valid?("example.-com")
    assert false == valid?("example.com-")
    assert false == valid?("example.-com-")
    assert false == valid?("example.--")
    assert false == valid?("example.123")
    assert false == valid?("example.c@m")

    # not ascii, but still valid! see rfc4343
    name = "example." <> <<128, 129>> <> ".com"
    assert true == valid?(name)
  end

  test "DNAME - encode" do
    # normal cases
    assert <<0>> == encode("")
    assert <<0>> == encode(".")
    assert <<7, "example", 3, "com", 0>> = encode("example.com")
    assert <<7, "eXampLe", 3, "cOm", 0>> = encode("eXampLe.cOm")

    # raises on empty labels
    assert_raise DNS.MsgError, fn -> encode("example..com") end
    assert_raise DNS.MsgError, fn -> encode(".example.com") end
    assert_raise DNS.MsgError, fn -> encode("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.MsgError, fn -> encode(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.MsgError, fn -> encode(name) end
  end

  test "DNAME - reverse" do
    # normal cases
    assert "com.example" == reverse("example.com")
    assert "com.example.www" == reverse("www.example.com")
    assert "com.example.www" == reverse("www.example.com.")

    # raises on empty labels
    assert_raise DNS.MsgError, fn -> reverse("example..com") end
    assert_raise DNS.MsgError, fn -> reverse(".example.com") end
    assert_raise DNS.MsgError, fn -> reverse("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.MsgError, fn -> reverse(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.MsgError, fn -> reverse(name) end
  end
end
