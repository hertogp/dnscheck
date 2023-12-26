defmodule DNS.UtilsTest do
  use ExUnit.Case
  doctest DNS.Utils, import: true

  import DNS.Utils

  test "DNAME - dname_decode" do
    # normal case
    msg = "stuff" <> <<7, ?E, ?x, ?A, ?m, ?P, ?l, ?E, 3, ?c, ?O, ?m, 0>> <> "more stuff"
    assert {18, "ExAmPlE.cOm"} == dname_decode(5, msg)
    <<_::binary-size(18), rest::binary>> = msg
    assert "more stuff" == rest

    # name compression, the <<192, 0>> points back to start
    msg = <<3, ?n, ?e, ?t, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>
    assert {15, "example.net"} == dname_decode(5, msg)

    msg = <<3, ?n, ?e, ?t, 192, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>
    assert_raise DNS.Msg.Error, fn -> dname_decode(6, msg) end

    # not <<0>> terminated, raises
    msg = "stuff" <> <<7, ?E, ?x, ?A, ?m, ?P, ?l, ?E, 3, ?c, ?O, ?m>> <> "more stuff"
    assert_raise DNS.Msg.Error, fn -> dname_decode(5, msg) end
  end

  test "DNAME - dname_to_labels" do
    # normal case
    assert ["example", "com"] == dname_to_labels("example.com")

    # trailing dot is ignored
    assert ["example", "com"] == dname_to_labels("example.com.")

    # case is preserved
    assert ["eXamPle", "CoM"] == dname_to_labels("eXamPle.CoM.")

    # empty and root name have no labels
    assert [] == dname_to_labels("")
    assert [] == dname_to_labels(".")

    # donot raise on illegal tld's
    assert ["example", "123"] == dname_to_labels("example.123")
    assert ["example", "-com"] == dname_to_labels("example.-com")
    assert ["example", "com-"] == dname_to_labels("example.com-")

    # raises on empty labels
    assert_raise DNS.Msg.Error, fn -> dname_to_labels("example..com") end
    assert_raise DNS.Msg.Error, fn -> dname_to_labels(".example.com") end
    assert_raise DNS.Msg.Error, fn -> dname_to_labels("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.Msg.Error, fn -> dname_to_labels(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.Msg.Error, fn -> dname_to_labels(name) end
  end

  test "DNAME - dname_valid?" do
    # normal cases
    assert true == dname_valid?("")
    assert true == dname_valid?(".")
    assert true == dname_valid?("example.com")
    assert true == dname_valid?("example.com.")
    assert true == dname_valid?("example.c0m.")
    assert true == dname_valid?("example.c-m.")
    assert true == dname_valid?("_25._tcp.example.com")
    assert true == dname_valid?("*.example.com")

    # tld errors
    assert false == dname_valid?("example.-com")
    assert false == dname_valid?("example.com-")
    assert false == dname_valid?("example.-com-")
    assert false == dname_valid?("example.--")
    assert false == dname_valid?("example.123")
    assert false == dname_valid?("example.c@m")

    # not ascii
    name = "example." <> <<128, 129>> <> ".com"
    assert false == dname_valid?(name)
  end

  test "DNAME - dname_encode" do
    # normal cases
    assert <<0>> == dname_encode("")
    assert <<0>> == dname_encode(".")
    assert <<7, "example", 3, "com", 0>> = dname_encode("example.com")
    assert <<7, "eXampLe", 3, "cOm", 0>> = dname_encode("eXampLe.cOm")

    # raises on empty labels
    assert_raise DNS.Msg.Error, fn -> dname_encode("example..com") end
    assert_raise DNS.Msg.Error, fn -> dname_encode(".example.com") end
    assert_raise DNS.Msg.Error, fn -> dname_encode("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.Msg.Error, fn -> dname_encode(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.Msg.Error, fn -> dname_encode(name) end
  end

  test "DNAME - dname_reverse" do
    # normal cases
    assert "com.example" == dname_reverse("example.com")
    assert "com.example.www" == dname_reverse("www.example.com")
    assert "com.example.www" == dname_reverse("www.example.com.")

    # raises on empty labels
    assert_raise DNS.Msg.Error, fn -> dname_reverse("example..com") end
    assert_raise DNS.Msg.Error, fn -> dname_reverse(".example.com") end
    assert_raise DNS.Msg.Error, fn -> dname_reverse("example.com..") end

    # raises on labels too long
    name = String.duplicate("a", 64) <> ".com"
    assert_raise DNS.Msg.Error, fn -> dname_reverse(name) end

    # raises on name too long
    name =
      String.duplicate("a", 28)
      |> List.duplicate(8)
      |> Enum.join(".")
      |> Kernel.<>(".abcdefghijklmnopqrstuv")

    assert 254 = String.length(name)
    assert_raise DNS.Msg.Error, fn -> dname_reverse(name) end
  end
end
