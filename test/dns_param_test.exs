defmodule DNS.ParamTest do
  use ExUnit.Case
  doctest DNS.Param, import: true

  import DNS.Param

  # DNS.Param functions are generated the same way for a number of types
  # of DNS parameters.  So we only test one: class_xxx since that is least
  # likely to get expanded in the future.

  test "Encode DNS class" do
    # known names/numbers encode to numbers
    for {k, v} <- class_list() do
      assert v == class_encode(k)
      assert v == class_encode(v)
      assert v == class_encode("#{k}")
    end

    # raises on unknown names or invalid numbers
    assert_raise DNS.MsgError, fn -> class_encode(:in) end
    assert_raise DNS.MsgError, fn -> class_encode("in") end
    assert_raise DNS.MsgError, fn -> class_encode(65536) end
  end

  test "Decode DNS class" do
    # known numbers/name(atoms)/names(binaries) encode to name
    for {k, v} <- class_list() do
      assert k == class_decode(v)
      assert k == class_decode(k)
      assert k == class_decode("#{k}")
    end

    # raises on unknown names or numbers
    assert_raise DNS.MsgError, fn -> class_decode(:OOPS) end
    assert_raise DNS.MsgError, fn -> class_decode("OOPS") end
    assert_raise DNS.MsgError, fn -> class_decode(65536) end
  end

  test "DNS class_list" do
    assert [
             {:RESERVED, 0},
             {:IN, 1},
             {:CH, 3},
             {:HS, 4},
             {:NONE, 254},
             {:ANY, 255}
           ] == class_list()
  end

  test "DNS class validity" do
    for {k, v} <- class_list() do
      assert class_valid?(k)
      assert class_valid?(v)
      assert class_valid?("#{k}")
    end

    assert false == class_valid?(:OOPS)
    assert false == class_valid?("OOPS")
    assert false == class_valid?(65536)
  end
end
