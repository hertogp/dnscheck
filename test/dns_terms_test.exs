defmodule DNS.Msg.TermsTest do
  use ExUnit.Case
  doctest DNS.Msg.Terms, import: true

  import DNS.Msg.Terms

  test "Encode DNS class" do
    # known names encode to numbers
    assert 0 == encode_dns_class(:RESERVED)

    # valid (unknown) numbers encode to themselves
    assert 65535 == encode_dns_class(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> encode_dns_class(:in) end

    # raises on invalid (unknown) numbers
    assert_raise DNS.Msg.Error, fn -> encode_dns_class(65536) end
  end

  test "Decode DNS class" do
    # known names decode to themselves
    assert :RESERVED == decode_dns_class(:RESERVED)

    # valid (unknown) numbers decode to themselves
    assert 1410 == decode_dns_class(1410)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> decode_dns_class(:reserved) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> decode_dns_class(65536) end
  end

  test "Encode DNS opcode" do
    # known names encode to numbers
    assert 0 == encode_dns_opcode(:QUERY)

    # valid (unknown) numbers encode to themselves
    assert 15 == encode_dns_opcode(15)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> encode_dns_opcode(:query) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> encode_dns_opcode(16) end
  end

  test "Decode DNS opcode" do
    # known names decode to themselves
    assert :QUERY == decode_dns_opcode(:QUERY)

    # valid numers decode to themselves
    assert 15 == decode_dns_opcode(15)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> decode_dns_opcode(:query) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> decode_dns_opcode(16) end
  end

  test "Encode DNS rcode" do
    # known names encode to numbers
    assert 0 == encode_dns_rcode(:NOERROR)

    # valid (unknown) numbers encode to themselves
    assert 65535 == encode_dns_rcode(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> encode_dns_rcode(:noerror) end

    # raises on invalid (unknown) numbers
    assert_raise DNS.Msg.Error, fn -> encode_dns_rcode(65536) end
  end

  test "Decode DNS rcode" do
    # known names decode to themselves
    assert :NOERROR == decode_dns_rcode(:NOERROR)

    # valid numers decode to themselves
    assert 65535 == decode_dns_rcode(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> decode_dns_rcode(:noerror) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> decode_dns_rcode(65536) end
  end

  test "Encode RR type" do
    # known names encode to numbers
    assert 1 == encode_rr_type(:A)

    # valid (unknown) numbers encode to themselves
    assert 65535 == encode_rr_type(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> encode_rr_type(:a) end

    # raises on invalid (unknown) numbers
    assert_raise DNS.Msg.Error, fn -> encode_rr_type(65536) end
  end

  test "Decode RR type" do
    # known names decode to themselves
    assert :A == decode_rr_type(:A)

    # valid numers decode to themselves
    assert 65535 == decode_rr_type(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> decode_rr_type(:a) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> decode_rr_type(65536) end
  end

  # [[ DNS OPT-RR ]]
  test "Encode OPT RR code" do
    # known names encode to numbers
    assert 1 == encode_rropt_code(:LLQ)

    # valid (unknown) numbers encode to themselves
    assert 65535 == encode_rropt_code(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> encode_rropt_code(:llq) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> encode_rropt_code(65536) end
  end

  test "Decode OPT RR code" do
    # known names decode to themselves
    assert :LLQ == decode_rropt_code(:LLQ)

    # valid numers decode to themselves
    assert 65535 == decode_rropt_code(65535)

    # raises on unknown names
    assert_raise DNS.Msg.Error, fn -> decode_rropt_code(:llq) end

    # raises on invalid numbers
    assert_raise DNS.Msg.Error, fn -> decode_rropt_code(65536) end
  end
end
