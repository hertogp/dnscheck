defmodule DNS.Msg.HdrTest do
  use ExUnit.Case
  doctest DNS.Msg.Hdr, import: true

  import DNS.Msg.Hdr

  test "new/0" do
    # default values
    h = new()
    assert h.id == 0
    assert h.qr == 0
    assert h.opcode == :QUERY
    assert h.aa == 0
    assert h.tc == 0
    assert h.rd == 1
    assert h.ra == 0
    assert h.z == 0
    assert h.ad == 0
    assert h.cd == 0
    assert h.rcode == :NOERROR
    assert h.qdc == 0
    assert h.anc == 0
    assert h.nsc == 0
    assert h.arc == 0
    assert h.wdata == <<>>

    # raises on invalid values
    assert_raise DNS.Msg.Error, fn -> new(id: 65536) end
    assert_raise DNS.Msg.Error, fn -> new(qr: 2) end
    assert_raise DNS.Msg.Error, fn -> new(opcode: 16) end
    assert_raise DNS.Msg.Error, fn -> new(rcode: 16) end

    # wdata is ignored
    h = new(wdata: "ignored")
    assert h.wdata == <<>>

    # atom names stored when available
    h = new(opcode: 0, rcode: 0)
    assert h.opcode == :QUERY
    assert h.rcode == :NOERROR

    # numbers are stored when no names are available
    # - usually, reserved/unassigned numbers are not translated
    h = new(opcode: 7, rcode: 12)
    assert h.opcode == 7
    assert h.rcode == 12

    # raises on crazy values
    assert_raise DNS.Msg.Error, fn -> new(opcode: ["asdf"]) end
    assert_raise DNS.Msg.Error, fn -> new(rcode: ["asdf"]) end
    assert_raise DNS.Msg.Error, fn -> new(qr: ["asdf"]) end
  end
end
