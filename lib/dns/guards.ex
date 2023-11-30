defmodule DNS.Guards do
  @moduledoc """
  Guards to validate values of DNS Msg fields.
  """

  @doc "Returns `true` is `n` is an unsigned 8 bit integer, `false` otherwise."
  defguard is_u8(n) when n in 0..255

  @doc "Returns `true` is `n` is an unsigned 15 bit integer, `false` otherwise."
  defguard is_u15(n) when n in 0..32767

  @doc "Returns `true` is `n` is an unsigned 16 bit integer, `false` otherwise."
  defguard is_u16(n) when n in 0..65535

  @doc "Returns `true` is `n` is an unsigned 32 bit integer, `false` otherwise."
  defguard is_u32(n) when n in 0..4_294_967_295

  @doc "Returns `true` is `n` is a signed 32 bit integer, `false` otherwise."
  defguard is_s32(n) when n in -2_147_483_648..2_147_483_647
end
