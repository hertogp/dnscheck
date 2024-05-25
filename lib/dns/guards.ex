defmodule DNS.Guards do
  @moduledoc """
  Guards to validate specific types of values

  """

  # [[ GUARDS ]]

  @doc "Returns true if `n` is true, false, 0 or 1"
  defguard is_bool(n) when is_boolean(n) or n in 0..1

  @doc "Returns true if `n` fits in an unsigned 7 bit integer"
  defguard is_u7(n) when n in 0..127

  @doc "Returns `true` if `n` fits in an unsigned 8 bit integer, `false` otherwise."
  defguard is_u8(n) when n in 0..255

  @doc "Returns `true` if `n` fits in an unsigned 15 bit integer, `false` otherwise."
  # 2**15 -1
  defguard is_u15(n) when n in 0..32767

  @doc "Returns `true` if `n` fits in an unsigned 16 bit integer, `false` otherwise."
  # 2**16 - 1
  defguard is_u16(n) when n in 0..65535

  @doc "Returns `true` if `n` fits in an unsigned 32 bit integer, `false` otherwise."
  # 2**32 - 1
  defguard is_u32(n) when n in 0..4_294_967_295

  @doc "Returns `true` if `n` fits in a signed 32 bit integer, `false` otherwise."
  # -2**31..2**31-1
  defguard is_s32(n) when n in -2_147_483_648..2_147_483_647

  @doc "Returns `true` if `n` is a valid ttl in range of 0..2**32 - 1"
  defguard is_ttl(n) when n in 0..4_294_967_295
end
