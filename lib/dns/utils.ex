defmodule DNS.Utils do
  @moduledoc """
  Utility functions used in various places

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

  # [[ MAPS ]]

  @doc """
  Normalizes a `:NAME,value` lookup map.

  Normalizing a :NAME,value-map means:
  - turn all keys into uppercase ATOM keys
  - add reverse mapping value -> :KEY

  Best used on maps that already has uppercase keys and unique values.

  ## Examples

       iex> normalize_name_map(%{"A" => 1})
       %{1 => :A, :A => 1}

       iex> normalize_name_map(%{"a" => 1})
       %{1 => :A, :A => 1}

       iex> normalize_name_map(%{a: 1})
       %{1 => :A, :A => 1}

  """
  @spec normalize_name_map(map) :: any
  def normalize_name_map(map) when is_map(map) do
    up = fn x -> to_string(x) |> String.upcase() |> String.to_atom() end

    map
    |> Enum.reduce(%{}, fn {k, v}, acc -> acc |> Map.put(up.(k), v) |> Map.put(v, up.(k)) end)
  end
end
