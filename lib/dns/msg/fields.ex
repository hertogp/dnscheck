defmodule DNS.Msg.Fields do
  @moduledoc """
  Functions to to encode/decode fields in a DNS Msg.
  """

  alias DNS.Msg.Error

  # [[ HELPERS ]]

  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  # [[ DNAME ]]

  @spec dname_to_labels(binary) :: [binary]
  def dname_to_labels(dname) when is_binary(dname) do
    case dname do
      <<>> -> []
      <<?.>> -> []
      <<?., rest::binary>> -> dname_to_labels([""], <<>>, rest)
      <<c::8, rest::binary>> -> dname_to_labels([], <<c>>, rest)
    end
  end

  def dname_to_labels(acc, label, rest) do
    case rest do
      <<>> -> Enum.reverse([label | acc])
      <<?.>> -> Enum.reverse([label | acc])
      <<?., rest::binary>> -> dname_to_labels([label | acc], <<>>, rest)
      <<c::8, rest::binary>> -> dname_to_labels(acc, <<label::binary, c::8>>, rest)
    end
  end

  @doc """
  Encode a domainname as length-encoded binary string.

  An argument error will be raised when:
  - the name length exceeds 255 characters (ignoring any trailing '.')
  - a label's length is not in 1..63 characters

  ## Examples

      iex> encode_dname(".")
      <<0::8>>

      iex> encode_dname("")
      <<0::8>>

      iex> encode_dname("acdc.au")
      <<4, ?a, ?c, ?d, ?c, 2, ?a, ?u, 0>>

      iex> encode_dname("acdc.au.")
      <<4, ?a, ?c, ?d, ?c, 2, ?a, ?u, 0>>

      # happily encode an otherwise illegal name
      iex> encode_dname("acdc.-au-.")
      <<4, 97, 99, 100, 99, 4, 45, 97, 117, 45, 0>>

  """

  # https://www.rfc-editor.org/rfc/rfc1035, sec 2.3.1, 3.1
  @spec encode_dname(binary) :: binary
  def encode_dname(dname) when is_binary(dname) do
    labels =
      dname
      |> dname_to_labels()
      |> Enum.map(fn label -> {byte_size(label), label} end)

    size = Enum.reduce(labels, Enum.count(labels) - 1, fn {n, _}, acc -> n + acc end)
    if size > 255, do: error(:edname, "dname > 255 octets")
    if Enum.any?(labels, fn {n, _} -> n < 1 end), do: error(:elabel, "empty label")
    if Enum.any?(labels, fn {n, _} -> n > 63 end), do: error(:elabel, "label > 63 octets")

    labels =
      labels
      |> Enum.map(fn {len, label} -> <<len::8, label::binary>> end)
      |> Enum.join()

    <<labels::binary, 0>>
  end

  # compression scheme https://www.rfc-editor.org/rfc/rfc1035, sec 4.1.4

  @doc """
  Decode a length-encoded domain name from a binary, returns dname & remainder.

  ## Examples

  """
  @spec decode_dname(non_neg_integer, binary) :: {non_neg_integer, binary}
  def decode_dname(offset, msg),
    do: decode_dname(offset, msg, <<>>, %{})

  def decode_dname(offset, msg, name, seen) do
    # note: OPT RR (EDNS0) MUST have root name (i.e. "" encoded as <<0>>
    <<_::binary-size(offset), bin::binary>> = msg

    case bin do
      <<0::8, _::binary>> ->
        {offset + 1, name}

      <<0::2, n::6, label::binary-size(n), _::binary>> ->
        name =
          if name == <<>>,
            do: <<label::binary>>,
            else: <<name::binary, ?., label::binary>>

        decode_dname(offset + n + 1, msg, name, Map.put(seen, offset, []))

      <<3::2, ptr::14, _::binary>> ->
        if Map.has_key?(seen, ptr),
          do: error(:edname, "domain name compression loop")

        {_, name} = decode_dname(ptr, msg, name, Map.put(seen, ptr, []))
        {offset + 2, name}

      _ ->
        error(:elabel, "bad label: #{inspect(name)}")
    end
  end
end
