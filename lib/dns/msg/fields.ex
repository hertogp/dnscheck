defmodule DNS.Msg.Fields do
  @moduledoc """
  Low level functions to encode/decode common fields in a DNS Msg.
  """

  alias DNS.Msg.Error

  @ldh Enum.concat([?a..?z, [?-], ?0..?9, ?A..?Z])

  # [[ HELPERS ]]

  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  defp do_labels(a, l, <<>>), do: add_label(a, l)
  defp do_labels(a, l, <<?.>>), do: add_label(a, l)
  defp do_labels(a, l, <<?., rest::binary>>), do: do_labels(add_label(a, l), <<>>, rest)
  defp do_labels(a, l, <<c::8, rest::binary>>), do: do_labels(a, <<l::binary, c::8>>, rest)
  defp add_label(_a, l) when byte_size(l) > 63, do: error(:dname, "label > 63")
  defp add_label(_a, l) when byte_size(l) < 1, do: error(:dname, "empty label")
  defp add_label(a, l), do: [l | a]

  # [[ DNAME ]]

  @doc """
  Decode a length-encoded domain name from given `msg` binary, starting at the zero-based `offset`.

  Returns `{new_offset, name}`, if successful.  The `new_offset` can be used to
  read more stuff from the binary.

  DNS [name compression](https://www.rfc-editor.org/rfc/rfc1035, sec 4.1.4) is
  supported, but raises on detection of a compression loop.

  ## Examples

      iex> dname_decode(5, <<"stuff", 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 3, ?c, ?o, ?m, 0, "more stuff">>)
      {18, "example.com"}

      iex> dname_decode(5, <<3, ?n, ?e, ?t, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>)
      {15, "example.net"}

  """
  @spec dname_decode(non_neg_integer, binary) :: {non_neg_integer, binary}
  def dname_decode(offset, msg) when is_binary(msg),
    do: dname_decode(offset, msg, <<>>, %{})

  defp dname_decode(offset, msg, name, seen) do
    # note: OPT RR (EDNS0) MUST have root name (i.e. "" encoded as <<0>>)
    <<_::binary-size(offset), bin::binary>> = msg

    case bin do
      <<0::8, _::binary>> ->
        {offset + 1, name}

      <<0::2, n::6, label::binary-size(n), _::binary>> ->
        name =
          if name == <<>>,
            do: <<label::binary>>,
            else: <<name::binary, ?., label::binary>>

        dname_decode(offset + n + 1, msg, name, Map.put(seen, offset, []))

      <<3::2, ptr::14, _::binary>> ->
        if Map.has_key?(seen, ptr),
          do: error(:edname, "domain name compression loop at offset #{offset}")

        {_, name} = dname_decode(ptr, msg, name, Map.put(seen, ptr, []))
        {offset + 2, name}

      _ ->
        error(:edname, "bad label after #{inspect(name)}")
    end
  end

  @doc """
  Given a domain name, return its labels in a list.

  An error is raised when:
  - the name exceeds 255 characters, or
  - a label's length is not in 1..63

  Returns an empty list for the root domain or an empty domain name (as used e.g. in
  OPT RR's domain name field)

  ## Examples

      iex> dname_to_labels("example.com")
      ["example", "com"]

      iex> dname_to_labels("example.com.")
      ["example", "com"]

      # root domain has no labels
      iex> dname_to_labels(".")
      []

      # root is implied
      iex> dname_to_labels("")
      []

      iex> dname_to_labels(".example.com")
      ** (DNS.Msg.Error) [:dname] "empty label"

  """
  def dname_to_labels(name) when is_binary(name) do
    labels =
      case name do
        <<>> -> []
        <<?.>> -> []
        name -> do_labels([], <<>>, name)
      end
      |> Enum.reverse()

    # https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
    # encoding = a sequence of length encoded strings, terminated by the root label <0>
    # max length of encoding is 255, so string form max (without the terminating
    # root) is 253 to account for the len-byte of the first label and the
    # terminating root label.  Note that stripping the root dot first, might
    # miss out on an empty label at the end, e.g. in a.b.. since a.b. itself is valid.

    if Enum.join(labels, ".") |> String.length() > 253,
      do: error(:edname, "name > 253 characters")

    labels
  end

  def dname_to_labels(noname),
    do: error(:dname, "#{inspect(noname)}")

  @doc """
  Checks whether a domain name is valid, or not.

  This checks for the following:
  - name's length is in 0..253
  - label lengths are in 1..63
  - name consists of only ASCII characters
  - tld label does not start or end with a hyphen
  - tld label consists of letter-digit-hyphen chars only
  = tld label is not all numeric

  ## Examples

       iex> dname_valid?("")
       true

       iex> dname_valid?(".")
       true

       iex> dname_valid?("example.com")
       true

       iex> dname_valid?("example.c-m")
       true

       iex> dname_valid?("example.123")
       false

       iex> dname_valid?("example.-om")
       false

       iex> dname_valid?("example.co-")
       false

       iex> dname_valid?("example..com")
       false

       iex> dname_valid?(".example.com")
       false

       iex> String.duplicate("a", 64) |> Kernel.<>(".com") |> dname_valid?
       false

  """
  @spec dname_valid?(binary) :: boolean
  def dname_valid?(name) when is_binary(name) do
    try do
      labels = dname_to_labels(name)
      tld = List.last(labels)

      cond do
        labels == [] ->
          true

        # ascii check
        name != for(<<c <- name>>, c < 128, into: "", do: <<c>>) ->
          false

        # ldh check, cannot start/end with hyphen though
        tld != for(<<c <- tld>>, c in @ldh, into: "", do: <<c>>) ->
          false

        String.starts_with?(tld, "-") ->
          false

        String.ends_with?(tld, "-") ->
          false

        # tld all numeric?
        tld == for(<<c <- tld>>, c in ?0..?9, into: "", do: <<c>>) ->
          false

        true ->
          true
      end
    rescue
      _ -> false
    end
  end

  def dname_valid?(_),
    do: false

  @doc """
  Encode a domain name as a length-encoded binary string.

  An argument error will be raised when:
  - the name length exceeds 255 characters (ignoring any trailing '.')
  - a label's length is not in 1..63 characters

  ## Examples

      iex> dname_encode(".")
      <<0::8>>

      iex> dname_encode("")
      <<0::8>>

      iex> dname_encode("acdc.au")
      <<4, ?a, ?c, ?d, ?c, 2, ?a, ?u, 0>>

      iex> dname_encode("acdc.au.")
      <<4, ?a, ?c, ?d, ?c, 2, ?a, ?u, 0>>

      # happily encode an otherwise illegal name
      iex> dname_encode("acdc.-au-.")
      <<4, 97, 99, 100, 99, 4, 45, 97, 117, 45, 0>>

  """
  # https://www.rfc-editor.org/rfc/rfc1035, sec 2.3.1, 3.1
  @spec dname_encode(binary) :: binary
  def dname_encode(dname) when is_binary(dname) do
    dname
    |> dname_to_labels()
    |> Enum.map(fn label -> <<String.length(label)::8, label::binary>> end)
    |> Enum.join()
    |> Kernel.<>(<<0>>)
  end

  def dname_encode(noname),
    do: error(:edname, "#{inspect(noname)}")

  @doc """
  Given a domain name, reverse its labels.

  Raises an error if the name is too long or has empty labels.

  ## Examples

      iex> dname_reverse("example.com")
      "com.example"

      # trailing dot is ignored
      iex> dname_reverse("example.com.")
      "com.example"

      iex> dname_reverse(".example.com")
      ** (DNS.Msg.Error) [:dname] "empty label"

  """
  @spec dname_reverse(binary) :: binary
  def dname_reverse(name) when is_binary(name) do
    name =
      case name do
        <<>> -> [name]
        <<?.>> -> [name]
        name -> do_labels([], <<>>, name)
      end
      |> Enum.join(".")

    if String.length(name) > 253,
      do: error(:dname, "name > 253 characters")

    name
  end

  def dname_reverse(noname),
    do: error(:dname, "#{inspect(noname)}")
end
