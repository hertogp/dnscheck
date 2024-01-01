defmodule DNS.Utils do
  @moduledoc """
  Utility functions used in various places

  """

  @ldh Enum.concat([?a..?z, [?-], ?0..?9, ?A..?Z])

  import DNS.MsgError, only: [error: 2]

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

  @doc "Returns `true` if `n` is a valid ttl in range of 0..2**31-1"
  defguard is_ttl(n) when n in 0..2_147_483_647

  # [[ DNAME HELPERS ]]

  defp do_labels(a, l, <<>>), do: add_label(a, l)
  defp do_labels(a, l, <<?.>>), do: add_label(a, l)
  defp do_labels(a, l, <<?., rest::binary>>), do: do_labels(add_label(a, l), <<>>, rest)
  defp do_labels(a, l, <<c::8, rest::binary>>), do: do_labels(a, <<l::binary, c::8>>, rest)
  defp add_label(_a, l) when byte_size(l) > 63, do: error(:eencode, "domain name label > 63")
  defp add_label(_a, l) when byte_size(l) < 1, do: error(:eencode, "domain name has empty label")
  defp add_label(a, l), do: [l | a]

  # [[ DNAME ]]

  @doc """
  Decodes a length-encoded domain name from given `msg` binary, starting at the zero-based `offset`.

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
          do: error(:edecode, "domain name compression loop at offset #{offset}")

        {_, name} = dname_decode(ptr, msg, name, Map.put(seen, ptr, []))
        {offset + 2, name}

      _ ->
        error(:edecode, "domain name, bad label after #{inspect(name)}")
    end
  end

  @doc """
  Encodes a domain `name` as a length-encoded binary string.

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
  def dname_encode(name) when is_binary(name) do
    # FIXME: use byte_size, not String.length (utf8)
    name
    |> dname_to_labels()
    |> Enum.map(fn label -> <<String.length(label)::8, label::binary>> end)
    |> Enum.join()
    |> Kernel.<>(<<0>>)
  end

  def dname_encode(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc ~S"""
  Returns true if given domain names are equal, false otherwise

  Basically a case-insensitive comparison.  Note that this does not
  check whether given domain names are actually valid.

  ## Examples

      iex> dname_equal?("example.com", "EXAMPLE.COM")
      true

      iex> dname_equal?("example.com.", "EXAMPLE.com")
      true

      iex> dname_equal?("EXAmple.com", "exaMPLE.COM.")
      true

      iex> dname_equal?("9xample.com", "YXAMPLE.COM.")
      false

      iex> dname_equal?(42, 42)
      false


  """
  def dname_equal?(aname, bbame)

  def dname_equal?(<<>>, <<>>),
    do: true

  def dname_equal?(<<?.>>, <<>>),
    do: true

  def dname_equal?(<<>>, <<?.>>),
    do: true

  def dname_equal?(<<a::8, arest::binary>>, <<b::8, brest::binary>>) do
    cond do
      a == b -> dname_equal?(arest, brest)
      a == b + 32 and a in ?a..?z -> dname_equal?(arest, brest)
      a + 32 == b and a in ?A..?Z -> dname_equal?(arest, brest)
      true -> false
    end
  end

  def dname_equal?(_, _),
    do: false

  @doc """
  Returns an `{:ok, normalized}` or `{:error, :edname} for given `name`.

  Normalization means that:
  - the trailing dot is stripped
  - all uppercase letters are converted to lowercase

  If the `name` is illegal (longer than 253 octets in string form, or
  has a label longer than 63 octets), the error tuple is returned.

  """
  def dname_normalize(name) do
    name =
      name
      |> dname_to_labels()
      |> Enum.join(".")
      |> String.downcase()

    {:ok, name}
  rescue
    _ -> {:error, :edname}
  end

  @doc """
  Reverses the labels for given a domain `name`.

  Raises an error if the name is too long or has empty labels.

  ## Examples

      iex> dname_reverse("example.com")
      "com.example"

      # trailing dot is ignored
      iex> dname_reverse("example.com.")
      "com.example"

      iex> dname_reverse(".example.com")
      ** (DNS.MsgError) [encode] domain name has empty label

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
      do: error(:eencode, "domain name > 253 characters")

    name
  end

  def dname_reverse(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc """
  Returns true is child is a subzone of parent, false otherwise.

  Also returns false if either child or parent has:
  - a label longer than 63 octets
  - an empty label

  ## Examples

      iex> dname_subzone?("example.COM", "com")
      true

      iex> dname_subzone?("host.example.com", "example.com")
      true

      iex> dname_subzone?("example.com.", "com")
      true

      iex> dname_subzone?("example.com.", "example.com")
      false

      iex> dname_subzone?("example.com.", "net")
      false


  """
  @spec dname_subzone?(binary, binary) :: boolean
  def dname_subzone?(child, parent) do
    child = dname_to_labels(child)
    parent = dname_to_labels(parent)
    clast = List.last(child)
    plast = List.last(parent)
    dname_equal?(clast, plast) and length(child) > length(parent)
  rescue
    _ -> false
  end

  @doc """
  Creates a list of labels for Given a domain `name`.

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
      ** (DNS.MsgError) [encode] domain name has empty label

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
      do: error(:eencode, "domain name > 253 characters")

    labels
  end

  def dname_to_labels(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc """
  Checks whether a domain `name` is valid, or not.

  This checks for the following:
  - name's length is in 0..253
  - label lengths are in 1..63
  - name consists of only ASCII characters
  - tld label does not start or end with a hyphen
  - tld label consists of letter-digit-hyphen chars only
  - tld label is not all numeric

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

  # [[ TIME ]]

  @doc false
  # current moment in monotonic time
  def now(),
    do: System.monotonic_time(:millisecond)

  @doc false
  # create a (usually future), monotonic point in time
  def time(timeout),
    do: now() + timeout

  @doc false
  # remaining time [ms] till we reach the monotonic `time`
  def timeout(time),
    do: timeout(now(), time)

  @doc false
  # how many ms till monotonic `time` reaches monotonic `endtime`
  def timeout(time, endtime) do
    if time < endtime,
      do: endtime - time,
      else: 0
  end

  @doc false
  # donot wait
  def wait(0),
    do: :ok

  # wait for `time` ms
  def wait(time) do
    # don't match any messages!
    receive do
    after
      time -> :ok
    end
  end
end
