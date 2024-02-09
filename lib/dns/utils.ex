defmodule DNS.Utils do
  @moduledoc """
  Utility functions used in various places

  """

  # TODO
  # [ ] dname_equal?("x.example.com", "*.example.com") <- equal?

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

  @doc "Returns `true` if `n` is a valid ttl in range of 0..2**32 - 1"
  defguard is_ttl(n) when n in 0..4_294_967_295

  # [[ DNAME HELPERS ]]

  @spec do_labels([binary], binary, binary) :: [binary] | no_return
  defp do_labels(acc, label, rest)

  defp do_labels(acc, l, rest) when rest in [<<>>, <<?.>>] do
    # note: add_label checks validity of l (not empty, len < 63)
    labels =
      add_label(acc, l)
      |> Enum.reverse()

    len =
      labels
      |> Enum.map(fn l -> byte_size(l) + 1 end)
      |> Enum.sum()
      |> Kernel.+(1)

    if len < 256,
      do: labels,
      else: error(:eencode, "domain name > 255 octets: #{len}")
  end

  # escaped numbers, eg \000..\255, i.e. num in 0..255
  defp do_labels(acc, l, <<?\\, a::8, b::8, c::8, rest::binary>>)
       when a in ?0..?9 and b in ?0..?9 and c in ?0..?9 do
    num = (a - ?0) * 100 + (b - ?0) * 10 + c - ?0

    unless num < 256,
      do: error(:eencode, "'\\#{num}' is illegal in a domain name")

    do_labels(acc, <<l::binary, num::8>>, rest)
  end

  # escaped chars, eg \\, \., \(, \), \; (and all others)
  defp do_labels(acc, l, <<?\\, c::8, rest::binary>>),
    do: do_labels(acc, <<l::binary, c::8>>, rest)

  defp do_labels(acc, l, <<?., rest::binary>>),
    do: do_labels(add_label(acc, l), <<>>, rest)

  defp do_labels(acc, l, <<c::8, rest::binary>>),
    do: do_labels(acc, <<l::binary, c::8>>, rest)

  # adds non-empty label <= 63 octets or raises DNSError
  @spec add_label([binary], binary) :: [binary] | no_return
  defp add_label(_acc, l) when byte_size(l) > 63,
    do: error(:eencode, "domain name label > 63")

  defp add_label(_acc, l) when byte_size(l) < 1,
    do: error(:eencode, "domain name has empty label")

  defp add_label(acc, l), do: [l | acc]

  @spec ldh?(0..255) :: boolean
  defp ldh?(c) do
    cond do
      c in ?a..?z -> true
      c in ?0..?9 -> true
      c in ?A..?Z -> true
      c == ?- -> true
      true -> false
    end
  end

  # [[ DNAME ]]

  @doc ~S"""
  Decodes a length-encoded domain name from given `msg` binary, starting at the
  zero-based `offset`.

  Returns `{new_offset, name}`, if successful.  The `new_offset` can be used to
  read more stuff from the binary.

  DNS [name compression](https://www.rfc-editor.org/rfc/rfc1035, sec 4.1.4) is
  supported, but raises on detection of a compression loop.

  Octets that are part of a label have values in range 0..255 and need some
  form of escaping when transformed into a string:
  - octet values for ' ;().' have special meaning in a zone file
  - octet values < 32 or > 127 are (mostly) not printable
  hence, octet values for special characters are represented as `\c' (e.g. `\;`)
  while the others are represented as `\ddd` where `ddd`is the string representation
  of the octet's value.  Examples:
  - `<<0>>` becomes> `\000`,
  - `<<59>>` becomes `\;',
  - `<<128>>` becomes `\128` and so on.

  See [RFC4343](https://datatracker.ietf.org/doc/html/rfc4343).


  ## Examples

      iex> dname_decode(5, <<"stuff", 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 3, ?c, ?o, ?m, 0, "more stuff">>)
      {18, "example.com"}

      iex> dname_decode(5, <<3, ?n, ?e, ?t, 0, 7, ?e, ?x, ?a, ?m, ?p, ?l, ?e, 192, 0>>)
      {15, "example.net"}

      iex> dname_decode(0, <<1, 255, 0>>)
      {3, "\\255"}

  """
  @spec dname_decode(non_neg_integer, binary) :: {non_neg_integer, binary}
  def dname_decode(offset, msg) when is_binary(msg),
    do: dname_decode(offset, msg, <<>>, %{})

  defp dname_decode(offset, msg, acc, seen) do
    # notes:
    # - OPT RR (EDNS0) MUST have root acc (i.e. "" encoded as <<0>>)
    # - case stmt matches either 0 (root), label_len < 64 or ptr to next label_len
    # - loop protecton: seen -> offsets already processed (ptr is just the next offset)
    <<_::binary-size(offset), bin::binary>> = msg

    case bin do
      <<0::8, _::binary>> ->
        {offset + 1, acc}

      <<0::2, n::6, label::binary-size(n), _::binary>> ->
        label = label_decode(label, <<>>)

        acc =
          if acc == <<>>,
            do: <<label::binary>>,
            else: <<acc::binary, ?., label::binary>>

        dname_decode(offset + n + 1, msg, acc, Map.put(seen, offset, []))

      <<3::2, ptr::14, _::binary>> ->
        if Map.has_key?(seen, ptr),
          do: error(:edecode, "domain name compression loop at offset #{offset}")

        {_, acc} = dname_decode(ptr, msg, acc, Map.put(seen, ptr, []))
        {offset + 2, acc}

      _ ->
        error(:edecode, "domain name has bad label after #{inspect(acc)}")
    end
  end

  defp label_decode(<<>>, <<>>),
    do: error(:edecode, "domain name has empty label")

  defp label_decode(<<>>, acc),
    do: acc

  defp label_decode(<<c::8, rest::binary>>, acc) do
    # octets in a label are u8 (0..255), i.e. legal in DNS
    # escape some special chars and encode non-printables as \ddd
    # note: order of the clauses matter
    cond do
      c in [?., ?;, ?(, ?), ?\s, ?\\] -> label_decode(rest, <<acc::binary, ?\\::8, c::8>>)
      c in 33..126 -> label_decode(rest, <<acc::binary, c::8>>)
      c > 99 -> label_decode(rest, <<acc::binary, ?\\::8, Integer.to_string(c)::binary>>)
      c > 9 -> label_decode(rest, <<acc::binary, ?\\::8, "0", Integer.to_string(c)::binary>>)
      true -> label_decode(rest, <<acc::binary, ?\\::8, "00", Integer.to_string(c)::binary>>)
    end
  end

  @doc ~S"""
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

      # escaped characters
      iex> dname_encode("one\\.label.see")
      <<9, "one.label", 3, "see", 0>>

      # escaped numbers
      iex> dname_encode("two\\.one\\.\\000.boom")
      <<9, "two.one.", 0, 4, "boom", 0>>

      iex> dname_encode("acdc.au.")
      <<4, ?a, ?c, ?d, ?c, 2, ?a, ?u, 0>>

      # happily encode an otherwise illegal name
      iex> dname_encode("acdc.-au-.")
      <<4, 97, 99, 100, 99, 4, 45, 97, 117, 45, 0>>


  """
  # https://www.rfc-editor.org/rfc/rfc1035, sec 2.3.1, 3.1
  @spec dname_encode(binary) :: binary
  def dname_encode(name) when is_binary(name) do
    name =
      name
      |> dname_to_labels()
      |> Enum.map(fn label -> <<byte_size(label)::8, label::binary>> end)
      |> Enum.join()
      |> Kernel.<>(<<0>>)

    if byte_size(name) < 256,
      do: name,
      else: error(:eencode, "domain name too long #{byte_size(name)}")
  end

  def dname_encode(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc ~S"""
  Returns true if given domain names are equal, false otherwise

  Basically a case-insensitive comparison.  Note that this does not
  check whether given domain names are actually valid.  Both domain
  names need to be in either `String.t` format (zone file format) or
  in wire format.  Don't mix the two because they will never compare
  equal.

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

      iex> name1 = dname_encode("example.NET")
      iex> name2 = dname_encode("EXAMPLE.net")
      iex> dname_equal?(name1, name2)
      true
      iex> dname_equal?("example.NET", name1)
      false
      iex> dname_decode(0, name1)
      {13, "example.NET"}

  """
  def dname_equal?(aname, bbame)

  def dname_equal?(<<>>, <<>>),
    do: true

  def dname_equal?(<<?.>>, <<>>),
    do: true

  def dname_equal?(<<>>, <<?.>>),
    do: true

  def dname_equal?(<<a::8, rest_a::binary>>, <<b::8, rest_b::binary>>) do
    cond do
      a == b -> dname_equal?(rest_a, rest_b)
      a == b + 32 and a in ?a..?z -> dname_equal?(rest_a, rest_b)
      a + 32 == b and a in ?A..?Z -> dname_equal?(rest_a, rest_b)
      true -> false
    end
  end

  def dname_equal?(_, _),
    do: false

  @doc """
  Returns an `{:ok, normalized}` or `{:error, :eencode}` for given `name`.

  Normalization means that:
  - the trailing dot is stripped
  - all uppercase letters are converted to lowercase

  If the `name` is illegal (longer than 253 octets in string form, or
  has a label longer than 63 octets), the error tuple is returned.

  """
  @spec dname_normalize(binary, Keyword.t()) :: {:ok, binary | [binary]} | {:error, :eencode}
  def dname_normalize(name, opts \\ []) do
    join = Keyword.get(opts, :join, true)

    labels =
      name
      |> String.downcase()
      |> dname_to_labels()

    result = if join, do: Enum.join(labels, "."), else: labels

    {:ok, result}
  rescue
    _ -> {:error, :eencode}
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
    case name do
      <<>> -> []
      <<?.>> -> []
      name -> do_labels([], <<>>, name)
    end
    |> Enum.reverse()
    |> Enum.join(".")
  end

  def dname_reverse(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc """
  Returns true is child is a subzone of parent, false otherwise.

  Also returns false if either child or parent has:
  - a label longer than 63 octets
  - an empty label

  ## Examples

      iex> dname_subdomain?("example.COM", "com")
      true

      iex> dname_subdomain?("host.example.com", "example.com")
      true

      iex> dname_subdomain?("example.com.", "com")
      true

      iex> dname_subdomain?("example.com.", "example.com")
      false

      iex> dname_subdomain?("example.com.", "net")
      false

  """
  @spec dname_subdomain?(binary, binary) :: boolean
  def dname_subdomain?(child, parent) do
    {:ok, child} = dname_normalize(child, join: false)
    {:ok, parent} = dname_normalize(parent, join: false)

    if length(child) > length(parent),
      do: List.starts_with?(Enum.reverse(child), Enum.reverse(parent)),
      else: false
  rescue
    _ -> false
  end

  @doc """
  Returns true is `child` is a subzone or same as the `ancestor`, false otherwise.

  Also returns false if either child or ancestor has:
  - a label longer than 63 octets
  - an empty label

  ## Examples

      iex> dname_indomain?("example.COM", "com")
      true

      iex> dname_indomain?("host.example.com", "example.com")
      true

      iex> dname_indomain?("example.com.", "com")
      true

      iex> dname_indomain?("example.com.", "example.com")
      true

      iex> dname_indomain?("example.com.", "net")
      false

  """
  # https://www.rfc-editor.org/rfc/rfc8499#section-7
  @spec dname_indomain?(binary, binary) :: boolean
  def dname_indomain?(child, ancestor) do
    {:ok, child} = dname_normalize(child, join: false)
    {:ok, ancestor} = dname_normalize(ancestor, join: false)
    child = Enum.reverse(child)
    ancestor = Enum.reverse(ancestor)

    if length(child) < length(ancestor),
      do: false,
      else: List.starts_with?(child, ancestor)
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
    case name do
      <<>> -> []
      <<?.>> -> []
      name -> do_labels([], <<>>, name)
    end
  end

  def dname_to_labels(noname),
    do: error(:eencode, "domain name expected a binary, got: #{inspect(noname)}")

  @doc """
  Checks whether a domain `name` is valid, or not.

  This checks for the following:
  - name's length (in encoded form) is in 1..255
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
        # name != for(<<c <- name>>, c < 128, into: "", do: <<c>>) ->
        #   false

        # tld only letters, digits or hyphens
        tld != for(<<c <- tld>>, ldh?(c), into: "", do: <<c>>) ->
          false

        # tld cannot start/end with hyphen
        String.starts_with?(tld, "-") ->
          false

        String.ends_with?(tld, "-") ->
          false

        # tld cannot be all numeric
        tld == for(<<c <- tld>>, c in ?0..?9, into: "", do: <<c>>) ->
          false

        true ->
          true
      end
    rescue
      # do_labels will raise on empty labels and/or labels > 63 octets
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
  # create a (usually future), monotonic point in time, timeout ms from now
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

  # wait for `time` ms, don't match any messages
  def wait(time) do
    receive do
    after
      time -> :ok
    end
  end
end
