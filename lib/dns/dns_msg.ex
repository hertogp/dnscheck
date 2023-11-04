defmodule DNS.Msg do
  @moduledoc """
  Encode or decode a DNS message.

  """

  @rrtypes %{
             a: 1,
             ns: 2,
             cname: 5,
             soa: 6,
             ptr: 12,
             mx: 15,
             txt: 16,
             aaaa: 28,
             rrsig: 46,
             nsec: 47,
             dnskey: 48,
             nsec3: 50,
             nsec3param: 51,
             tlsa: 52,
             cds: 59,
             cdnskey: 60,
             https: 65,
             spf: 99
           }
           |> Enum.reduce(%{}, fn {k, v}, acc -> acc |> Map.put(k, v) |> Map.put(v, k) end)

  @type rrtype :: atom

  @header_opts %{
    qr: 0,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 1,
    ra: 0,
    z: 0,
    rcode: 0
  }

  # [[ DNS MESSAGE ]]
  # see section 4
  # The top level format of message is divided
  # into 5 sections (some of which are empty in certain cases) shown below:
  #
  #     +---------------------+
  #     |        Header       | <<ID, flags, qdcount, ancount, nscount, arcount>> = 12 bytes
  #     +---------------------+
  #     |       Question      | [<<QNAME, QTYPE, QCLASS>>]
  #     +---------------------+
  #     |        Answer       | [RRs] with answers
  #     +---------------------+
  #     |      Authority      | [RRs] pointing toward an authority
  #     +---------------------+
  #     |      Additional     | [RRs] additional information
  #     +---------------------+
  #
  #     where RR = <<NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA>>=
  #     NAME, RDATA are variable length

  # -[[ Header Section]]
  # contains the following fields: (sec 4.1.1)
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      ID                       |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    QDCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ANCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    NSCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ARCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  # - ID, query ID, is copied in the reply
  # - QR, 0=query, 1=response
  # - Opcode, kind of query: 0=normal, 1=inverse q, 2=server status, 3-15 reserved
  # - AA, Authoritative Anser, valid in responses
  # - TC, TrunCation
  # - RD, Recursion Desired, may be set in a Qry and copied to Resp.
  # - RA, Recursion Available, set or cleared in a Resp.
  # - Z, reserved, must be zero
  # - RCODE, Response Code
  # - QDCOUNT, 16b, num entries in Question section
  # - ANCOUNT, 16b, num of RRs in Answer section
  # - NSCOUNT, 16b, num of NS RRs in Authority section
  # - ARCOUNT, 16b, num of RRs in Additional section

  # -[[ Question Section ]]
  # The question section is used to carry the "question" in most queries,
  # i.e., the parameters that define what is being asked.  The section
  # contains QDCOUNT (usually 1) entries, each of the following format:
  #
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                     QNAME                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QTYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QCLASS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  # - QNAME, length encoded domain name, no padding
  # QTYPE, 2 octets, type of Qry
  # QCLASS, 2 octets, class of Qry, usally IN ()

  # -[[ Answer, Authority, and Additional sections ]]
  # a variable number of resource records, where the number of
  # records is specified in the corresponding count field in the header.
  # Each resource record has the following format:
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                                               /
  #     /                      NAME                     /
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     CLASS                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TTL                      |
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                   RDLENGTH                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  #     /                     RDATA                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  # where:
  # - NAME     a length encoded owner name
  # - TYPE     two octets containing one of the RR TYPE codes
  # - CLASS    two octets containing one of the RR CLASS codes
  # - TTL      a 32 bit signed integer indicating max cache time
  #            TTL=0 means no caching, use RR only in current transaction
  # - RDLENGTH an unsigned 16 bit integer, specifies length in octets of the RDATA field.
  # - RDATA    depends on the TYPE/CLASS

  @doc """
  Given a `dname` and `rrtype`, return a DNS message in binary format.
  """
  @spec encode(binary, rrtype) :: binary | :error
  def encode(dname, rrtype) do
    # qname = encode(dname)
    # rrtype = rrtype(rrtype)
    "msg #{dname}, #{inspect(rrtype)}"
  end

  # [[ DNAME ]]
  # TODO: support dname compression

  @spec dname_to_labels(binary) :: [binary]
  defp dname_to_labels(dname) when is_binary(dname) do
    case dname do
      <<>> -> []
      <<?.>> -> []
      <<?., rest::binary>> -> dname_to_labels([""], <<>>, rest)
      <<c::8, rest::binary>> -> dname_to_labels([], <<c>>, rest)
    end
  end

  defp dname_to_labels(acc, label, rest) do
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
    if size > 255, do: raise("dname > 255 octets")
    if Enum.any?(labels, fn {n, _} -> n < 1 end), do: raise("empty label")
    if Enum.any?(labels, fn {n, _} -> n > 63 end), do: raise("label > 63 octets")

    labels =
      labels
      |> Enum.map(fn {len, label} -> <<len::8, label::binary>> end)
      |> Enum.join()

    <<labels::binary, 0>>
  end

  # DNAME compression scheme
  # anywhere a label can occur, there are 2 situations:
  # 1.  <<0::2, len::6, label::binary-size(len), rest::binary>>
  # - len indicates the next number of octets is the label
  #
  # 2. <<3::2, ptr::14, rest::binary>>
  # - where ptr is offset in DNS msg of a label to *continue* with
  # - there you'll find the rest (or all) of the labels for current dname
  # - this is because names in a domain tend to have the same ending labels
  #   or (full) names occur N-times, e.g. if they have N A-records
  #
  # 3. <<1::2, ..>> and <<2::2, ..>> are reserved for future use
  #
  # This means:
  # - you need the entire DNS msg [header|questions|answers|..]
  # - since you're following ptr's, you need loop detection

  # https://www.rfc-editor.org/rfc/rfc1035, sec 4.1.4
  #  In order to reduce the size of messages, the domain system utilizes a
  # compression scheme which eliminates the repetition of domain names in a
  # message.  In this scheme:
  # - an entire domain name or
  # - a list of labels at the end of a domain name
  # is replaced with a pointer to a *prior* occurance of the same name.
  #                                 ^^^^^^^ - related to canonical order of RRs
  # The pointer takes the form of a two octet sequence:
  #
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     | 1  1|                OFFSET                   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  # Pointers can only be used for occurances of a domain name where the
  # format is not class specific (as of yet in current RDATA's).
  #
  # If a domain name is contained in a part of the message that is subject to a
  # length field (such as the RDATA section of an RR), and compression is
  # used, the length of the compressed name is used in the length
  # calculation, rather than the length of the expanded name.
  #
  # Programs are free to avoid using pointers in messages they generate.
  # Programs are required to understand arriving messages that contain pointers
  #
  # So, when reading a dname from an input, you need to keep:
  # - the org msg            - used to read via ptr
  # - the cur pos in org msg - rest of org msg to be processed later
  # - the ptr pos in org msg - when reading compressed part of the name
  # - the dname being built
  # if you see same ptr pos twice, you're in a loop
  #
  # <<0::binary-size(12), 3::2, 12::14, 1::16, 1::16>>
  # is an example of a loop, the QNAME in this points to itself!

  @doc """
  Decode a length-encoded domain name from a binary, returns dname & remainder.

  ## Examples

  """
  @spec decode_dname(binary, binary) :: {binary, binary}
  def decode_dname(cur, msg) do
    decode_dname(cur, cur, msg, <<>>, %{})
  end

  defp decode_dname(<<>>, cur, _msg, dname, _seen), do: {dname, cur}

  defp decode_dname(<<0::8, rest::binary>>, cur, _msg, dname, seen) do
    case map_size(seen) do
      0 -> {dname, rest}
      _ -> {dname, cur}
    end
  end

  defp decode_dname(<<0::2, n::6, label::binary-size(n), rest::binary>>, cur, msg, dname, seen) do
    dname =
      case dname do
        <<>> -> label
        dname -> <<dname::binary, ?., label::binary>>
      end

    case map_size(seen) do
      0 -> decode_dname(rest, rest, msg, dname, seen)
      _ -> decode_dname(rest, cur, msg, dname, seen)
    end
  end

  defp decode_dname(<<3::2, ptr::14, rest::binary>>, cur, msg, dname, seen) do
    if Map.has_key?(seen, ptr), do: raise("loop")

    cur =
      case map_size(seen) do
        0 -> rest
        _ -> cur
      end

    seen = Map.put(seen, ptr, [])

    case msg do
      <<_::binary-size(ptr), rest::binary>> -> decode_dname(rest, cur, msg, dname, seen)
      _ -> raise "bad pointer"
    end
  end

  # [[ RRTYPE ]]

  @doc """
  Turn an rrtype atom into its number.

  When given `rrtype` is not an atom, it is return unchanged.
  """
  @spec rrtype(atom | non_neg_integer) :: non_neg_integer()
  def rrtype(rrtype) when is_atom(rrtype),
    do: Map.get(@rrtypes, rrtype, rrtype)

  def rrtype(rrtype),
    do: rrtype
end
