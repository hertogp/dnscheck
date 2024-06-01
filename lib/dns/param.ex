defmodule DNS.Param do
  @moduledoc """
  Low level functions to convert between DNS Param numbers and atom (or strings)

  """
  import DNS.MsgError, only: [error: 2]

  @typedoc "A parameter's name, either an uppercase atom or uppercase binary"
  @type name :: atom | binary

  @typedoc "A parameter's numeric value"
  @type value :: non_neg_integer

  # # [[ DNS class ]]
  #
  # @class_defs [
  #   {:RESERVED, 0},
  #   {:IN, 1},
  #   {:CH, 3},
  #   {:HS, 4},
  #   {:NONE, 254},
  #   {:ANY, 255}
  # ]
  #
  # @doc """
  # Returns the list of known DNS class `{name, value}` pairs.
  #
  # Known classes include:
  # ```
  # #{inspect(@class_defs, pretty: true, width: 20)}
  # ```
  #
  # """
  # def class_list(),
  #   do: @class_defs
  #
  # @doc """
  # Returns a known DNS class value.
  #
  # Raises `t:DNS.MsgError/t` if given `name` (or value) is unknown. See
  # `class_list/0` for known classes.
  #
  # ## Examples
  #
  #     iex> class_encode(:IN)
  #     1
  #
  #     iex> class_encode("IN")
  #     1
  #
  #     iex> class_encode(1)
  #     1
  #
  #     iex> class_encode(:OOPS)
  #     ** (DNS.MsgError) [encode] DNS class name :OOPS is unknown
  #
  #     iex> class_encode(42)
  #     ** (DNS.MsgError) [encode] DNS class name 42 is unknown
  #
  #
  #
  # """
  # @spec class_encode(name | value) :: value | DNS.MsgError.t()
  # def class_encode(name)
  #
  # for {k, v} <- @class_defs do
  #   s = Atom.to_string(k)
  #   def class_encode(unquote(k)), do: unquote(v)
  #   def class_encode(unquote(v)), do: unquote(v)
  #   def class_encode(unquote(s)), do: unquote(v)
  # end
  #
  # def class_encode(k),
  #   do: error(:eencode, "DNS class name #{inspect(k)} is unknown")
  #
  # @doc """
  # Returns a DNS class name (as an atom) for given name or value.
  #
  # Returns `t:DNS.MsgError/t` if given `value` (or name) is unknown. See
  # `class_list/0` for known classes.
  #
  # ## Examples
  #
  #     iex> class_decode(1)
  #     :IN
  #
  #     iex> class_decode(:IN)
  #     :IN
  #
  #     iex> class_decode("IN")
  #     :IN
  #
  #     iex> class_decode(42)
  #     ** (DNS.MsgError) [decode] DNS class value 42 is unknown
  # """
  # for {k, v} <- @class_defs do
  #   s = Atom.to_string(k)
  #   def class_decode(unquote(v)), do: unquote(k)
  #   def class_decode(unquote(k)), do: unquote(k)
  #   def class_decode(unquote(s)), do: unquote(k)
  # end
  #
  # def class_decode(k),
  #   do: error(:edecode, "DNS class value #{inspect(k)} is unknown")
  #
  # @doc """
  # Returns true is given `class` name or value is valid, false otherwise.
  #
  # ## Examples
  #
  #     iex> class_valid?(:IN)
  #     true
  #
  #     iex> class_valid?("IN")
  #     true
  #
  #     iex> class_valid?("in")
  #     false
  #
  #     iex> class_valid?(1)
  #     true
  #
  #     iex> class_valid?(42)
  #     false
  # """
  # @spec class_valid?(name | value) :: boolean
  # def class_valid?(class) do
  #   class_encode(class)
  #   true
  # rescue
  #   _ -> false
  # end

  @params %{
    # [[ DNS class ]]

    :class => [
      {:RESERVED, 0},
      {:IN, 1},
      {:CH, 3},
      {:HS, 4},
      {:NONE, 254},
      {:ANY, 255}
    ],

    # [[ RRTYPE ]]
    :rrtype => [{:A, 1}, {:B, 2}],

    # [[ EDNS(0) OPT ]]
    :edns_opt => [{:A, 1}, {:B, 2}]
  }

  @doc """
  Returns a DNS class name (as an atom) for given name or value.

  Returns `t:DNS.MsgError/t` if given `value` (or name) is unknown. See
  `class_list/0` for known classes.

  ## Examples

      iex> class_decode(1)
      :IN

      iex> class_decode(:IN)
      :IN

      iex> class_decode("IN")
      :IN

      iex> class_decode(42)
      ** (DNS.MsgError) [decode] class_decode: unknown parameter value '42'
  """
  @spec class_decode(name | value) :: name | DNS.MsgError.t()
  def class_decode(value)

  @doc """
  Returns a known DNS class value.

  Raises `t:DNS.MsgError.t/0` if given `name` (or value) is unknown. See
  `class_list/0` for known classes.

  ## Examples

      iex> class_encode(:IN)
      1

      iex> class_encode("IN")
      1

      iex> class_encode(1)
      1

      iex> class_encode(:OOPS)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name ':OOPS'

      iex> class_encode(42)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name '42'



  """
  @spec class_encode(name | value) :: value | DNS.MsgError.t()
  def class_encode(name)

  # [[ CODECs ]]

  for {name, parms} <- @params do
    encode = String.to_atom("#{name}_encode")
    decode = String.to_atom("#{name}_decode")
    list = String.to_atom("#{name}_list")
    valid = String.to_atom("#{name}_valid?")

    for {k, v} <- parms do
      s = Atom.to_string(k)
      def unquote(encode)(unquote(k)), do: unquote(v)
      def unquote(encode)(unquote(v)), do: unquote(v)
      def unquote(encode)(unquote(s)), do: unquote(v)
      def unquote(decode)(unquote(v)), do: unquote(k)
      def unquote(decode)(unquote(k)), do: unquote(k)
      def unquote(decode)(unquote(s)), do: unquote(k)
    end

    def unquote(encode)(k),
      do: error(:eencode, "#{unquote(encode)}: unknown parameter name '#{inspect(k)}'")

    def unquote(decode)(v),
      do: error(:edecode, "#{unquote(decode)}: unknown parameter value '#{inspect(v)}'")

    def unquote(list)(),
      do: @params[unquote(name)]

    def unquote(valid)(parm) do
      unquote(encode)(parm)
      true
    rescue
      _ -> false
    end
  end
end
