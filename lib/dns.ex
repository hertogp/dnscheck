defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  alias DNS.Msg

  # [[ TODO ]]
  # https://www.rfc-editor.org/rfc/rfc1034#section-5
  # https://www.rfc-editor.org/rfc/rfc1035#section-7
  # - udp & fallback to tcp
  # - do iterative queries, unless required to do rd=1 to specific nameserver
  # - handle timeout and multiple nameservers

  # [[ RESOLVE ]]

  @doc """
  Queries DNS for given `name` and `type`, returns `t:DNS.Msg.t/0`

  Options include:
  - `rd`, defaults to 1 (recursion desired, true)
  - `id`, defaults to 0 (used to link replies to requests)
  - `opcode`, defaults to 0
  - `bufsize`, defaults to 1410 if edns0 is used
  - `do`, defaults to 0 (dnssec ok, false)
  - `cd`, defaults to 0 (dnssec check disable, fals)
  - `nameserver`, defaults to `{{8,8,8,8}, 53}`

  If any of the `bufsize, do or cd` options is used, a pseudo-RR
  is added to the additonal section of the `Msg`.


  """
  @spec resolve(binary, atom) :: Msg.t()
  def resolve(name, type, opts \\ []) do
    {edns_opts, opts} = Keyword.split(opts, [:bufsize, :do])
    {hdr_opts, opts} = Keyword.split(opts, [:rd, :id, :opcode, :cd])
    qtn_opts = [[name: name, type: type]]
    edns_opts = if edns_opts == [], do: [], else: [Keyword.put(edns_opts, :type, :OPT)]

    msg =
      Msg.new(qtn: qtn_opts, hdr: hdr_opts, add: edns_opts)
      |> IO.inspect(label: :query)
      |> Msg.encode()

    udp_query(msg.wdata, opts)
    |> case do
      {:error, reason} -> {:error, reason}
      response -> Msg.decode(response)
    end
  end

  # [[ SEND/RECV MSG ]]

  def udp_query(msg, opts \\ []) do
    nameserver = Keyword.get(opts, :nameserver, {{8, 8, 8, 8}, 53})
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, recbuf: 4000])
    :ok = :gen_udp.send(sock, nameserver, msg)

    timeout_ms = 500

    case :gen_udp.recv(sock, 0, timeout_ms) do
      {:ok, {_address, _port, response}} ->
        response

      {:error, reason} ->
        {:error, reason}
    end
  end
end
