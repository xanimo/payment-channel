# protocol

one json object per line over tcp. every message has the same fields and the
`psbt` field is a hex payload whose meaning follows the type:

    {"type":"payment","ref":"<64 hex>","vout":<n>,"more":<0|1>,
     "to_bob":<koinu>,"addr":"<base58>","psbt":"<hex>","tx":"<hex>"}

    request   alice asks for a channel. no payload
    announce  psbt is bob's compressed pubkey, addr is where he wants paying
    open      psbt is alice's opening psbt, tx is the funding transaction that
              created its input, to_bob is the locktime, ref the funding txid
              and vout its index
    accept    bob has checked the funding and will take payments on it. to_bob
              is the capacity he read off it
    reject    bob will not. addr carries the reason
    invoice   to_bob is the cumulative total now owed, addr is where it goes
    payment   psbt is the psbt, ref the funding txid, to_bob the cumulative
              total paid to bob
    ack       psbt is "01", to_bob echoes the total bob now holds, more says
              whether another invoice follows
    close     from alice psbt is "01" and means "close now"; from bob psbt is
              the final raw transaction

the parser is hand written and refuses anything it does not recognise: no
escapes, no nesting, fixed field shapes, `ref` either empty or exactly 64 hex
characters, `psbt` always non-empty hex, `more` absent or 0 or 1. a general json
parser here would be a dependency and a larger attack surface for no gain.

## exchange

bob is told nothing about the channel in advance. he answers with the key he
will sign with and works the rest out for himself.

    alice -> bob   request
    bob   -> alice announce  his pubkey, and the address he wants paying at

alice pins that key against `--peer-pubkey` if she was given one. that pin is
the only thing defending this exchange: the transport is plain tcp in the clear,
so everything on it is visible and modifiable, and without the pin a substituted
pubkey hands the channel to whoever sent it.

she builds the redeem script from her key, his, and a locktime, funds the p2sh,
waits for it to confirm, and announces the channel as a psbt spending that
output. bob reads the script back out of the psbt and refuses unless it names
his own key, the transaction beside it really pays that script, and the locktime
sits far enough above the height he was given. he cannot see the chain, so the
height is his operator's word and confirming the funding is his operator's job.

    alice -> bob   open      the opening psbt, and the funding transaction
    bob   -> alice accept    the capacity he read off it

the funding transaction travels beside the psbt rather than inside it because no
published accessor reports an input's previous transaction, so bob checks it
against the outpoint the psbt actually spends.

bob then prices an order and invoices for the running total. alice pays it as a
complete transaction spending the funding outpoint, paying `to_bob` to bob and
the remainder back to herself, signed by alice only. bob countersigns, parses
what he signed, checks it, and acks.

    bob   -> alice invoice   cumulative total owed, and where
    alice -> bob   payment   psbt, cumulative total
    bob   -> alice ack       total bob now holds, and whether more is coming

any number of orders, each total strictly larger than the last. the ack's `more`
flag is what ends the loop: bob is the only side that knows the order is
finished, so without it alice waits for an invoice that never comes and both
sides block in recv. once it is clear alice closes.

    alice -> bob   close     "01"
    bob   -> alice close     the final raw transaction

## roles against bip174

alice is creator, updater and signer. she wraps the unsigned spend in a psbt,
attaches the funding transaction and the redeem script, and signs her input.

bob is signer, finalizer and extractor. he signs the same input, builds the
scriptsig himself because `OP_IF` does not classify, installs it with
`dogecoin_psbt_input_set_final_scriptsig`, and extracts.

there is no combiner step. the psbt travels one way and each side signs it in
turn, so there are never two copies to merge.

## failure

bob rejects with a reason and alice prints it and gives up. a reject is not a
negotiation: this is a prototype and a message bob will not take means something
is broken or hostile. anything worse than that, a message that does not parse or
a peer that stops talking, closes the connection and logs why.

## refund

if bob stops responding, alice waits for the locktime and spends the funding
output through the `OP_IF` branch with `nLockTime` set to the locktime and a non
final sequence number, both of which `OP_CHECKLOCKTIMEVERIFY` requires. that is
`alice --refund`, it talks to nobody, and contrib/regtest.sh broadcasts one and
checks it confirms and returns the balance.

nothing revokes an old state, so bob can still broadcast any payment he holds
before the locktime arrives. that is the design rather than a gap: every state
he holds pays him more than the last, so the newest is the one he wants.
