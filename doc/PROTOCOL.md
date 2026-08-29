# protocol

one json object per line over tcp. every message has the same four fields and
the `psbt` field is a hex payload whose meaning follows the type:

    {"type":"payment","ref":"<64 hex>","to_bob":<koinu>,"psbt":"<hex>"}

    announce  psbt is the sender's compressed pubkey, to_bob is the locktime,
              ref is empty
    payment   psbt is the psbt, ref is the funding txid, to_bob is the
              cumulative total paid to bob
    ack       psbt is "01", to_bob echoes the total the receiver now holds
    close     from alice psbt is "01" and means "close now"; from bob psbt is
              the final raw transaction

the parser is hand written and refuses anything it does not recognise: no
escapes, no nesting, fixed field shapes, `ref` either empty or exactly 64 hex
characters, `psbt` always non-empty hex. a general json parser here would be a
dependency and a larger attack surface for no gain.

## exchange

both sides announce and each checks the other's pubkey against the one pinned on
its command line. a mismatch is an attacker on the socket, not a disagreement,
so the connection ends.

    alice -> bob   announce  alice pubkey, locktime
    bob   -> alice announce  bob pubkey, locktime

alice then sends payments. each is a complete transaction spending the funding
outpoint, paying `to_bob` to bob and the remainder back to herself, signed by
alice only. bob countersigns, parses what he signed, checks it, and acks.

    alice -> bob   payment   psbt, cumulative total
    bob   -> alice ack       total bob now considers paid

any number of payments, each strictly larger than the last. then either side
stops, or alice closes:

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

there is no error message. a party that does not like what it received closes
the connection and logs why. this is a prototype and a wrong message means
something is broken or hostile, neither of which is worth negotiating over.

## refund

if bob stops responding, alice waits for the locktime and spends the funding
output through the `OP_IF` branch with `nLockTime` set to at least the locktime
and a non final sequence number. neither program does this yet.
