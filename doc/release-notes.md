Release Notes for Nexa 1.0.2
======================================================

Nexa version 1.0.2 is now available from:

  <https://gitlab.com/nexa/nexa/-/releases>

Please report bugs using the issue tracker at github:

  <https://gitlab.com/nexa/nexa/-/issues>

This is minor release of Nexa, for more information about Nexa see:

- https://nexa.org
- https://spec.nexa.org

Upgrading
---------

Main changes in 1.0.2
-----------------------

This is list of the main changes that have been merged in this release:

- improved locking
- add more miner stats to getmininginfo
- fix coins selection in the qt clients
- improve headers processing during IBD

Commit details
--------------

- `65a019517` Bump version to 1.0.2 (Andrea Suisani)
- `80178a8f4` Remove GUARDED_BY(cs_main) for minrelaytxfee global definition (Peter Tschipper)
- `a7138af06` Tidy up the global wallet fee variables  and use the tweaks instead (Peter Tschipper)
- `0fdee74ae` Add a valid NEXA mainnet block to the unit tests and use it (Peter Tschipper)
- `ce1ed2491` add simple tracking of miners asking for candidates and submitting blocks get new address when block is found add miner stat info to getmininginfo (Andrew Stone)
- `4fe09c706` add help text for tx idem in various places (Peter Tschipper)
- `3e5412a1f` electrum: Check if token outputs are in history (Dagur Valberg Johannsson)
- `1669ce139` Add missing help text for rpc getblock and getblockheader (Peter Tschipper)
- `8c6035fcf` Remove GetBlockChainHeight() (ptschip)
- `f30f015e8` Change relayfee to sat/KB rather than NEX in getnetworkinfo rpc (Peter Tschipper)
- `97fc8ac34` The last of the easy to remove cs_main locks (Peter Tschipper)
- `6ca386e7f` add max block size to getmininginfo rpc (Peter Tschipper)
- `4d8870ee8` fix a crash in the qt gui's coin control feature, due to an out of bounds output being selected (Andrew Stone)
- `941407b64` Fix slow processing of new headers during IBD which is caused by CalculateNextMaxBlockSize() (Peter Tschipper)
- `4716cf595` Tidy up GetChainTips() (Peter Tschipper)
- `3f2ebcf18` systemctl startup script and notes (thanks @sickpig) (Andrew Stone)
- `9681d58cc` remove redundant inline declaration (Griffith)
- `d6fdf35a8` Fix compile warning - to many parameters for format (ptschip)
- `f75b97b5e` Remove cs_main in ping and getconnectioncount rpc (ptschip)
- `c1125fd15` Remove cs_main in gettxout rpc (ptschip)
- `0918f5273` Remove cs_main lock on getblockhash rpc call (ptschip)
- `f5bc93aae` Remove cs_main lock in getrawtxpool and getrawtxpoolbyid (ptschip)
- `1bd0f8338` When trimming from the mempool do not remove prioritised transactions (ptschip)
- `0c5a36aca` add txidem to the help text in wallet gettransaction (ptschip)
- `05bd5dc54` remove --with-incompatible-bdb option from ci builds, it does not exist (Griffith)
- `d3721446c` qa: Increase electrum timeouts (Dagur Valberg Johannsson)

Credits
=======

Thanks to everyone who directly contributed to this release:

- Andrea Suisani
- Andrew Stone
- Dagur Valberg Johannsson
- Griffith
- Peter Tschipper
